// PGP Key Lookup — desktop-only enrichment for Email Address and PGP Key nodes.
//
// For each selected `identity.email_address` (by address) or `identity.pgp_key` (by fingerprint),
// queries the public key directories for OpenPGP public keys and creates `identity.pgp_key` nodes,
// each linked via `key bound to` to an `identity.email_address` for EVERY address in its User IDs —
// not only the one that was asked about, so a fingerprint leads back to all of its addresses.
//
// PROVENANCE: keys.openpgp.org and keys.mailvelope.com publish a User ID only after mailing its
// address and getting the confirmation back; the HKP keyservers accept any upload, so anyone can
// publish a key naming anyone's address there. Which directories served each User ID is recorded
// in `user_id_sources` (undeclared in the type, so it is data only). Nothing here verifies a
// signature, so "served by a verifying directory" is the most that can be said about a UID.
//
// SOURCES (v1 — no WKD yet):
//   • keys.openpgp.org (VKS by-email / by-fingerprint) — answers with
//     `access-control-allow-origin: *`, so it is reached through `ctx.net.fetch` under the
//     declared `network` allowlist.
//   • keyserver.ubuntu.com / pgpkeys.eu / keys.mailvelope.com (HKP `op=get&search=<email>` or
//     `search=0x<fingerprint>`; without the 0x an HKP server runs a full-text search instead) —
//     none send CORS headers, so they are reached through `ctx.net.probe` (web_probe scope), the
//     desktop-only anonymous main-process channel. The plugin therefore requires the desktop app;
//     in the web build it fails loudly rather than returning a clean miss (same pattern as the
//     WhatsMyName pack).
//   • WKD is deliberately NOT in v1: it serves BINARY certificates (RFC 9580), and the probe
//     channel carries bodies as UTF-8 text, so key material would be corrupted in transit.
//     Adding it needs a binary/base64 option on the probe channel first.
//
// NO ENUMERATION: every request is an exact by-email / by-UID / by-fingerprint lookup. The
// `op=index` search surface of the HKP protocol is never used — it enables bulk harvesting of
// UIDs (emails) and signatures, which is what killed the old SKS pool; see net-allowlist's
// egress notes.
//
// Parsing is a minimal, dependency-free OpenPGP packet reader (v4 + v6 public-key packets):
// fingerprint (v4: SHA-1 over 0x99|2-octet len|body; v6: SHA-256 over 0x9B|4-octet len|body), long key ID,
// algorithm, key size, creation time, expiry (newest v4 self-certification, hashed subpacket 9),
// User IDs, and revocation (v4 signature type 0x20). Everything a pgp_key node's schema declares —
// no third-party certification graph, subkey detail, or key-flag bits (extend here if ever needed).
import { definePlugin } from './sdk';
import type { HostContext, RunResult } from './sdk';

const OPENPGP_ORG_VKS = 'https://keys.openpgp.org/vks/v1/'; // CORS *, via ctx.net.fetch
const HKP_SERVERS = [
    { name: 'keyserver.ubuntu.com', endpoint: 'https://keyserver.ubuntu.com/pks/lookup' },
    { name: 'pgpkeys.eu', endpoint: 'https://pgpkeys.eu/pks/lookup' },
    { name: 'keys.mailvelope.com', endpoint: 'https://keys.mailvelope.com/pks/lookup' },
] as const; // no CORS, via ctx.net.probe
/** Directories that publish a User ID only after confirming its address by mail. */
const VERIFYING = new Set(['keys.openpgp.org', 'keys.mailvelope.com']);
/** Node data is capped at 256 KB (core/serializers.py GRAPH_DATA_MAX_BYTES); leave room for the rest. */
const ARMOR_MAX = 192 * 1024;

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const FPR_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const ARMOR_RE = /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;

const ALGO_NAMES: Record<number, string> = {
    1: 'rsa',
    2: 'rsa',
    3: 'rsa',
    16: 'elgamal',
    17: 'dsa',
    18: 'ecdh',
    19: 'ecdsa',
    22: 'eddsa',
    25: 'x25519',
    26: 'x448',
    27: 'ed25519',
    28: 'ed448',
};

/** Curve OID → [name, bits] for the ECC public-key algorithms (18/19/22). */
const CURVES: Record<string, [string, number]> = {
    '1.2.840.10045.3.1.7': ['nist p256', 256],
    '1.3.132.0.34': ['nist p384', 384],
    '1.3.132.0.35': ['nist p521', 521],
    '1.3.132.0.10': ['secp256k1', 256],
    '1.3.6.1.4.1.11591.15.1': ['ed25519', 256],
    '1.3.6.1.4.1.3029.1.5.1': ['cv25519', 256],
    '1.3.6.1.4.1.11591.15.2': ['ed448', 448],
    '1.3.6.1.4.1.3029.1.5.2': ['cv448', 448],
    '1.3.36.3.3.2.8.1.1.7': ['brainpool p256r1', 256],
    '1.3.36.3.3.2.8.1.1.11': ['brainpool p384r1', 384],
    '1.3.36.3.3.2.8.1.1.13': ['brainpool p512r1', 512],
};

interface ParsedKey {
    fingerprint: string;
    keyId: string;
    algorithm?: string;
    keySize?: number;
    createdAt?: string; // YYYY-MM-DD
    expiresAt?: string; // YYYY-MM-DD
    selfSigAt?: number; // creation time of the self-certification expiresAt was read from
    userIds: string[];
    revoked: boolean;
    armor: string;
}

// ------------------------------------------------------------------ OpenPGP packet reader --

function readU32(b: Uint8Array, off: number): number {
    return (((b[off] ?? 0) << 24) | ((b[off + 1] ?? 0) << 16) | ((b[off + 2] ?? 0) << 8) | (b[off + 3] ?? 0)) >>> 0;
}

/** MPI = 2-byte bit count + ceil(bits/8) bytes. Returns {bits, bytes, nextOffset}. */
function readMpi(b: Uint8Array, off: number): { bits: number; next: number } | null {
    if (off + 2 > b.length) return null;
    const bits = (b[off] << 8) | b[off + 1];
    const nbytes = Math.ceil(bits / 8);
    if (off + 2 + nbytes > b.length) return null;
    return { bits, next: off + 2 + nbytes };
}

/** Parse an ECC OID ("1.3.6.1..."→ dotted decimal) from an OID-length-prefixed body. */
function readOid(b: Uint8Array, off: number): { oid: string; next: number } | null {
    const len = b[off];
    if (off + 1 + len > b.length) return null;
    const parts: number[] = [Math.floor(b[off + 1] / 40), b[off + 1] % 40];
    let acc = 0;
    for (let i = off + 2; i < off + 1 + len; i++) {
        acc = (acc << 7) | (b[i] & 0x7f);
        if (!(b[i] & 0x80)) {
            parts.push(acc);
            acc = 0;
        }
    }
    return { oid: parts.join('.'), next: off + 1 + len };
}

/** Base64 → bytes (ASCII armor bodies only; tolerate CRLF). */
function b64decode(s: string): Uint8Array | null {
    try {
        const bin = atob(s.replace(/\s+/g, ''));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    } catch {
        return null;
    }
}

/**
 * Strip armor framing: skip the BEGIN line and the header block (RFC 4880: headers end at the
 * first blank line), then collect base64 until END. The CRC24 line ("=XXXX", the last line before
 * END) is dropped too — base64 data never starts a line with '=' (padding only ends one), so a
 * leading '=' is unambiguous.
 */
function unarmor(block: string): Uint8Array | null {
    const lines = block.split(/\r?\n/);
    const body: string[] = [];
    let phase: 'begin' | 'header' | 'data' = 'begin';
    for (const line of lines) {
        if (/^-----END PGP/.test(line)) break;
        if (phase === 'begin') {
            if (/^-----BEGIN PGP/.test(line)) phase = 'header';
        } else if (phase === 'header') {
            if (line.trim() === '') phase = 'data';
        } else if (!line.startsWith('=')) {
            body.push(line);
        }
    }
    return b64decode(body.join(''));
}

/** Walk the packet stream. Old-format lengths incl. indeterminate; new-format incl. 5-octet. */
function* packets(data: Uint8Array): Generator<{ tag: number; body: Uint8Array; start: number }> {
    let pos = 0;
    while (pos + 1 <= data.length) {
        const head = data[pos];
        if ((head & 0x80) === 0) break; // not a packet header
        const newFmt = (head & 0x40) !== 0;
        let tag: number;
        let len: number;
        let bodyStart: number;
        if (newFmt) {
            tag = head & 0x3f;
            const l1 = data[pos + 1];
            if (l1 < 192) {
                len = l1;
                bodyStart = pos + 2;
            } else if (l1 < 224) {
                len = ((l1 - 192) << 8) + data[pos + 2] + 192;
                bodyStart = pos + 3;
            } else if (l1 === 255) {
                len = readU32(data, pos + 2);
                bodyStart = pos + 6;
            } else {
                break; // partial body length — not expected in a key from a keyserver
            }
        } else {
            tag = (head >> 2) & 0x0f;
            const lt = head & 0x03;
            if (lt === 0) {
                len = data[pos + 1];
                bodyStart = pos + 2;
            } else if (lt === 1) {
                len = (data[pos + 1] << 8) | data[pos + 2];
                bodyStart = pos + 3;
            } else if (lt === 2) {
                len = readU32(data, pos + 1);
                bodyStart = pos + 5;
            } else {
                len = data.length - (pos + 1);
                bodyStart = pos + 1;
            }
        }
        if (bodyStart + len > data.length) break; // truncated
        yield { tag, body: data.subarray(bodyStart, bodyStart + len), start: pos };
        pos = bodyStart + len;
    }
}

/** Public-key packet (tag 6) → version, creation time, algorithm, key-size hint, curve name. */
function parsePublicKey(body: Uint8Array): {
    version: number;
    created: number;
    algo: number;
    keySize?: number;
    algorithm?: string;
} | null {
    const v = body[0];
    if (v !== 4 && v !== 6) return null; // v2/v3 legacy keys are not handled
    const created = readU32(body, 1);
    const algo = body[5];
    let off = 6;
    let keySize: number | undefined;
    let algorithm: string | undefined = ALGO_NAMES[algo];

    const eccWithOid = algo === 18 || algo === 19 || algo === 22; // ECDH/ECDSA/EdDSA
    const fixedEcc: Record<number, [string, number]> = {
        25: ['x25519', 256],
        26: ['x448', 448],
        27: ['ed25519', 256],
        28: ['ed448', 448],
    };
    if (eccWithOid) {
        const oid = readOid(body, off);
        if (oid) {
            const curve = CURVES[oid.oid];
            if (curve) {
                algorithm = curve[0];
                keySize = curve[1];
            }
            off = oid.next;
        }
    } else if (fixedEcc[algo]) {
        algorithm = fixedEcc[algo][0];
        keySize = fixedEcc[algo][1];
    }
    const mpi = readMpi(body, off);
    if (mpi && keySize === undefined) keySize = mpi.bits; // RSA/DSA/ElGamal: first MPI = modulus
    return { version: v, created, algo, keySize, algorithm };
}

/**
 * Read a v4 signature packet: its type, creation time (subpacket 2) and key expiration (9, seconds
 * from key creation; 0 means none) from the hashed area, and issuer key ID (16) / issuer
 * fingerprint (33) from either area — v4 signers routinely put the issuer in the unhashed one.
 * v6 signatures are skipped (v1 scope).
 */
function readSig(body: Uint8Array): { type: number; created?: number; expiry?: number; issuers: string[] } | undefined {
    if (body[0] !== 4 || body.length < 6) return undefined;
    const sig: { type: number; created?: number; expiry?: number; issuers: string[] } = { type: body[1], issuers: [] };
    let p = 4;
    for (const hashed of [true, false]) {
        if (p + 2 > body.length) break;
        const end = p + 2 + ((body[p] << 8) | body[p + 1]);
        if (end > body.length) break;
        p += 2;
        while (p < end) {
            let len = body[p++];
            if (len === 255) {
                len = readU32(body, p);
                p += 4;
            } else if (len >= 192) {
                len = ((len - 192) << 8) + body[p] + 192;
                p += 1;
            }
            if (len < 1 || p + len > end) break;
            const type = body[p] & 0x7f; // high bit = critical flag
            if (hashed && type === 2 && len >= 5) sig.created = readU32(body, p + 1);
            else if (hashed && type === 9 && len >= 5) sig.expiry = readU32(body, p + 1) || undefined;
            else if (type === 16 && len >= 9) sig.issuers.push(hex(body.subarray(p + 1, p + 9)));
            else if (type === 33 && len >= 2) sig.issuers.push(hex(body.subarray(p + 2, p + len)));
            p += len;
        }
        p = end;
    }
    return sig;
}

/**
 * Parse one ASCII-armored block into the schema's fields, one ParsedKey PER primary public-key
 * packet. HKP `op=get` routinely returns several certificates concatenated in a single armor
 * block (the ftpmaster@ubuntu.com example returns 13), so a tag-6 packet always starts a new key;
 * subsequent UID / signature packets belong to the key they follow. Subkey packets (tag 14) are
 * not parsed — they never carry the block's key boundary — but they end the primary key's part:
 * every signature after one binds or revokes a subkey, and its expiry is the subkey's.
 */
async function parseArmoredKey(armor: string): Promise<ParsedKey[]> {
    const raw = unarmor(armor);
    if (!raw || raw.length < 10) return [];

    interface Acc {
        version: number;
        created: number;
        keySize?: number;
        algorithm?: string;
        fingerprint: string;
        expiresAt?: number;
        selfSigAt?: number;
        inSubkeys?: boolean;
        revoked: boolean;
        userIds: string[];
        start: number; // offset of its public-key packet in `raw`
    }
    const keys: ParsedKey[] = [];
    let cur: Acc | null = null;
    let end = 0; // end of the last packet read

    const finish = (certEnd: number): void => {
        if (!cur?.fingerprint) return;
        keys.push({
            fingerprint: cur.fingerprint,
            // RFC 9580 §5.5.4: a v4 key ID is the LAST 64 bits of the fingerprint, a v6 one the FIRST.
            keyId: cur.version === 6 ? cur.fingerprint.slice(0, 16) : cur.fingerprint.slice(-16),
            algorithm: cur.algorithm,
            keySize: cur.keySize,
            createdAt: isoDate(cur.created),
            expiresAt: cur.expiresAt ? isoDate(cur.expiresAt) : undefined,
            selfSigAt: cur.selfSigAt,
            userIds: cur.userIds,
            revoked: cur.revoked,
            // This certificate's packets alone, not the whole block: an HKP block holds every key
            // the lookup matched, and each node keeps only its own.
            armor: armorOf(raw.subarray(cur.start, certEnd)),
        });
    };

    for (const { tag, body, start } of packets(raw)) {
        end = body.byteOffset - raw.byteOffset + body.length;
        if (tag === 6) {
            finish(start); // a second public-key packet ends the previous certificate
            cur = null; // …even one this reader skips, so its UIDs do not land on the previous key
            const pk = parsePublicKey(body);
            if (!pk) continue;
            const digest =
                pk.version === 6
                    ? await crypto.subtle.digest('SHA-256', prependLen(0x9b, body, 4))
                    : await crypto.subtle.digest('SHA-1', prependLen(0x99, body, 2));
            cur = {
                version: pk.version,
                created: pk.created,
                keySize: pk.keySize,
                algorithm: pk.algorithm,
                fingerprint: hex(new Uint8Array(digest)).toLowerCase(),
                revoked: false,
                userIds: [],
                start,
            };
        } else if (tag === 13 && cur) {
            try {
                cur.userIds.push(new TextDecoder('utf-8', { fatal: false }).decode(body));
            } catch {
                /* skip undecodable UID */
            }
        } else if (tag === 14 && cur) {
            cur.inSubkeys = true;
        } else if (tag === 2 && cur && cur.version === 4 && !cur.inSubkeys) {
            const sig = readSig(body);
            if (!sig) continue;
            if (sig.type === 0x20) cur.revoked = true; // key revocation
            // Expiry is the newest self-certification's (0x10-0x13). Not the last one read:
            // keyservers do not keep a UID's self-signatures in date order. And not a third
            // party's certification, which HKP serves alongside — when it names an issuer, the
            // issuer has to be this key.
            const fp = cur.fingerprint;
            if (
                sig.type >= 0x10 &&
                sig.type <= 0x13 &&
                sig.issuers.every((i) => fp.endsWith(i)) &&
                (sig.created ?? 0) >= (cur.selfSigAt ?? 0)
            ) {
                cur.selfSigAt = sig.created ?? 0;
                cur.expiresAt = sig.expiry ? cur.created + sig.expiry : undefined;
            }
        }
    }
    finish(end);
    return keys;
}

/** [prefix, big-endian length, …body] — the fingerprint pre-image. The length is 2 octets for v4
 *  and 4 for v6 (RFC 9580 §5.5.4). */
function prependLen(prefix: number, body: Uint8Array, lenOctets: 2 | 4): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(1 + lenOctets + body.length) as Uint8Array<ArrayBuffer>;
    out[0] = prefix;
    for (let i = 0; i < lenOctets; i++) out[lenOctets - i] = (body.length >>> (8 * i)) & 0xff;
    out.set(body, 1 + lenOctets);
    return out;
}

function hex(b: Uint8Array): string {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
}

/** Bytes → an armor block. No CRC-24 line: it is optional (RFC 4880 §6.2, RFC 9580 §6.1). */
function armorOf(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const lines = btoa(bin).replace(/.{64}/g, '$&\n').trimEnd();
    return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${lines}\n-----END PGP PUBLIC KEY BLOCK-----`;
}

function isoDate(unixSec: number): string {
    if (!unixSec) return '';
    return new Date(unixSec * 1000).toISOString().slice(0, 10);
}

// ------------------------------------------------------------------------------ the plugin --

export const pgpLookup = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.pgp_lookup',
        content_type: 'vineyard:plugin',
        name: 'PGP Key Lookup',
        version: '1.1.0',
        description:
            'Looks up OpenPGP public keys on keys.openpgp.org, keyserver.ubuntu.com, pgpkeys.eu and keys.mailvelope.com: by address for each selected Email Address, by fingerprint for each selected PGP Key. Creates one PGP Key node per distinct fingerprint (key ID, algorithm, key size, creation/expiration, User IDs, revocation, armored key, sources, and user_id_sources: per User ID, the directories that served it and whether one of them verifies addresses), and an Email Address node for every address in its User IDs, linked "key bound to". Desktop only.',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        icon: 'key',
        platforms: {
            primary: 'desktop', // HKP servers answer no CORS → needs the desktop probe channel
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'pgp_key' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'pgp_key' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'edge:create'],
            network: [
                {
                    endpoint: OPENPGP_ORG_VKS,
                    methods: ['GET'],
                    purpose: 'Look up keys by each selected email address or key fingerprint on keys.openpgp.org.',
                },
            ],
            web_probe: {
                purpose:
                    'Look up keys by each selected email address or key fingerprint on keyserver.ubuntu.com, pgpkeys.eu and keys.mailvelope.com.',
            },
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx: HostContext): Promise<RunResult> {
        const ids = ctx.input.selection;
        if (!ids.length)
            return {
                summary: 'Select one or more Email Address or PGP Key nodes first',
                counts: { checked: 0, keys: 0 },
            };
        if (!ctx.net?.probe) {
            // Three of the four directories answer no CORS and are reachable only through the
            // desktop main-process probe. Fail loudly instead of returning a clean miss.
            return {
                summary:
                    'PGP Key Lookup queries keyservers that answer no cross-origin requests and needs the Vineyard desktop app. Open this project in the desktop app and run it again.',
                counts: { checked: 0, keys: 0 },
            };
        }
        if (!ctx.net?.fetch)
            return { summary: 'Network capability not granted to this plugin', counts: { checked: 0, keys: 0 } };

        const found: Found = new Map();
        // address → Email Address node id, seeded with the selection so its edges land on those nodes
        const addressNode = new Map<string, string>();
        const stats = { answered: 0, error: '' };

        let emails = 0;
        let fingerprints = 0;
        for (let i = 0; i < ids.length; i++) {
            if (ctx.signal?.aborted) break;
            const node = await ctx.graph!.get!(ids[i]);
            if (!node) continue;
            const data = node.data as any;
            let query: string;
            if (node.type === 'identity.email_address') {
                const email = String(data.email ?? '')
                    .trim()
                    .toLowerCase();
                if (!EMAIL_RE.test(email)) continue;
                emails++;
                addressNode.set(email, ids[i]);
                query = email;
            } else if (node.type === 'identity.pgp_key') {
                const fp = String(data.fingerprint ?? '')
                    .trim()
                    .toLowerCase();
                if (!FPR_RE.test(fp)) continue;
                fingerprints++;
                query = fp;
            } else continue;
            ctx.progress?.set?.({
                percent: Math.round(((emails + fingerprints) / ids.length) * 100),
                message: `PGP lookup ${query}`,
            });
            await lookup(ctx, query, found, stats);
        }

        let created = 0;
        let linked = 0;
        for (const [fp, hit] of found) {
            if (ctx.signal?.aborted) break;
            const uids = [...hit.uids];
            const data: Record<string, unknown> = {
                fingerprint: fp,
                key_id: hit.key.keyId,
                user_ids: uids.map(([uid]) => uid).join('\n'),
                user_id_sources: uids
                    .map(
                        ([uid, from]) =>
                            `${uid} | ${[...from].join(', ')} | address verified by directory: ${
                                [...from].some((s) => VERIFYING.has(s)) ? 'yes' : 'no'
                            }`,
                    )
                    .join('\n'),
                revoked: hit.key.revoked,
                sources: [...hit.sources].join('\n'),
            };
            if (hit.key.algorithm) data.algorithm = hit.key.algorithm;
            if (hit.key.keySize !== undefined) data.key_size = hit.key.keySize;
            if (hit.key.createdAt) data.creation_time = hit.key.createdAt;
            if (hit.key.expiresAt) data.expiration_time = hit.key.expiresAt;
            if (hit.key.armor.length <= ARMOR_MAX) data.armored_key = hit.key.armor;
            else ctx.progress?.log?.(`${fp.slice(0, 16)}…: armored key over ${ARMOR_MAX / 1024} KB, not stored`);

            const keyNode = await ctx.graph!.createNode!({ type: 'identity.pgp_key', data });
            created++;
            const addresses = new Set(uids.map(([uid]) => uidAddress(uid)).filter((a): a is string => !!a));
            for (const address of addresses) {
                let to = addressNode.get(address);
                if (!to) {
                    const n = await ctx.graph!.createNode!({
                        type: 'identity.email_address',
                        data: { email: address },
                    });
                    addressNode.set(address, (to = String(n.id)));
                }
                await ctx.graph!.createEdge!({ from: String(keyNode.id), to, label: 'key bound to' });
                linked++;
            }
        }

        const checked = emails + fingerprints;
        // Every directory down for every lookup is a failure, not "no keys" — a run only fails by throwing.
        if (!created && checked && !stats.answered && !ctx.signal?.aborted)
            throw new Error(`No key directory answered (${stats.error})`);
        const what =
            [emails ? `${emails} email address(es)` : '', fingerprints ? `${fingerprints} key fingerprint(s)` : '']
                .filter(Boolean)
                .join(' and ') || '0 email address(es)';
        const summary =
            created === 0
                ? `No PGP keys found for ${what} across 4 directories`
                : `${created} PGP key(s) found for ${what}`;
        ctx.progress?.set?.({ percent: 100, message: summary });
        return { summary, counts: { checked, keys: created, links: linked } };
    },
});

// ------------------------------------------------------------------------------ lookups ----

/** fingerprint (lowercase hex) → merged key, the directories that served it, and per User ID the
 *  directories that served THAT User ID (keys.openpgp.org drops unverified ones, HKP keeps all). */
type Found = Map<string, { key: ParsedKey; sources: Set<string>; uids: Map<string, Set<string>> }>;

/** The address in a User ID: the `<…>` of "Name (comment) <addr>", or the whole UID if bare. */
function uidAddress(uid: string): string | undefined {
    const address = (uid.match(/<([^<>]*)>\s*$/)?.[1] ?? uid).trim().toLowerCase();
    return EMAIL_RE.test(address) ? address : undefined;
}

/** Keys or a clean miss (404, or 400 for a v6 fingerprint): the directory answered. A redirect,
 *  429 or 5xx is a failure, which must not read as "no keys". */
const settled = (status: number) =>
    (status >= 200 && status < 300) || (status >= 400 && status < 500 && status !== 429);

/** `query` is an email address or a lowercase fingerprint (FPR_RE). */
async function lookup(ctx: HostContext, query: string, found: Found, stats: { answered: number; error: string }) {
    const fp = FPR_RE.test(query) ? query : undefined;

    // 1) keys.openpgp.org — CORS-enabled, via the network allowlist.
    try {
        const path = fp ? `by-fingerprint/${fp.toUpperCase()}` : `by-email/${encodeURIComponent(query)}`;
        const res = await ctx.net!.fetch!(`${OPENPGP_ORG_VKS}${path}`, { method: 'GET' });
        if (settled(res.status)) stats.answered++;
        else stats.error ||= `keys.openpgp.org: HTTP ${res.status}`;
        if (res.ok) await ingestArmor(ctx, await res.text(), 'keys.openpgp.org', query, found);
    } catch (e) {
        stats.error ||= `keys.openpgp.org: ${(e as Error)?.message ?? e}`; // unreachable — not fatal alone
    }

    // 2) HKP servers — no CORS, via the desktop probe. A fingerprint needs the 0x prefix: without it
    // HKP runs a full-text search, which answers with any key whose User ID merely mentions it.
    for (const s of HKP_SERVERS) {
        if (ctx.signal?.aborted) break;
        try {
            const res = await ctx.net!.probe!(
                `${s.endpoint}?op=get&search=${encodeURIComponent(fp ? `0x${fp}` : query)}`,
                {
                    method: 'GET',
                    maxBytes: 2 * 1024 * 1024, // the shell's ceiling; well-used keys carry MBs of signatures
                    timeoutMs: 15_000,
                },
            );
            if (!settled(res.status) || res.truncated) {
                const why = res.truncated ? 'answer over 2 MiB, not read' : res.error ?? `HTTP ${res.status}`;
                stats.error ||= `${s.name}: ${why}`;
                ctx.progress?.log?.(`${s.name}: ${why}`);
                continue;
            }
            stats.answered++;
            if (res.status === 200 && res.body) await ingestArmor(ctx, res.body, s.name, query, found);
        } catch (e) {
            stats.error ||= `${s.name}: ${(e as Error)?.message ?? e}`; // unreachable — not fatal alone
        }
    }
}

/** Split an armor body into blocks (HKP may return several) and merge each parsed key that is the
 *  one asked for: the fingerprint's certificate, or a key with the address in a User ID. HKP's
 *  answer also carries any key whose User ID merely mentions the fingerprint or address. */
async function ingestArmor(ctx: HostContext, body: string, source: string, query: string, found: Found): Promise<void> {
    if (!body.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) return;
    const blocks = body.match(ARMOR_RE) ?? [];
    for (const block of blocks) {
        if (ctx.signal?.aborted) return;
        const keys = await parseArmoredKey(block);
        for (const key of keys) {
            if (FPR_RE.test(query) ? key.fingerprint !== query : !key.userIds.some((u) => uidAddress(u) === query))
                continue;
            // Merging is idempotent (Sets), so a key seen from several sources or for several
            // selected nodes lands once in `found` with every source attached.
            let hit = found.get(key.fingerprint);
            if (!hit) found.set(key.fingerprint, (hit = { key, sources: new Set(), uids: new Map() }));
            else {
                // Directories hold different vintages of a certificate: the newest self-certification wins.
                const newer = (key.selfSigAt ?? -1) > (hit.key.selfSigAt ?? -1);
                if (newer) {
                    hit.key.expiresAt = key.expiresAt;
                    hit.key.selfSigAt = key.selfSigAt;
                }
                // The armor too, if it fits a node; else any copy that does (keyservers keep every
                // third-party signature, keys.openpgp.org strips them — megabytes against kilobytes).
                if (key.armor.length <= ARMOR_MAX && (newer || hit.key.armor.length > ARMOR_MAX))
                    hit.key.armor = key.armor;
                if (key.revoked) hit.key.revoked = true;
            }
            hit.sources.add(source);
            for (const uid of key.userIds) {
                const from = hit.uids.get(uid) ?? new Set<string>();
                hit.uids.set(uid, from.add(source));
            }
            ctx.progress?.log?.(`${source}: ${key.fingerprint.slice(0, 16)}… ${key.userIds[0] ?? ''}`.trim());
        }
    }
}

// The loader reads `mod.default ?? mod.plugin` and nothing else (plugin-worker.ts, `load`), so a
// bundle that exports only a named binding resolves to null and fails with "plugin not loadable" —
// which is what the published pack did, from its first release, on every run. Every other pack
// happens to end in `export default definePluginPack(...)` and so never met this. A lone
// plugin is a legal default export (see PluginEntry in sdk.ts); the named export is kept alongside it.
export default pgpLookup;
