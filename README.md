# PGP Key Lookup

A Vineyard **plugin pack** for PGP/OpenPGP OSINT. Given an **Email Address** node, it looks up
public keys published for that address across public key directories and adds **PGP Key** nodes
linked back to the email.

## Sources (v1)

| Directory | Protocol | Channel |
| --- | --- | --- |
| keys.openpgp.org | VKS `by-email` | `ctx.net.fetch` (CORS-enabled, network allowlist) |
| keyserver.ubuntu.com | HKP `op=get&search=<email>` | `ctx.net.probe` (desktop) |
| pgpkeys.eu | HKP `op=get&search=<email>` | `ctx.net.probe` (desktop) |
| keys.mailvelope.com | HKP `op=get&search=<email>` | `ctx.net.probe` (desktop) |

Every request is an **exact by-email lookup** — no `op=index` search, no enumeration, no bulk
harvesting. WKD is not in v1: it serves binary certificates, and the desktop probe channel carries
bodies as UTF-8 text (adding WKD needs a binary/base64 option on that channel first).

## Desktop only

Three of the four directories answer no CORS headers, so those requests go through the desktop
shell's `web_probe` capability — the same anonymous, SSRF-guarded, main-process channel the
WhatsMyName pack uses. In a browser the plugin is present but inert: it detects the missing
capability and tells you to open the project in the desktop app rather than returning a misleading
empty result.

## What gets added to the graph

- One **PGP Key** node (`identity.pgp_key`) per distinct fingerprint, with `fingerprint`,
  `key_id`, `algorithm`, `key_size`, `creation_time`, `expiration_time`, `user_ids`, `revoked`,
  `armored_key`, and `sources` (which directories had it).
- A `key bound to` edge from each key to every selected email it was found for.
- Keys are deduplicated by fingerprint across all four directories and across all selected emails.

Requires the `identity.pgp_key` type (Identity type pack ≥ 1.2.0).

## License

Apache-2.0
