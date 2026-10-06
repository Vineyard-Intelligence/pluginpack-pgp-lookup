# PGP Key Lookup

A Vineyard **plugin pack** for PGP/OpenPGP OSINT. Given an **Email Address** node, it looks up
public keys published for that address across public key directories; given a **PGP Key** node, it
looks the key up by its fingerprint. It adds **PGP Key** nodes linked to every address in their
User IDs.

## Sources (v1)

| Directory | Protocol | Verifies addresses |
| --- | --- | --- |
| keys.openpgp.org | VKS `by-email` / `by-fingerprint` | yes |
| keyserver.ubuntu.com | HKP `op=get&search=<email>` / `0x<fingerprint>` | no |
| pgpkeys.eu | HKP `op=get&search=<email>` / `0x<fingerprint>` | no |
| keys.mailvelope.com | HKP `op=get&search=<email>` / `0x<fingerprint>` | yes |

A directory that verifies addresses publishes a User ID only after the address owner confirms it
by email. The others publish whatever is uploaded, so anyone can put a key there that names anyone's
address.

Every request is an **exact by-email or by-fingerprint lookup** — no `op=index` search, no
enumeration, no bulk harvesting. WKD is not supported in v1.

## Desktop only

Three of the four directories send no CORS headers, so the browser cannot read them. In a browser
the plugin tells you to open the project in the desktop app rather than returning a misleading empty
result.

## What gets added to the graph

- One **PGP Key** node (`identity.pgp_key`) per distinct fingerprint, with `fingerprint`,
  `key_id`, `algorithm`, `key_size`, `creation_time`, `expiration_time`, `user_ids`, `revoked`,
  `armored_key` (that certificate alone; left out when every copy is over 192 KB, as keyserver
  copies of widely signed keys are), `sources` (which directories had it), and `user_id_sources` —
  one line per User ID: the directories that served it, and whether one of them verifies addresses.
- An **Email Address** node for every address in the key's User IDs, with a `key bound to` edge
  from the key.
- Keys are deduplicated by fingerprint across all four directories and across all selected nodes.
  `expiration_time` comes from the newest self-signature any directory holds.

Requires the `identity.pgp_key` type (Identity type pack ≥ 1.2.0).

## License

Apache-2.0
