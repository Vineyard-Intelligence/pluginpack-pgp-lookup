# PGP Key Lookup

A Vineyard **plugin pack** for PGP/OpenPGP OSINT. Given an **Email Address** node, it looks up
public keys published for that address across public key directories and adds **PGP Key** nodes
linked back to the email.

## Sources (v1)

| Directory | Protocol |
| --- | --- |
| keys.openpgp.org | VKS `by-email` |
| keyserver.ubuntu.com | HKP `op=get&search=<email>` |
| pgpkeys.eu | HKP `op=get&search=<email>` |
| keys.mailvelope.com | HKP `op=get&search=<email>` |

Every request is an **exact by-email lookup** — no `op=index` search, no enumeration, no bulk
harvesting. WKD is not supported in v1.

## Desktop only

Three of the four directories send no CORS headers, so the browser cannot read them. In a browser
the plugin tells you to open the project in the desktop app rather than returning a misleading empty
result.

## What gets added to the graph

- One **PGP Key** node (`identity.pgp_key`) per distinct fingerprint, with `fingerprint`,
  `key_id`, `algorithm`, `key_size`, `creation_time`, `expiration_time`, `user_ids`, `revoked`,
  `armored_key`, and `sources` (which directories had it).
- A `key bound to` edge from each key to every selected email it was found for.
- Keys are deduplicated by fingerprint across all four directories and across all selected emails.

Requires the `identity.pgp_key` type (Identity type pack ≥ 1.2.0).

## License

Apache-2.0
