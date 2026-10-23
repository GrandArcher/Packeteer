# RIPEstat rpki-validation answers

`unknown.json` is the answer of `GET https://stat.ripe.net/data/rpki-validation/data.json?resource=AS64496&prefix=192.0.2.0/24&sourceapp=packeteer`, recorded on 2026-10-22: no ROA covers the documentation prefix.

`valid.json`, `invalid_asn.json`, and `invalid_length.json` are that answer with `data.resource`, `data.prefix`, `data.status`, and `data.validating_roas` set to documentation values in the shape RIPEstat returns for those states (seen on 2026-10-22 for public prefixes, which are not committed).
