# IRR whois answers

Port 43 was not reachable from the recording host. The object text follows answers seen on 2026-10-23 over HTTPS (the IRRd 4 whois endpoint of rr.ntt.net and the RIPE database REST API), and the tests add the port 43 framing.

| File | What |
|---|---|
| `irrd-route.txt` | Body of `!r198.51.100.0/24` in the shape `https://rr.ntt.net/v1/whois/?q=!r<prefix>` returned for a RIPE NCC IPv4 prefix (IRRd 4, NTTCOM mirror): a RIPE object with the RIPE "THIS OBJECT IS MODIFIED" remarks and `rpki-ov-state`, a RADB object with a second origin, and the `source: RPKI  # Trust Anchor: ripe` object IRRd builds from a ROA. |
| `irrd-route6.txt` | Body of `!r2001:db8::/32`, shaped like the answer for a RIPE NCC IPv6 prefix. |
| `irrd-as-set.txt` | Body of `!iAS-EXAMPLE,1`: space-separated AS numbers, as for a RIPE NCC as-set. |
| `irrd-aut-num.txt` | Body of `!maut-num,AS64496`, shaped like the answer for the RIPE NCC aut-num. |
| `ripe-route-unfiltered.txt` | `ripe-route.txt` as a `-B` (unfiltered) query returns it: the `notify` attribute kept and no `# Filtered` on `source`. |
| `ripe-*.txt` | Built in the shape of port 43 output from a RIPE database server for `-r -s RIPE -x -T route,route6`, `-T as-set`, and `-T aut-num` queries: the `%` header and footer lines around objects shaped like `https://rest.db.ripe.net/search.txt` answers, `%ERROR:101: no entries found` for nothing found, and `%ERROR:201: access denied` for a refused client. |

Every prefix, AS number, maintainer, and name was replaced with documentation values (RFC 5737, RFC 3849, RFC 5398); the live resources queried are not recorded here. A query that found nothing returned HTTP 204, which is `C` (IRRd `!r`, `!i`) or `D` (key not found) on port 43, and `!sNOPE` returned `One or more selected sources are unavailable.`, which is an `F` line on port 43 ([IRRd whois queries](https://irrd.readthedocs.io/en/stable/users/queries/whois/)).
