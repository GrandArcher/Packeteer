# IRR file fixtures

`irr.db` is RPSL in the layout of an IRR database dump (RADB-style `changed:` lines, `+` and comment continuation lines, the `source: RPKI` object IRRd builds from a ROA), with documentation prefixes and AS numbers.

`bgpq4.json` is two concatenated `bgpq4 -j -l AS<n> AS<n>` documents. The entry layouts (`exact: true`; `exact: false` with `greater-equal` and `less-equal`; `exact: false` with `less-equal` only) and the escaped `\/` are the ones bgpq4 writes (`printer.c`, `bgpq4_print_json_prefix`; `tests/reference/json--4.txt` in the bgpq4 repository).
