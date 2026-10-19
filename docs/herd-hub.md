# Herd hub

The hub (#261) is a public repository that lists herd servers. A node fetches the list over HTTPS and uses it as its seed and bootstrap source for [herd](herd.md). The hub never holds measurements. Each entry is signed with one of its own node keys and checked by the node, but the signature only shows the entry was not altered: anyone can sign an entry with a key they made. The hub is therefore trusted to decide which keys become peers of every node and which ASN each claims (see Trust).

## Node side

```yaml
herd:
  hub:
    url: https://hub.example.net/herd.json   # https only
    refresh: 6h                              # 10m to 168h
    max_peers: 16                            # 1 to 64
```

The list is fetched at start and every `refresh`. Redirects to http are not followed, the body is limited to 4 MiB and 4096 entries, and a failed fetch keeps the last list. Before the first successful fetch the node uses the snapshot built into the release (`internal/herd/hub_snapshot.json`, refreshed at release time with `make hub-snapshot HUB_URL=...`); a stale snapshot only loses its expired entries.

Each entry is checked: strict fields, https endpoints with a port (the names `localhost` and `*.localhost`, and loopback, private, link-local, multicast, and unspecified IP literals are refused; other host names are not resolved when the entry is checked), the signature of one of its own node keys, and an expiry in the future and at most 180 days after `issued`. The node then uses at most one entry per ASN (the newest), never its own entry or ASN, each key once, and never a node already in `herd.peers`. When more entries are listed than `max_peers`, which ones are used depends on the node's own key, so members do not all pull from the same few. The peers show in `GET /api/herd` with `source` `hub` or `snapshot`, and a hub peer's status document must report the ASN its entry claims.

Hub peers are pulled from like static peers, and their keys may connect to the pull API under the same limits. The key is checked again on every request, so one that leaves the list loses its open connections. They leave when the entry expires or disappears from the list, and `hub` set with `preview_only` is refused. The hub changes nothing else: herd stays advisory, and it never announces.

## Trust

A node accepts from the hub list only what the signature and the checks above show. That is not an identity check, so a listed entry is trusted for two things:

- Its node keys may connect to this node's pull API and read the records this node shares, as a static peer's key may.
- Its ASN is a claim. An entry with a later `issued` that claims an ASN replaces the genuine entry for that ASN on every node that uses the list, and a hub peer's status document is only compared with its own entry.

So a hub repository that merges entries without checking who submitted them lets a stranger become a pull client of every node. Review entries before merging, and share only what you would give any listed member. What a node accepts from a peer is still decided by the pinned key and the signed responses, as for static peers. This is the gap RPKI validation of the identity statement would close; this build does not do it.

The identity statement and RSC (RFC 9323) an entry may reference are carried, not validated: this build does not check RPKI objects, so a hub peer's ASN is a claim. Do not treat it as verified.

## Joining

1. Enable herd and start the controller once, so the node key exists. `GET /api/herd` shows it.
2. Print your entry. `-url` is where peers reach `herd.listen`; add `-node ed25519:<key>=https://host:port` for each other node of your ASN, and `-statement-url`, `-statement-sha256`, `-rsc-url` together if you publish an identity statement:

   ```
   docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml" -v packeteer-data:/var/lib/packeteer \
     ghcr.io/grandarcher/packeteer:<version> herd entry -url https://203.0.113.10:9444 > 64500.json
   ```

   The entry holds your ASN, node keys and endpoints, retention, data classes, and an expiry (`-valid`, default 90 days, at most 180). Nothing else from the config is in it.
3. Open a pull request that adds the file as `entries/<asn>.json`.
4. Sign a new entry before the old one expires; replace the file by pull request. To leave, delete the file.

## Hub repository

The hub repository holds `entries/<asn>.json`, one file per ASN (so an ASN cannot be listed twice), and publishes the list built from them as `herd.json`. `packeteer herd hub-check DIR` is the check (only regular `*.json` files that do not start with a dot are entries): every entry passes the node's own checks, each file is named for its ASN, no ASN, key, or address is listed twice, and an expired entry fails. `-list FILE` writes the list document, `-prune` deletes expired entries instead of failing on them. It reads no config and starts nothing, so CI runs it from the image:

```yaml
# .github/workflows/check.yml
on: [pull_request, push]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker run --rm -v "$PWD:/hub" ghcr.io/grandarcher/packeteer:<version> herd hub-check -list /hub/herd.json /hub/entries
```

```yaml
# .github/workflows/prune.yml: drops expired entries, so a stale member leaves the list
on:
  schedule: [{cron: "17 3 * * *"}]
permissions: {contents: write, pull-requests: write}
jobs:
  prune:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker run --rm -v "$PWD:/hub" ghcr.io/grandarcher/packeteer:<version> herd hub-check -prune /hub/entries
      - run: |
          git diff --quiet && exit 0
          git checkout -b prune-$(date +%F)
          git -c user.name=hub -c user.email=hub@example.invalid commit -am "Prune expired entries"
          git push origin HEAD
          gh pr create --fill
        env: {GH_TOKEN: "${{ github.token }}"}
```

An entry cannot outlive its signed expiry, so pruning removes exactly the stale ones.
