#!/bin/sh
# Warning-level lint: a README.md, docs/, or lab/ markdown line longer than 1500 characters is a
# paragraph that should be bullets or short paragraphs. It always exits 0; CI
# shows each hit as a warning annotation. Allowlist, with the reason:
#   - docs/FEATURES.md table rows: one row per capability, status text stays in the row.
#   - CHANGELOG.md is not scanned: check-changelog.sh caps entries at 200
#     characters, and release summaries are prose paragraphs above them.
# Lines of 1,100 to 1,500 characters (the /api/exchanges and potential-peers
# rows, PeeringDB refresh, span/NET_RAW, router-check removal) are under the limit and stay.
limit=1500
git ls-files -z -- README.md 'docs/*.md' 'lab/*.md' |
  xargs -0 awk -v limit="$limit" '
    length($0) > limit && !(FILENAME == "docs/FEATURES.md" && /^\|/) {
      printf "::warning file=%s,line=%d::paragraph is %d characters (limit %d); split it into bullets or short paragraphs\n", FILENAME, FNR, length($0), limit
    }'
exit 0
