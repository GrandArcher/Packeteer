#!/usr/bin/env bash
# NetBox inventory lab (#208). Starts a NetBox container, seeds tagged
# providers through its REST API, then runs the real `packeteer config plan`,
# `diff`, and `apply -git` against it. Checks that the plan names the
# providers, the applied git commit holds exactly the lines `diff` showed,
# the written file passes `packeteer -check`, and a second plan has nothing
# left to do. Observe mode; nothing announces. Needs docker, curl, jq, git.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
compose=(docker compose -f lab/docker-compose-netbox.yml)
cleanup() {
  "${compose[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "e2e-netbox: FAIL: $*" >&2; "${compose[@]}" logs --tail 40 netbox >&2 || true; exit 1; }

base=http://127.0.0.1:18208
token=labonlynetboxtoken0000000000000000000000
api() { # method path [json]
  curl -fsS -X "$1" -H "Authorization: Token $token" -H 'Content-Type: application/json' -H 'Accept: application/json' \
    ${3:+-d "$3"} "$base$2"
}

go build -o "$work/pk" ./cmd/controller
"${compose[@]}" up -d

ready=0
for _ in $(seq 1 120); do
  if curl -fsS -H "Authorization: Token $token" "$base/api/circuits/providers/?limit=1" >/dev/null 2>&1; then ready=1; break; fi
  sleep 5
done
[ "$ready" = 1 ] || fail "NetBox did not answer within 10 minutes"

# Seed: one tag, the four custom fields, a registry for the ASNs, and three
# providers. Only two carry the tag, so the third proves the tag filter.
tag=$(api POST /api/extras/tags/ '{"name":"packeteer","slug":"packeteer"}' | jq -r .id)
for f in type source_ip next_hop communities; do
  api POST /api/extras/custom-fields/ "{\"object_types\":[\"circuits.provider\"],\"type\":\"text\",\"name\":\"packeteer_$f\",\"label\":\"Packeteer $f\"}" >/dev/null
done
rir=$(api POST /api/ipam/rirs/ '{"name":"Lab registry","slug":"lab-registry"}' | jq -r .id)
asn() { api POST /api/ipam/asns/ "{\"asn\":$1,\"rir\":$rir}" | jq -r .id; }
provider() { # name slug asn tagged fields-json
  local body
  body=$(jq -n --arg n "$1" --arg s "$2" --argjson a "$(asn "$3")" --argjson t "$4" --argjson tag "$tag" --argjson cf "$5" \
    '{name:$n, slug:$s, asns:[$a], custom_fields:$cf} + (if $t then {tags:[$tag]} else {} end)')
  api POST /api/circuits/providers/ "$body" >/dev/null
}
provider 'Transit A' transit-a 64496 true '{"packeteer_type":"transit","packeteer_next_hop":"192.0.2.9","packeteer_communities":"64496:100,64496:200"}'
provider 'Peer B' peer-b 64497 true '{"packeteer_type":"peer","packeteer_source_ip":"192.0.2.13","packeteer_next_hop":"192.0.2.3"}'
provider 'Other C' other-c 64498 false '{"packeteer_next_hop":"192.0.2.77","packeteer_source_ip":"192.0.2.78"}'

cfg="$work/repo/config.yaml"
mkdir -p "$work/repo"
cat >"$cfg" <<YAML
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    communities: ["64496:100"]
  - name: legacy
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
inventory:
  type: netbox
  config:
    base_url: $base
    tag: packeteer
YAML
git -C "$work/repo" init -q
git -C "$work/repo" add config.yaml
git -C "$work/repo" -c user.name=lab -c user.email=lab@example.invalid commit -q -m base
export PACKETEER_NETBOX_TOKEN=$token

plan=$("$work/pk" config plan -config "$cfg")
echo "$plan"
for want in '~ transit-a' 'next_hop: 192.0.2.1 -> 192.0.2.9' 'communities: 64496:100 -> 64496:100,64496:200' '+ peer-b' '. not in the inventory, left as they are: legacy'; do
  grep -qF -- "$want" <<<"$plan" || fail "plan lacks: $want"
done
if grep -q other-c <<<"$plan"; then fail "an untagged provider was read"; fi
id=$(sed -n 's/^plan id: //p' <<<"$plan")
[ -n "$id" ] || fail "no plan id"
"$work/pk" config diff -config "$cfg" | grep -E '^[-+]' | sed 's/^\([-+]\) /\1/' | sort >"$work/diff.txt"
[ -s "$work/diff.txt" ] || fail "empty diff"

"$work/pk" config apply -config "$cfg" -plan "$id" -git
[ "$(git -C "$work/repo" rev-list --count HEAD)" = 2 ] || fail "no commit for the apply"
git -C "$work/repo" log -1 --format=%s | grep -q "^Apply inventory plan $id\$" || fail "commit subject"
git -C "$work/repo" show HEAD --format= -- config.yaml | grep -E '^[-+][^-+]' | sort >"$work/commit.txt"
grep -E '^[-+][^-+]' "$work/diff.txt" | diff - "$work/commit.txt" || fail "the commit differs from the diff the plan showed"
[ -z "$(git -C "$work/repo" status --porcelain)" ] || fail "tree not clean after apply"

"$work/pk" -check -config "$cfg" | tee "$work/check.txt"
grep -q 'mode: observe' "$work/check.txt" || fail "applied config is not observe"
grep -q 'peer-b source_ip=192.0.2.13 next_hop=192.0.2.3' "$work/check.txt" || fail "peer-b missing from the checked config"
grep -q 'transit-a source_ip=192.0.2.11 next_hop=192.0.2.9' "$work/check.txt" || fail "transit-a next hop not updated"
"$work/pk" config plan -config "$cfg" | grep -q 'the config already matches the inventory' || fail "second plan is not empty"
echo "e2e-netbox: ok"
