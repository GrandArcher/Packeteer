#!/usr/bin/env bash
# SNMP agent, traps, informs, and syslog lab check (#212). Runs the real
# controller in observe mode against net-snmp: snmpwalk/snmpget/snmpset read
# the snmpagent exporter (v2c and v3 authPriv) with deploy/mib/PACKETEER-MIB.txt
# loaded, and snmptrapd receives the snmptrap notifier's v2c trap, v2c inform,
# v3 trap, and v3 inform. Two netcat listeners take the syslog notifier over
# UDP and TCP. Needs the net-snmp tools and IETF MIBs (apt: snmp snmptrapd
# snmp-mibs-downloader) and nc.
# Nothing here announces; there is no BGP session.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "e2e-snmp: FAIL: $*" >&2; for f in pk.log trap-v2c.log inform-v2c.log trap-v3.log inform-v3.log syslog-tcp.log syslog-udp.log; do echo "== $f" >&2; tail -30 "$work/$f" >&2 2>/dev/null || true; done; exit 1; }

AGENT=127.0.0.1:11161
BASE=.1.3.6.1.4.1.8072.9999.9999.7717
# Lab-only values.
export SNMP_COMMUNITY=lab-only-community SNMP_USER=nms SNMP_AUTH=lab-only-auth-pass SNMP_PRIV=lab-only-priv-pass
export TRAP_COMMUNITY=lab-only-trap-community TRAP_AUTH=lab-only-trap-auth TRAP_PRIV=lab-only-trap-priv
mib=(-M "+$PWD/deploy/mib" -m +PACKETEER-MIB)

# The MIB compiles and puts the names where the agent and the trap code put them.
[ "$(snmptranslate "${mib[@]}" -On PACKETEER-MIB::pktrProviderDown)" = "$BASE.0.6" ] || fail "pktrProviderDown is not $BASE.0.6"
[ "$(snmptranslate "${mib[@]}" -On PACKETEER-MIB::pktrMode.0)" = "$BASE.2.2.0" ] || fail "pktrMode.0 is not $BASE.2.2.0"
[ "$(snmptranslate "${mib[@]}" -On PACKETEER-MIB::pktrEventDedupKey.0)" = "$BASE.1.6.0" ] || fail "pktrEventDedupKey.0 is not $BASE.1.6.0"

# Receivers.
conf="$work/snmptrapd.conf"
sed -e "s/CHANGE-ME-community/$TRAP_COMMUNITY/" -e "s/CHANGE-ME-auth/$TRAP_AUTH/g" -e "s/CHANGE-ME-priv/$TRAP_PRIV/g" \
  examples/monitoring/snmptrapd.conf >"$conf"
# One snmptrapd per notifier, so each one's delivery is checked on its own.
ports=(11162 11163 11164 11165)
names=(trap-v2c inform-v2c trap-v3 inform-v3)
for i in 0 1 2 3; do
  snmptrapd -f -C -c "$conf" -On -Lf "$work/${names[$i]}.log" "udp:127.0.0.1:${ports[$i]}" >"$work/snmptrapd-${names[$i]}.out" 2>&1 &
  pids+=($!)
done
nc -l 127.0.0.1 15514 >"$work/syslog-tcp.log" &
pids+=($!)
# netcat locks onto the first sender, which is enough: controller.started is the first event.
nc -u -l 127.0.0.1 15515 >"$work/syslog-udp.log" &
pids+=($!)
sleep 1

cat >"$work/config.yaml" <<YAML
mode: observe
asn: 64512
router_id: 192.0.2.10
auth: {enabled: false}
http:
  listen: "127.0.0.1:18212"
providers:
  - name: lab-a
    source_ip: 127.0.0.1
    next_hop: 192.0.2.1
  - name: lab-b
    source_ip: 127.0.0.2
    next_hop: 192.0.2.2
probe: {interval: 2s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config:
      targets: [{prefix: 198.51.100.0/24, host: 198.51.100.1}]
probers:
  - type: fixed
    config:
      paths:
        - {provider: lab-a, sent: 100, loss_pct: 4, rtt_ms: 20}
        - {provider: lab-b, sent: 100, loss_pct: 0, rtt_ms: 12}
exporters:
  - type: snmpagent
    config:
      listen: $AGENT
      community_env: SNMP_COMMUNITY
      username_env: SNMP_USER
      auth_env: SNMP_AUTH
      priv_env: SNMP_PRIV
      allow_from: [127.0.0.1]
notifiers:
  - type: snmptrap
    name: trap-v2c
    config: {address: 127.0.0.1, port: 11162, community_env: TRAP_COMMUNITY}
  - type: snmptrap
    name: inform-v2c
    config: {address: 127.0.0.1, port: 11163, community_env: TRAP_COMMUNITY, inform: true}
  - type: snmptrap
    name: trap-v3
    config: {address: 127.0.0.1, port: 11164, version: 3, username_env: TRAP_USER_TRAP, auth_env: TRAP_AUTH, priv_env: TRAP_PRIV, engine_id: "0x8000000001020304"}
  - type: snmptrap
    name: inform-v3
    config: {address: 127.0.0.1, port: 11165, version: 3, username_env: TRAP_USER_INFORM, auth_env: TRAP_AUTH, priv_env: TRAP_PRIV, inform: true}
  - type: syslog
    name: syslog-tcp
    config: {address: 127.0.0.1, port: 15514, transport: tcp}
  - type: syslog
    name: syslog-udp
    config: {address: 127.0.0.1, port: 15515}
YAML

export TRAP_USER_TRAP=trapuser TRAP_USER_INFORM=informuser
CGO_ENABLED=0 go build -o "$work/packeteer" ./cmd/controller
"$work/packeteer" -config "$work/config.yaml" >"$work/pk.log" 2>&1 &
pk=$!
pids+=($pk)

# The start event reaches every receiver. controller.started is trap 1.
for name in "${names[@]}"; do
  for _ in $(seq 1 30); do
    grep -Eq "7717\.0\.1([^0-9]|$)" "$work/$name.log" 2>/dev/null && break
    sleep 1
  done
  grep -Eq "7717\.0\.1([^0-9]|$)" "$work/$name.log" || fail "$name: controller.started never reached snmptrapd"
  grep -q "$BASE.1.1.0.*controller.started" "$work/$name.log" || fail "$name: the notification carries no event kind varbind"
done
for _ in $(seq 1 10); do grep -q 'kind="controller.started"' "$work/syslog-tcp.log" && break; sleep 1; done
grep -q 'kind="controller.started"' "$work/syslog-tcp.log" || fail "no RFC 5424 message over tcp"
grep -Eq '^[0-9]+ <134>1 [0-9T:.-]+Z [^ ]+ packeteer - controller.started \[packeteer@32473 kind="controller.started" severity="info"' "$work/syslog-tcp.log" || fail "the tcp message is not octet-counted RFC 5424"
for _ in $(seq 1 10); do grep -q 'kind="controller.started"' "$work/syslog-udp.log" && break; sleep 1; done
grep -Eq '^<134>1 .* packeteer - controller.started \[packeteer@32473' "$work/syslog-udp.log" || fail "no RFC 5424 message over udp"

# The first metrics snapshot comes after 30 s.
v2=(snmpget -v2c -c "$SNMP_COMMUNITY" -t 2 -r 0 "${mib[@]}" "$AGENT")
for _ in $(seq 1 60); do
  "${v2[@]}" PACKETEER-MIB::pktrMode.0 2>&1 | grep -q 'STRING: "\?observe' && break
  sleep 2
done
out="$("${v2[@]}" PACKETEER-MIB::pktrMode.0)" || fail "the agent never answered"
echo "$out" | grep -q 'STRING: "\?observe' || fail "pktrMode: $out"

walk="$(snmpwalk -v2c -c "$SNMP_COMMUNITY" "${mib[@]}" "$AGENT" PACKETEER-MIB::pktrStatus)"
echo "$walk"
for want in 'pktrMode.0 = STRING: "\?observe' 'pktrHaRole.0 = INTEGER: standalone' 'pktrImprovementsActive.0 = Gauge32:' 'pktrDataAge.0 = Gauge32:'; do
  echo "$walk" | grep -q "$want" || fail "status walk lacks: $want"
done
tbl="$(snmpwalk -v2c -c "$SNMP_COMMUNITY" "${mib[@]}" "$AGENT" PACKETEER-MIB::pktrProviderTable)"
echo "$tbl"
for want in 'pktrProviderName.1 = STRING: "\?lab-a' 'pktrProviderName.2 = STRING: "\?lab-b' 'pktrProviderLossPermille.1 = Gauge32: 40' 'pktrProviderRttMicros.2 = Gauge32: 12000'; do
  echo "$tbl" | grep -q "$want" || fail "provider table lacks: $want"
done

# v3 authPriv reads the same.
v3=(snmpget -v3 -u "$SNMP_USER" -l authPriv -a SHA -A "$SNMP_AUTH" -x AES -X "$SNMP_PRIV" -t 3 -r 0 "${mib[@]}" "$AGENT")
"${v3[@]}" PACKETEER-MIB::pktrMode.0 | grep -q 'observe' || fail "v3 authPriv get failed"
# A client that asks for less than authPriv, or has the wrong key, gets nothing.
snmpget -v3 -u "$SNMP_USER" -l authNoPriv -a SHA -A "$SNMP_AUTH" -t 2 -r 0 "$AGENT" "$BASE.2.2.0" >/dev/null 2>&1 && fail "v3 authNoPriv was answered"
snmpget -v3 -u "$SNMP_USER" -l authPriv -a SHA -A wrong-pass-123 -x AES -X "$SNMP_PRIV" -t 2 -r 0 "$AGENT" "$BASE.2.2.0" >/dev/null 2>&1 && fail "v3 with a wrong key was answered"
snmpget -v2c -c public -t 2 -r 0 "$AGENT" "$BASE.2.2.0" >/dev/null 2>&1 && fail "a wrong community was answered"
# Nothing is writable.
set +e
sets="$(snmpset -v2c -c "$SNMP_COMMUNITY" -t 2 -r 0 "${mib[@]}" "$AGENT" PACKETEER-MIB::pktrMode.0 s inject 2>&1)"
set -e
echo "$sets" | grep -qi 'notWritable' || fail "snmpset: $sets"
"${v2[@]}" PACKETEER-MIB::pktrMode.0 | grep -q 'observe' || fail "the mode changed after a SET"

# SIGTERM: exit 0, and controller.stopping (trap 2) is sent.
kill -TERM "$pk"
wait "$pk" || fail "the controller exited non-zero on SIGTERM"
pids=("${pids[@]/$pk}")
for name in "${names[@]}"; do
  grep -Eq "7717\.0\.2([^0-9]|$)" "$work/$name.log" || fail "$name: no controller.stopping notification"
done
echo "e2e-snmp: ok"
