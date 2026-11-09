#!/bin/sh
# Minimal Packeteer exec plugin (prober), protocol packeteer-exec/v1.
# See static-targets.sh for the request and response framing.
#
#   probers:
#     - type: exec
#       name: example
#       config:
#         command: exec-prober.sh
#
# It sends nothing and reports a 10 ms reply for every packet. A real prober
# measures the path from params.source and must tag its packets when params
# carries "mark" or "dscp"; one that cannot must return an error, never a
# 100% loss result.
req=$(cat)
case "$req" in
  *'"method":"init"'*)
    echo '{"result":{}}'
    ;;
  *'"method":"probe"'*)
    case "$req" in
      *'"mark"'*|*'"dscp"'*)
        echo '{"error":"cannot tag packets"}'
        exit 0
        ;;
    esac
    count=$(printf '%s' "$req" | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p')
    rtts=""
    i=0
    while [ "$i" -lt "${count:-0}" ]; do
      rtts="${rtts:+$rtts,}10"
      i=$((i + 1))
    done
    echo "{\"result\":{\"sent\":${count:-0},\"rtts_ms\":[$rtts]}}"
    ;;
  *)
    echo '{"error":"unsupported method"}'
    ;;
esac
