#!/bin/sh
# Minimal Packeteer exec plugin (target source), protocol packeteer-exec/v1.
#
# Packeteer writes ONE JSON request to stdin and expects ONE JSON response on
# stdout. Anything written to stderr is logged at debug level.
#
# Mount into the container at /etc/packeteer/plugins/static-targets.sh and
# configure:
#
#   sources:
#     - type: exec
#       name: example
#       config:
#         command: static-targets.sh
#
# Uses only POSIX sh so it runs in the stock (alpine) image. Real plugins
# would parse JSON properly (jq, Python, Go, ...).
req=$(cat)
case "$req" in
  *'"method":"init"'*)
    echo '{"result":{}}'
    ;;
  *'"method":"targets"'*)
    echo '{"result":{"targets":[{"prefix":"198.51.100.0/24","host":"198.51.100.1"},{"prefix":"203.0.113.0/24","weight":2}]}}'
    ;;
  *)
    echo '{"error":"unsupported method"}'
    ;;
esac
