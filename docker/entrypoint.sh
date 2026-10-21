#!/bin/sh
# Validate the config, then run honeyd in the foreground.
#
#   HONEYD_CONFIG      config file (default /etc/honeyd/honeyd.conf)
#   HONEYD_INTERFACES  space-separated capture interfaces (default eth0)
#   HONEYD_NET         optional: address/range honeyd answers for
#                      (honeyd's trailing net argument)
#   HONEYD_JSON_LOG    optional: "stdout" writes JSON Lines events (#24) to
#                      the container's stdout (for a log shipper); any
#                      other value is a file path writable by nobody
#   HONEYD_SENSOR_ID   optional: sensor_id in JSON events (default hostname)
#   HONEYD_HEARTBEAT   optional: JSON heartbeat interval in seconds
#
# Any arguments are appended to the honeyd command line. Arguments
# starting with --version/--help/--verify-config are passed straight to
# honeyd without starting the daemon.
set -eu

conf=${HONEYD_CONFIG:-/etc/honeyd/honeyd.conf}
ifs=${HONEYD_INTERFACES:-eth0}

case "${1:-}" in
--version|-V|--help|-h)
	exec /usr/bin/honeyd "$@" ;;
esac

set -- -f "$conf" --disable-webserver "$@"
case "${HONEYD_JSON_LOG:-}" in
"")	;;
stdout|-) set -- "$@" --json-log=- ;;
*)	set -- "$@" --json-log="$HONEYD_JSON_LOG" ;;
esac
[ -n "${HONEYD_SENSOR_ID:-}" ] && set -- "$@" --sensor-id="$HONEYD_SENSOR_ID"
[ -n "${HONEYD_HEARTBEAT:-}" ] && set -- "$@" --heartbeat="$HONEYD_HEARTBEAT"
for i in $ifs; do set -- -i "$i" "$@"; done

# honeyd needs these at runtime; with a read-only rootfs mount a tmpfs
# on /run (see docs/docker.md).
mkdir -p /run

# Only asked to verify: run that once and exit with its status.
case " $* " in
*" --verify-config "*) exec /usr/bin/honeyd "$@" ${HONEYD_NET:-} ;;
esac

echo "honeyd-entrypoint: verifying $conf" >&2
/usr/bin/honeyd --verify-config "$@" ${HONEYD_NET:-}

exec /usr/bin/honeyd -d "$@" ${HONEYD_NET:-}
