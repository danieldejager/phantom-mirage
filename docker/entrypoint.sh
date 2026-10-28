#!/bin/sh
# Validate the config, then run phantom-mirage in the foreground.
#
#   PHANTOM_MIRAGE_CONFIG      config file (default /etc/phantom-mirage/phantom-mirage.conf)
#   PHANTOM_MIRAGE_INTERFACES  space-separated capture interfaces (default eth0)
#   PHANTOM_MIRAGE_NET         optional: address/range phantom-mirage answers for
#                      (phantom-mirage's trailing net argument)
#   PHANTOM_MIRAGE_JSON_LOG    optional: "stdout" writes JSON Lines events (#24) to
#                      the container's stdout (for a log shipper); any
#                      other value is a file path writable by nobody
#   PHANTOM_MIRAGE_SENSOR_ID   optional: sensor_id in JSON events (default hostname)
#   PHANTOM_MIRAGE_HEARTBEAT   optional: JSON heartbeat interval in seconds
#   PHANTOM_MIRAGE_PERSONALITIES  personality file (default: the project's
#                      own fingerprint database, columbo-v1.db, checked
#                      against its pinned sha256; a -p argument also overrides)
#
# Any arguments are appended to the phantom-mirage command line. Arguments
# starting with --version/--help/--verify-config are passed straight to
# phantom-mirage without starting the daemon.
#
# The pre-rename HONEYD_* names are still accepted (deprecated): each one
# is used only if the PHANTOM_MIRAGE_* variable is unset.
set -eu

for v in CONFIG INTERFACES NET JSON_LOG SENSOR_ID HEARTBEAT UI_GROUP; do
	eval "old=\${HONEYD_$v:-} new=\${PHANTOM_MIRAGE_$v+set}"
	if [ -n "$old" ] && [ -z "$new" ]; then
		echo "phantom-mirage-entrypoint: warning: HONEYD_$v is deprecated, use PHANTOM_MIRAGE_$v" >&2
		eval "PHANTOM_MIRAGE_$v=\$old"
		export "PHANTOM_MIRAGE_$v"
	fi
done

conf=${PHANTOM_MIRAGE_CONFIG:-/etc/phantom-mirage/phantom-mirage.conf}
ifs=${PHANTOM_MIRAGE_INTERFACES:-eth0}

case "${1:-}" in
--version|-V|--help|-h)
	exec /usr/bin/phantom-mirage "$@" ;;
esac

data=/usr/share/phantom-mirage
pers=${PHANTOM_MIRAGE_PERSONALITIES:-$data/columbo-v1.db}
if [ "$pers" = "$data/columbo-v1.db" ]; then
	( cd "$data" && sha256sum -c --status columbo-v1.db.sha256 ) || {
		echo "phantom-mirage-entrypoint: $pers does not match its pinned sha256" >&2
		exit 1
	}
fi

# -p first so a -p in the arguments wins (last one is used)
set -- -f "$conf" -p "$pers" --disable-webserver "$@"
case "${PHANTOM_MIRAGE_JSON_LOG:-}" in
"")	;;
stdout|-) set -- "$@" --json-log=- ;;
*)	set -- "$@" --json-log="$PHANTOM_MIRAGE_JSON_LOG" ;;
esac
[ -n "${PHANTOM_MIRAGE_SENSOR_ID:-}" ] && set -- "$@" --sensor-id="$PHANTOM_MIRAGE_SENSOR_ID"
[ -n "${PHANTOM_MIRAGE_HEARTBEAT:-}" ] && set -- "$@" --heartbeat="$PHANTOM_MIRAGE_HEARTBEAT"
for i in $ifs; do set -- -i "$i" "$@"; done

# phantom-mirage needs these at runtime; with a read-only rootfs mount a tmpfs
# on /run (see docs/docker.md).
mkdir -p /run

# Only asked to verify: run that once and exit with its status.
case " $* " in
*" --verify-config "*) exec /usr/bin/phantom-mirage "$@" ${PHANTOM_MIRAGE_NET:-} ;;
esac

echo "phantom-mirage-entrypoint: verifying $conf" >&2
/usr/bin/phantom-mirage --verify-config "$@" ${PHANTOM_MIRAGE_NET:-}

exec /usr/bin/phantom-mirage -d "$@" ${PHANTOM_MIRAGE_NET:-}
