#!/bin/sh
# Validate the config, then run honeyd in the foreground.
#
#   HONEYD_CONFIG      config file (default /etc/honeyd/honeyd.conf)
#   HONEYD_INTERFACES  space-separated capture interfaces (default eth0)
#   HONEYD_NET         optional: address/range honeyd answers for
#                      (honeyd's trailing net argument)
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
