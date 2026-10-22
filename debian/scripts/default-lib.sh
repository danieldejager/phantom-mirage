# Shared by check-default, pm-start, phantom-mirage-setup and the init
# script (#110). POSIX sh; meant to be sourced.
#
# /etc/default/phantom-mirage is NOT sourced and NOT read with systemd's
# EnvironmentFile=: both let a quoted value run on over several lines, so
# one stray quote (NETWORK="10.211.55.200/29 with no closing quote) made
# NETWORK swallow the comments below it up to OPTIONS="...", and the
# daemon got "-x and" from "This includes: -f, -l, -p, -x and -a.".
# pm_load_default accepts only one KEY=VALUE per line and rejects anything
# else with a clear message.

PM_EX_CONFIG=78

pm_fail() {
	echo "phantom-mirage: $*" >&2
	exit $PM_EX_CONFIG
}

# pm_load_default FILE: set the variables assigned in FILE.
pm_load_default() {
	_f=$1 _n=0
	[ -r "$_f" ] || pm_fail "cannot read $_f"
	while IFS= read -r _l || [ -n "$_l" ]; do
		_n=$((_n + 1))
		_l=${_l%"$(printf '\r')"}
		# strip leading/trailing blanks
		_l=${_l#"${_l%%[![:space:]]*}"}
		_l=${_l%"${_l##*[![:space:]]}"}
		case $_l in ''|'#'*) continue ;; esac
		case $_l in 'export '*) _l=${_l#export }; _l=${_l#"${_l%%[![:space:]]*}"} ;; esac
		case $_l in
			*=*) ;;
			*) pm_fail "$_f line $_n: expected KEY=VALUE or a # comment, got: $_l" ;;
		esac
		_k=${_l%%=*} _v=${_l#*=}
		case $_k in
			''|[0-9]*|*[!A-Za-z0-9_]*) pm_fail "$_f line $_n: invalid variable name \"$_k\"" ;;
		esac
		case $_v in
			\"*\")	_v=${_v#\"}; _v=${_v%\"}; _q=1 ;;
			\'*\')	_v=${_v#\'}; _v=${_v%\'}; _q=1 ;;
			*)	_q= ;;
		esac
		case $_v in
			*[\"\']*) pm_fail "$_f line $_n: unbalanced or stray quote in $_l (each value must be on one line, quoted as a whole, e.g. $_k=\"value\")" ;;
			*[\$\`\\]*) pm_fail "$_f line $_n: \$, \` and \\ are not supported in $_l" ;;
		esac
		if [ -z "$_q" ]; then
			case $_v in *[[:space:]]#*)
				pm_fail "$_f line $_n: $_l has a comment after the value; put comments on their own line" ;;
			esac
			case $_v in *[[:space:]]*)
				pm_fail "$_f line $_n: $_l has spaces; quote the value, e.g. $_k=\"$_v\"" ;;
			esac
		fi
		eval "$_k=\$_v"
	done < "$_f"
}

# pm_check FILE: INTERFACE/NETWORK sanity checks on the loaded values.
pm_check() {
	DEFAULT=$1
	SYSNET=${PM_SYSFS_NET:-/sys/class/net}
	if [ -z "$INTERFACE" ]; then
		pm_fail "INTERFACE is not set in $DEFAULT; set it to the decoy interface (list interfaces with: ip -br a)"
	fi
	case $INTERFACE in
		*/*|.|..|*[[:space:]]*) pm_fail "INTERFACE=\"$INTERFACE\" in $DEFAULT is not a valid interface name (use one name; extra ones go in OPTIONS as -i NAME)" ;;
	esac
	if [ ! -e "$SYSNET/$INTERFACE" ]; then
		pm_fail "interface \"$INTERFACE\" (INTERFACE in $DEFAULT) does not exist; list interfaces with: ip -br a"
	fi
	
	if [ "$ALLOW_WIDE_NETWORK" = yes ]; then
		return 0
	fi
	
	if [ -z "$NETWORK" ]; then
		pm_fail "NETWORK is not set in $DEFAULT; set it to a small unused block (e.g. 192.168.50.8/29), or set ALLOW_WIDE_NETWORK=yes to answer for every address on $INTERFACE"
	fi
	
	for net in $NETWORK; do
		case $net in
			*/*)
				bits=${net##*/}
				case $bits in
					''|*[!0-9]*) pm_fail "NETWORK \"$net\" in $DEFAULT has an invalid prefix length" ;;
				esac
				case $net in
					*:*) min=120 ;;	# IPv6: at most 256 addresses, like an IPv4 /24
					*) min=24 ;;
				esac
				if [ "$bits" -lt "$min" ]; then
					pm_fail "NETWORK=$net in $DEFAULT is wider than /$min; use a small unused block (e.g. a /29), or set ALLOW_WIDE_NETWORK=yes if you really mean it"
				fi
				;;
		esac
	done
	return 0
}
