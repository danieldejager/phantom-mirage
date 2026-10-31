#!/bin/sh
# Security regression tests: small in-process harnesses built with
# AddressSanitizer, UndefinedBehaviorSanitizer and LeakSanitizer against
# the real sources. Local only: sockets are socketpairs, resolvers and
# connects are stubbed, and no packet leaves the process.
#
#   ./autogen.sh && ./configure && make check-security
#   tests/security/run.sh [name ...]      # one or more tests by name
#
# Each test is tests/security/<name>.test, a shell fragment that uses the
# helpers below and returns non zero on failure.
set -eu

cd "$(dirname "$0")/../.."
ROOT=$PWD
T=$ROOT/tests/security
OUT=${OUT:-$T/out}
CC=${CC:-clang}
SAN="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined"
SAN="$SAN -fno-sanitize=alignment -fno-sanitize-recover=all"
# A printf style call whose arguments do not match its format fails the build
SAN="$SAN -Werror=format"
ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1}
UBSAN_OPTIONS=${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}
# Leaks made while loading the daemon's data files at start up are known
LSAN_OPTIONS=${LSAN_OPTIONS:-suppressions=$T/lsan.supp:print_suppressions=0}
export ASAN_OPTIONS UBSAN_OPTIONS LSAN_OPTIONS

if [ ! -f Makefile ]; then
	echo "tests/security: run ./configure first" >&2
	exit 2
fi
mkdir -p "$OUT/obj"

q() { make -s -f Makefile -f - "$1" <<'MK'
cflags: ; @echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CFLAGS)
objs: ; @echo $(am_phantom_mirage_OBJECTS)
libs: ; @echo $(phantom_mirage_LDADD) $(LIBS) | sed "s/[^ ]*sha1[^ ]*\\.o//"
MK
}
CF="$(q cflags) -I$ROOT -I$ROOT/subsystems"
LIBS_H=$(q libs)

# Compile a harness with extra sources: cc_san NAME source...
cc_san() {
	n=$1; shift
	# shellcheck disable=SC2086
	$CC $SAN $CF "$@" $LIBS_H -o "$OUT/$n"
}

# Checksum of every header the daemon objects can include. Objects are
# only rebuilt when their .c is newer, so a header change drops them all.
hdr_sum() {
	cat ./*.h compat/*.h subsystems/*.h fuzz/*.h 2>/dev/null | cksum
}

# Build the daemon objects once (honeyd.c comes in via fuzz_common.c)
DOBJS=
daemon_objs() {
	[ -n "$DOBJS" ] && return 0
	# The Makefile rules only generate parse.c and lex.c when missing
	[ parse.y -nt parse.c ] && rm -f parse.c parse.h
	[ lex.l -nt lex.c ] && rm -f lex.c
	make -s parse.c lex.c >/dev/null
	sum=$(hdr_sum)
	if [ "$sum" != "$(cat "$OUT/obj/headers.sum" 2>/dev/null)" ]; then
		rm -f "$OUT"/obj/*.o "$OUT/obj/headers.sum"
	fi
	for o in $(q objs) sha1.o; do
		[ "$o" = honeyd.o ] && continue
		s=${o%.o}.c
		if [ ! -f "$OUT/obj/$o" ] || [ "$s" -nt "$OUT/obj/$o" ]; then
			# shellcheck disable=SC2086
			$CC $SAN $CF -c "$s" -o "$OUT/obj/$o"
		fi
		DOBJS="$DOBJS $OUT/obj/$o"
	done
	echo "$sum" > "$OUT/obj/headers.sum"
	# shellcheck disable=SC2086
	$CC $SAN $CF -DFUZZ_DATADIR="\"$ROOT\"" -c fuzz/fuzz_common.c \
	    -o "$OUT/obj/fuzz_common.o"
	DOBJS="$DOBJS $OUT/obj/fuzz_common.o"
}

# Link a harness against the whole daemon: cc_daemon NAME harness.c
cc_daemon() {
	daemon_objs
	n=$1; shift
	w="-Wl,--wrap=fork,--wrap=execv,--wrap=execvp,--wrap=connect"
	w="$w,--wrap=ip_open,--wrap=ip_send,--wrap=eth_send"
	# shellcheck disable=SC2086
	$CC $SAN $CF -I"$ROOT/fuzz" "$@" $DOBJS $LIBS_H $w -o "$OUT/$n"
}

# Run a built harness; fail on a non zero exit or any sanitizer report.
# run_clean NAME [args...]; the log is $OUT/NAME.log. Only the return
# value reports the result: a test's own variables, such as an rc that
# collects several cases, are left alone.
run_clean() {
	_rc_n=$1; shift
	_rc_x=0
	"$OUT/$_rc_n" "$@" > "$OUT/$_rc_n.log" 2>&1 || _rc_x=$?
	if [ $_rc_x -ne 0 ] || grep -Eq \
	    'ERROR: (Address|Leak)Sanitizer|runtime error:|Assertion' \
	    "$OUT/$_rc_n.log"; then
		grep -E 'ERROR|SUMMARY|runtime error|Assertion|FAIL' \
		    "$OUT/$_rc_n.log" | head -5 >&2
		echo "$_rc_n: exit $_rc_x" >&2
		return 1
	fi
	return 0
}

if [ $# -gt 0 ]; then
	tests=$*
else
	tests=$(cd "$T" && ls ./*.test 2>/dev/null | sed 's|^\./||; s|\.test$||')
fi

fail=0
for t in $tests; do
	if ( . "$T/$t.test" ); then
		echo "PASS: $t"
	else
		echo "FAIL: $t"
		fail=1
	fi
done
exit $fail
