#!/bin/sh
# Build honeyd's libFuzzer harnesses (issue #38) with clang + ASan/UBSan.
#
#   fuzz/build.sh            # from the repository root
#
# Produces fuzz/out/{fuzz_packet,fuzz_config,fuzz_macprefix}. Uses the
# normal autotools build for honeyd's objects, so run it in a clean tree
# (it runs autogen/configure itself).
set -eu

cd "$(dirname "$0")/.."
ROOT=$PWD
OUT=$ROOT/fuzz/out
CC=${CC:-clang}
SAN="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=alignment -fno-sanitize-recover=all"
mkdir -p "$OUT"

if [ ! -f Makefile ]; then
	./autogen.sh
	CC="$CC" CPPFLAGS="$SAN" ./configure --prefix=/usr
fi
# Ask make for the exact compile flags and honeyd's object/library lists
q() { make -s -f Makefile -f - "$1" <<'MK'
cflags: ; @echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CFLAGS)
objs: ; @echo $(am_honeyd_OBJECTS)
libs: ; @echo $(honeyd_LDADD) $(LIBS) | sed "s/[^ ]*sha1[^ ]*\\.o//"
MK
}
CFLAGS_H=$(q cflags)
OBJS=$(q objs | tr ' ' '\n' | grep -v '^honeyd\.o$' | tr '\n' ' ')
LIBS_H=$(q libs)
# Only honeyd's objects (plus the sha1 compat object); no daemon link
# shellcheck disable=SC2086
make -j"$(nproc)" CC="$CC" CPPFLAGS="$SAN" $OBJS sha1.o
OBJS="$OBJS sha1.o"

WRAP="-Wl,--wrap=fork,--wrap=execv,--wrap=execvp,--wrap=connect"
WRAP="$WRAP,--wrap=ip_open,--wrap=ip_send,--wrap=eth_send"

# shellcheck disable=SC2086
$CC $SAN $CFLAGS_H -DFUZZ_DATADIR="\"$ROOT\"" -I"$ROOT" \
	-c fuzz/fuzz_common.c -o "$OUT/fuzz_common.o"

for t in fuzz_packet fuzz_config; do
	# shellcheck disable=SC2086
	$CC $SAN $CFLAGS_H -I"$ROOT" -c fuzz/$t.c -o "$OUT/$t.o"
	# shellcheck disable=SC2086
	$CC -fsanitize=fuzzer,address,undefined "$OUT/$t.o" \
		"$OUT/fuzz_common.o" $OBJS $LIBS_H $WRAP -o "$OUT/$t"
done

# Standalone: ethernet.c only
# shellcheck disable=SC2086
$CC $SAN -fsanitize=fuzzer $CFLAGS_H -I"$ROOT" fuzz/fuzz_macprefix.c \
	$LIBS_H -o "$OUT/fuzz_macprefix"

ls -la "$OUT"/fuzz_packet "$OUT"/fuzz_config "$OUT"/fuzz_macprefix
