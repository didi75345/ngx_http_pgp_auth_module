#!/bin/sh
# test/fuzz/build.sh - build the libFuzzer harnesses.
#
# Requires clang with libFuzzer + ASan/UBSan runtimes
# (Debian/Ubuntu: `apt-get install clang libclang-rt-<ver>-dev`).
#
# Usage:
#   sh test/fuzz/build.sh
#   ./test/fuzz/fuzz_gpg_status_parser   -max_len=8200  test/fuzz/seeds/
#   ./test/fuzz/fuzz_form_field_decoder  -max_len=65536 test/fuzz/seeds/
#
# Each binary is a standard libFuzzer target: run it with no arguments for a
# quick smoke pass, point it at test/fuzz/seeds/ to fuzz continuously, or add
# -runs=N / a timeout for CI. A found crash is written to ./crash-<hash> in
# the current directory; reproduce with `./fuzz_<name> crash-<hash>`.

set -eu
cd "$(dirname "$0")"

CC=${CC:-clang}
FLAGS="-g -O1 -fsanitize=fuzzer,address,undefined"

$CC $FLAGS fuzz_gpg_status_parser.c  -o fuzz_gpg_status_parser
$CC $FLAGS fuzz_form_field_decoder.c -o fuzz_form_field_decoder

echo "built: test/fuzz/fuzz_gpg_status_parser, test/fuzz/fuzz_form_field_decoder"
