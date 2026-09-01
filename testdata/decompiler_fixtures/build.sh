#!/bin/bash
# Rebuild arm64 Mach-O fixture binary from C / ObjC sources.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
OUT="${ROOT}/decompiler_fixtures"
OBJDIR="${ROOT}/.objs"
mkdir -p "$OBJDIR"

# Most fixtures at -O0 (readable control flow).
clang -O0 -arch arm64 -fno-inline -c -o "$OBJDIR/arithmetic.o" src/arithmetic.c
clang -O0 -arch arm64 -fno-inline -c -o "$OBJDIR/control_flow.o" src/control_flow.c
clang -O0 -arch arm64 -fno-inline -c -o "$OBJDIR/calls.o" src/calls.c
clang -O0 -arch arm64 -fno-inline -c -o "$OBJDIR/switch.o" src/switch.c
clang -O0 -arch arm64 -fno-inline -fobjc-arc -c -o "$OBJDIR/objc.o" src/objc.m

# Dense switch at -O2 so clang emits a jump table (helpers stay separate).
clang -O2 -arch arm64 -c -o "$OBJDIR/switch_dense_helpers.o" src/switch_dense_helpers.c
clang -O2 -arch arm64 -c -o "$OBJDIR/switch_dense.o" src/switch_dense.c

clang -arch arm64 -fobjc-arc -framework Foundation -o "$OUT" \
  "$OBJDIR/arithmetic.o" \
  "$OBJDIR/control_flow.o" \
  "$OBJDIR/calls.o" \
  "$OBJDIR/switch.o" \
  "$OBJDIR/switch_dense_helpers.o" \
  "$OBJDIR/switch_dense.o" \
  "$OBJDIR/objc.o"

echo "wrote $OUT"
nm -gU "$OUT" | awk '{print $3}' | sort
