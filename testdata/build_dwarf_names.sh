#!/bin/bash
# Rebuild dwarf_names.o (DWARF5 names fixture for P4-2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/dwarf_names.c"
OUT="$ROOT/dwarf_names.o"
cat > "$SRC" <<'EOF'
int add1(int x) { return x + 1; }
int absdiff(int a, int b) {
    if (a > b) {
        return a - b;
    }
    return b - a;
}
EOF
clang -g -O0 -arch arm64 -fno-inline -c -o "$OUT" "$SRC"
echo "wrote $OUT"
dwarfdump "$OUT" 2>&1 | grep -E 'DW_AT_name|DW_TAG_formal|DW_TAG_subprogram' | head -20
