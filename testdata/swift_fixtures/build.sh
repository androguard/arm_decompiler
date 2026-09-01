#!/usr/bin/env bash
# Rebuild Swift Phase-6 fixtures (arm64).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
swiftc -parse-as-library -module-name smoke -emit-library -Onone -g \
  -target arm64-apple-macosx14.0 \
  -o libsmoke.dylib smoke.swift
swiftc -parse-as-library -module-name smoke -emit-object -Onone -g \
  -target arm64-apple-macosx14.0 \
  -o smoke.o smoke.swift
echo "built $ROOT/libsmoke.dylib and smoke.o"
