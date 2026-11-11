#!/bin/bash -eu

go install github.com/AdamKorcz/go-118-fuzz-build@a70c2aa677fa43583571959478decabe02a96cd6     # v0.0.0-20250520111509-a70c2aa677fa
go get github.com/AdamKorcz/go-118-fuzz-build/testing@a70c2aa677fa43583571959478decabe02a96cd6 # v0.0.0-20250520111509-a70c2aa677fa

# go-118-fuzz-build rewrites one *_test.go and omits sibling test files, so
# unexported helpers (e.g. testConfig) disappear. Build internal test files
# as package sources. Leave package codepair_test alone; that is a different
# package and cannot live in a non-test file next to this one.
for f in *_test.go; do
  if grep -q '^package codepair_test$' "$f"; then
    continue
  fi
  mv "$f" "${f%.go}_pkg.go"
done

compile_native_go_fuzzer github.com/Totative/go-codepair FuzzNormalizeIsIdempotent fuzz_normalize_is_idempotent
compile_native_go_fuzzer github.com/Totative/go-codepair FuzzMessages fuzz_messages
