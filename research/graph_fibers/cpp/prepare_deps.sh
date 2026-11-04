#!/bin/sh
set -eu
cd "$(dirname "$0")"
for site in ../.venv/lib/python*/site-packages; do
    if [ -d "$site/z3/include" ] && [ -f "$site/pypcode/processors/x86/data/languages/x86-64.sla" ]; then
        mkdir -p .deps/z3 .deps/zlib .deps/spec
        cp -a "$site/z3/include" "$site/z3/lib" .deps/z3/
        cp "$site/pypcode/zlib/zlib.h" "$site/pypcode/zlib/zconf.h" .deps/zlib/
        cp "$site/pypcode/processors/x86/data/languages/x86-64.sla" .deps/spec/
        sha256sum .deps/z3/lib/libz3.so .deps/spec/x86-64.sla > .deps/SHA256SUMS
        exit 0
    fi
done
printf '%s\n' 'Missing downloaded native SDK files; set Z3_ROOT, ZLIB_INCLUDE, SLA_FILE when building/running.' >&2
exit 1
