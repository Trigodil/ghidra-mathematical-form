# Application reverse-engineering CLI

From the checkout root, install the prepared application and its default command:

```sh
python3 tools/re-cli/install.py
re- /path/to/application folder
```

The installer places re- in ~/.local/bin and copies the native analyzers,
Z3 runtime, extraction helper and language specifications into
~/.local/lib/re-cli. Add ~/.local/bin to your shell's PATH if it is absent.
The installed application works independently of the original checkout.
Use --prefix /path/to/prefix for a different installation location.

The folder argument can contain spaces without quotes: consecutive positional
arguments are joined into one path. Shell metacharacters still require normal
shell escaping. This command launches static analysis; it does not execute the
application being analyzed.

Results default to $XDG_STATE_HOME/re-cli or ~/.local/state/re-cli.
Use --output /path/to/results to choose a directory outside the backend checkout.
Each binary gets executable-section assembly, per-function pseudocode, analysis
logs and a JSON report. Rerun the same command to reuse successful function
checkpoints. --fresh retries them; --symbolic also attempts generic register
and RAM models. re- --help lists resource limits and other options.

The terminal streams analyzer output and errors live, labels each stage and
function result, and updates a progress bar after each function. In a terminal,
the bar redraws below log messages; redirected output uses plain progress lines.
The bar tracks completed named functions for the current binary, including
resumed results, with success and issue counts. Final totals include
successful, failed, timed-out and partial functions, binary outcomes, analysis
stage outcomes, emitted pseudocode files, resumed work, skipped paths and elapsed
time. Full logs remain available in the result directory.

The backend supports little-endian x86-64 ELF executables and shared libraries
on Linux with Landlock ABI 3 or newer and seccomp. It decompiles named, sized
functions. Stripped code still gets an assembly view, but complete source
recovery is not guaranteed. Symlinks are skipped, archives are not unpacked,
and PE/Mach-O binaries and other architectures are reported as unsupported.
The optional Bun extractor supports the stored graph layout implemented by
extract_bun_static.py; other layouts remain explicit failures.

Exit codes are 0 for completed supported work, 1 for an error, 2 for partial or
unsupported results, and 130 for interruption. Pseudocode is heuristic and is
not an equivalence proof or recovery of the original source text.

The native recovery manifest links to recursive-discovery/sites.tsv and
coverage.tsv. The former records unresolved raw indirect transfers, decode
errors and queued work at the instruction limit; the latter gives decoded and
unexamined executable-byte ranges. Decoding does not prove that bytes are code,
that a function is complete, or that its pseudocode is equivalent. The pipeline
iterates decompiler-resolved calls and switch targets where safe; switch targets
are flow seeds, not function entries. The loader applies x86-64 RELATIVE
relocations at link-time virtual addresses and withholds inferred edges for
functions that read unsupported relocations. Budgets and unexamined ranges identify unfinished analysis, not
proof that recovery is impossible. Function reports include decompiler warnings
and failed or partial results, and completed pseudocode can be resumed.

## Local fiber check

```
sh
python3 tools/re-cli/local_fiber.py --target ELF --function NAME ... --candidate tu.c [--decompiled-report report.json] [--profiles-json p.json] [--budget N]
```

It compiles each candidate TU with -c per compiler profile and compares every named function with the target, masking relocated fields on both sides.
It prints a JSON report (per-function match, sizes, first differing offset, similarity) and stops at the first full TU match; an exhausted budget is not evidence that no source exists.

## Building the native backend

Installation requires prepared analyzers. To build them from this checkout:

```sh
python3 tools/re-cli/build_backend.py -j 2
python3 tools/re-cli/install.py
```

Supply a native Z3 SDK in research/graph_fibers/cpp/.deps/z3, zlib headers in
.deps/zlib, and compiled x86 SLEIGH specifications in .deps/spec, including
x86-64.sla. These dependencies and generated binaries are not committed.
The build also requires Python 3.11+, a C++17 compiler, the system zlib runtime
and the fork's decompiler sources. Analysis requires binutils (objdump),
util-linux (prlimit), and the native runtime libraries; Bun extraction also
requires libzstd.so.1. No Python package installation is required.

Run the integration checks with the prepared backend:

```sh
python3 -m unittest discover -s tools/re-cli/tests -v
```
