# Application reverse-engineering CLI

From the checkout root, install the prepared application and its default command:

```sh
python3 tools/re-cli/install.py
re- /path/to/application folder
```

The installer places `re-` in `~/.local/bin` and copies the native analyzers,
Z3 runtime, extraction helper and language specifications into
`~/.local/lib/re-cli`. Add `~/.local/bin` to your shell's PATH if it is absent.
The installed application works independently of the original checkout.
Use `--prefix /path/to/prefix` for a different installation location.

The folder argument can contain spaces without quotes: consecutive positional
arguments are joined into one path. Shell metacharacters still require normal
shell escaping. This command launches static analysis; it does not execute the
application being analyzed.

Results default to `$XDG_STATE_HOME/re-cli` or `~/.local/state/re-cli`.
Use `--output /path/to/results` to choose a directory outside the backend checkout.
Each binary gets executable-section assembly, per-function pseudocode, analysis
logs and a JSON report. Rerun the same command to reuse successful function
checkpoints. `--fresh` retries them; `--symbolic` also attempts generic register
and RAM models. `re- --help` lists resource limits and other options.

The backend supports little-endian x86-64 ELF executables and shared libraries
on Linux with Landlock ABI 3 or newer and seccomp. It decompiles named, sized
functions. Stripped code still gets an assembly view, but complete source
recovery is not guaranteed. Symlinks are skipped, archives are not unpacked,
and PE/Mach-O binaries and other architectures are reported as unsupported.
The optional Bun extractor supports the stored graph layout implemented by
`extract_bun_static.py`; other layouts remain explicit failures.

Exit codes are 0 for completed supported work, 1 for an error, 2 for partial or
unsupported results, and 130 for interruption. Pseudocode is heuristic and is
not an equivalence proof or recovery of the original source text.

## Building the native backend

Installation requires prepared analyzers. To build them from this checkout:

```sh
python3 tools/re-cli/build_backend.py -j 2
python3 tools/re-cli/install.py
```

Supply a native Z3 SDK in `research/graph_fibers/cpp/.deps/z3`, zlib headers in
`.deps/zlib`, and compiled x86 SLEIGH specifications in `.deps/spec`, including
`x86-64.sla`. These dependencies and generated binaries are not committed.
The build also requires Python 3.11+, a C++17 compiler, the system zlib runtime
and the fork's decompiler sources. Analysis requires binutils (`objdump`),
util-linux (`prlimit`), and the native runtime libraries; Bun extraction also
requires `libzstd.so.1`. No Python package installation is required.

Run the integration checks with the prepared backend:

```sh
python3 -m unittest discover -s tools/re-cli/tests -v
```
