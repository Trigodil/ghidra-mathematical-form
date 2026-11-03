# Whole-project source recovery

The objective is a complete source project whose build reproduces every byte of
the target ELF. The CLI now attempts a whole-project rebuild after native analysis;
function coverage, emitted pseudocode and successful compilation do not satisfy
that objective. This is **not yet a general full-source recovery algorithm**.

Without a supplied source grammar, all emitted function bodies are combined into
one C proposal, with basic decompiler type aliases. No missing function is replaced
with a stub. Inferred types, globals, compiler intrinsics, runtime code and build
settings may prevent this proposal from compiling. The default proposal generator
does not repair those problems or automatically infer a source grammar.

## Run

From the checkout root:

```sh
tools/re-cli/bin/re- /path/to/program -o /tmp/program-recovery
```

To reuse existing decompilation without rerunning the native analyzers:

```sh
tools/re-cli/bin/re- /path/to/program -o /tmp/program-recovery \
  --reuse-analysis /path/to/previous/report.json
```

The previous report must identify the same path and SHA-256. Its pseudocode is
copied into the new output; the old report is not changed. Byte comparison of the
new build remains mandatory. Existing decompilation is candidate evidence, not a
proof of equivalence. Build attempts are rerun, not accepted from cached results.

Use `--recovery-spec project-grammar.json` to search explicit whole-project source
choices and compiler profiles. The file has this structure:

```json
{
  "version": 1,
  "targets": {
    "program": {
      "files": {
        "state.h": "extern unsigned state; unsigned step(unsigned);\n",
        "worker.c": "#include \"state.h\"\nunsigned state=@@INITIAL@@;\nunsigned step(unsigned x){if(x&1)state+=x;else state^=x;return state;}\n",
        "main.c": "#include \"state.h\"\nint main(int argc,char **argv){unsigned y=0;for(unsigned i=0;i<(unsigned)argc;++i)y+=step(i);return y&255;}\n"
      },
      "holes": {
        "INITIAL": [
          {"text": "2", "cost": 0},
          {"text": "7", "cost": 1}
        ]
      },
      "profiles": [
        {"compiler": "gcc", "flags": ["-O1"], "sources": ["main.c", "worker.c"], "cost": 0}
      ]
    }
  }
}
```

Target keys are filenames for a single input or paths relative to an input folder.
Every translation unit must participate in each profile. Headers can be shared
between translation units. A hole has the same substitution at every occurrence,
including occurrences in different files. Choices can contain source statements
or declarations, not just constants. Substitution is literal and nonrecursive.

The search lazily traverses the finite product of choices and compiler profiles
in nondecreasing total declared cost. It builds complete projects rather than
accepting individual functions independently. This is enumerative compiler-fiber
search; it is not an SMT synthesis procedure and does not automatically derive new
choices from a compiler diagnostic. Its cost is generally exponential in the
number of independent choices. Cost measures the supplied preference, not an
inferred probability of historical authorship.

`--recovery-candidates` sets the per-binary build budget (default 64).
`--function-timeout` and `--memory-mb` also bound each build. Reaching a budget
never certifies that no source exists. No shell commands, object inputs, compiler
plugins, arbitrary compiler paths or build scripts are accepted in profiles.
The supported flag set is explicit in `full_recovery.py`.

## Acceptance and artifacts

Each binary's `full-recovery/` directory contains:

- `grammar.json`: the complete source search specification.
- `report.json`: search state, every attempt, unresolved attempts and recovery status.
- `attempts/NNNNNN/`: complete generated source files, `build.json`, `rebuild.py`,
  compiler identity/version, build log, and the rebuilt ELF if compilation succeeds.
- `comparison.json` for successful builds: both hashes, file lengths, differing-byte
  count and the first byte mismatch, including end-of-file mismatches.

From an attempt directory, `python3 rebuild.py` rebuilds the source using the
recorded command and controlled environment. It requires the same installed system
toolchain and libraries; dependencies are not vendored, and portable reproducibility
is not established. The script builds but does not execute the result.

`verified_exact` requires streaming comparison of the **entire file**, with the
input hash checked against the initial target hash. No normalization, code-section
comparison, metadata removal, byte copying from the target or binary patching is
performed by the reconstruction engine. Candidate admissibility remains relative
to the supplied C/C++ grammar; arbitrary submitted source has not been independently
proved free of embedded-code tricks. The default generator uses decompiler text.

Other terminal states include `grammar_exhausted`, `budget_exhausted`, `unresolved`,
`input_changed`, and `no_source_candidate`. Compile failures and byte mismatches
are separate attempt states. Timeouts, missing compilers and failed build isolation
remain unresolved. A minimum-cost claim is only relative to the supplied finite
grammar and is withheld if earlier attempts were unresolved.

`whole_binary_recovered` means an exact constructive rebuild of one ELF artifact.
`historical_source_recovered` remains false: binary equality does not identify the
original author's source spelling. Analysis status is retained separately.
Directory scans also report `whole_binary_set_recovered`; matching scanned ELFs does
not certify recovery of application resources or dependency sources, so the whole
application flag remains false for directory inputs. A single-file input's whole
application flag has the explicitly reported scope `single ELF artifact`.

Compilation runs under resource limits and Landlock ABI 3 or newer. Writes are
confined to the candidate directory, and candidate files cannot execute. The
compiler can read system toolchain directories, which may contain system binaries;
the target path is never passed as a compiler input. Targets and rebuilt binaries
are never run by this workflow.

## Claude 2.1.316 result

The local target has SHA-256
`fd13c70000fec3f2116dfbcbb6121210b4a29328bf0e46210a59dd594a67d824`.
The whole-project attempt using all 712 previously emitted functions fails
compilation. Diagnostics include invalid inferred aggregate operations, undeclared
globals/register state, missing helper intrinsics and calls to unrecovered native
functions. The source grammar currently contains one automatic proposal, so its
failure exhausts that grammar; it does not prove recovery impossible.

The earlier named-function audit covers 189,210 of 114,102,976 executable segment
bytes. Bundled JavaScript extraction also does not reconstruct Bun's native runtime
or its original build. **Claude has not been fully recovered.** The current change
supplies whole-project search and an exact acceptance check; automatic reconstruction
of the missing code, types, data and build remains necessary.

## Validation

```sh
python3 -m unittest discover -s tools/re-cli/tests -v
```

New integration checks rebuild a complete multi-file executable with calls, a loop,
a branch and shared mutable state. They exercise global source choices, reject
non-code byte differences, distinguish exhausted search from budget and timeout,
check isolation, validate analysis reuse, and verify CLI reporting. The fixture's
source grammar is supplied; these tests do not establish automatic recovery of an
unknown arbitrary program.
