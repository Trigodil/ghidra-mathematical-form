# Native mathematical workflow

The active implementation is C++17. It compiles SLEIGH directly from this fork
and uses the Z3 C++ API. Building and running it does not execute Python.
The original Python experiment one directory above is retained as a reference.

## Run

From the repository root, using the native dependencies already prepared here:

```sh
make -C research/graph_fibers/cpp -j4 check
```

This builds the native engine and our fixture library, runs the validation harness,
and writes cpp/build/results/report.txt, p-code/model descriptions, sparse graph
DOT files, and replayable SMT-LIB queries. Exhaustive native input enumeration is
used only as independent validation of the small byte fixtures, not to perform the
symbolic box queries.

Analyze a named function without loading or executing its ELF:

```sh
cd research/graph_fibers/cpp
./build/graph-fibers --sla .deps/spec/x86-64.sla \
  --binary build/fixtures.so --symbol affine \
  --arg x:8:DIL --arg y:8:SIL --return AL --output build/analysis
```

The input and return ABI must be supplied. For affine32, use x:32:EDI,
y:32:ESI, and --return EAX. For pointer fixtures, use p:64:RDI and q:64:RSI.
Only --fixtures enters the validation mode that executes a shared library.

## Boxes and memory

A box is a predicate over possible machine states. It need not be a rectangular
Cartesian product: constraints can retain correlations between registers,
addresses, and memory contents. All boxes refer to the same state variables.

- A.intersect(Z) conjoins their predicates.
- A.subset_of(B) searches for a state satisfying A AND NOT B. unsat proves
  containment within the declared model; sat gives a counterexample.
- A.overlaps(Z) checks A AND Z. sat supplies a shared state; unsat means
  the intersection is empty. unknown remains unresolved.

These are sets of machine states, not address intervals. Address footprints can
be constraints within them. Memory is one shared SMT byte array, and stores and
loads retain alias relationships across chunks. Dividing work into boxes does
not assume disjoint memory or independent computation.

The alias fixture writes *p=7, then *q=9, then returns *p. Its result is 9
exactly when p==q, and 7 otherwise. In a two-byte allocation box B, define
A=B AND p==q and Z=B AND returned_byte==9. The workflow checks both containments
between A and Z and produces a witness in their intersection.

The partial-overlap fixture writes bytes 0x11,0x22 at p, writes 0x33 at q,
then reads the two-byte value at p. It distinguishes q==p, q==p+1, and other
addresses. Validation checks the returned value and final memory bytes.

The 512-by-512 example uses two 9-bit variables, not 262,144 materialized cells.
It checks box containment and feasible/impossible intersections symbolically.
An ordinary sum is represented with 10 bits to avoid accidental 9-bit wraparound.

## Actual complexity

Let V and E count graph vertices and directed edges; d(v) counts the incident
edges processed at a vertex. Graph storage is O(V+E). With expected constant-time
hash-table operations, one color-refinement round costs

```text
O(V + E + sum_v d(v) log d(v))
```

because each neighborhood is sorted. Repeated rounds multiply this cost by r.
Hash keys are checked with exact vector equality, so hash collisions cannot
produce false color equality. Adversarial hash collisions can still hurt runtime.
Different colors can rule out a labeled graph match; matching colors do not prove
graph isomorphism or semantic equivalence. A six-cycle/two-triangle regression
case explicitly demonstrates this limit of 1-WL.

Neither the whole workflow nor SMT solving is claimed to be O(n). Branch paths
can grow exponentially; constraint problems can be difficult. Symbolic state
copies at a branch also cost time. C++ reduces runtime overhead but does not change
these algorithmic bounds. Reported timings describe only the local examples.

## Constructive inverse and dimension experiments

Run the additional experiments with:

```sh
make -C research/graph_fibers/cpp -j4 inverse-check
```

For the canonical source family f(x,y)=a*x+b*y+c (mod 2^w), coefficients are
normalized to unsigned w-bit values. The inverse recovers them from the lifted
binary at three basis inputs:

```text
c = f(0,0)
a = f(1,0) - c  (mod 2^w)
b = f(0,1) - c  (mod 2^w)
```

It then checks membership against the whole modeled input domain, proves that
the normalized coefficient triple is unique within this family, generates a
canonical C++ function, and recompiles it. An exact inverse is accepted only when
the extracted function bytes match byte-for-byte. Semantic equivalence without
matching bytes is reported separately and does not count as an exact round trip.

Here C_theta maps the canonical source text to the named function's code bytes
with the recorded g++ version and fixed flags. The accepted inverse satisfies
C_theta(I(b)) = b on its checked domain. This is a partial right inverse of that
map; it is not presented as an inverse for every compiler, source language, or
whole executable. It does not require the historical source text to have used
the canonical spelling. Zero coefficients, modular boundary coefficients, u8/u32
cases, and a non-affine rejection case are included in validation.

For a specific binary, add --recover affine to the analysis command above.
This mode compiles the generated candidate source, but does not load or execute
the supplied ELF. Artifacts under inverse/ include the recovered source,
compiler version/log, both function-byte files, membership/uniqueness SMT queries,
and the round-trip report. Exit status 2 means semantics matched but bytes did not.

The dimension experiment represents 6*x+4 in three ways: modular word
arithmetic, an F_2 Boolean circuit with explicit carries, and a real-coordinate
embedding whose points remain constrained to hypercube vertices. These models
are checked to have the same execution fiber for output byte 22: {3,131}.
Keeping the quotient k=floor((6*x+4)/256) gives an injective augmented
observation on byte inputs: (22,0) identifies 3, while (22,3) identifies 131.
On this image, the inverse is x=(y+256*k-4)/6.

The quotient is extra observed state. The implementation also lifts the actual
affine machine code with full EAX observed at RET and full EDI/ESI inputs
constrained to 0<=EDI<256, ESI=0; it checks these two refinements in the binary
model. This is static analysis, not a collected debugger trace. Relaxing the real
coordinates continuously admits spurious candidates; discrete constraints remain
part of the exact model.

The topology check uses the underlying simple undirected graph as a 1-dimensional
complex. It discards edge direction/multiplicity and does not fill triangles with
faces. Component and independent-cycle counts (beta0,beta1) distinguish a
six-cycle (1,1) from two triangles (2,2), even though the tested 1-WL coloring
cannot distinguish them. These invariants improve discrimination for that pair;
they are not claimed to characterize every computation.

## Counterexample-guided state loop

```sh
make -C research/graph_fibers/cpp -j4 state-check
```

synthesis.hpp uses one controller for formula reconstruction and invariant
parameters. It alternates between proposing parameters, searching for a violating
state, and adding that counterexample as a new constraint. Acceptance requires
an unsat counterexample query over the whole declared state domain. Proposal and
state variables have finite bit-vector domains. Solver unknown and iteration
limits remain unresolved; exhaustion applies only to the current grammar.

The expression grammar includes affine/quadratic modular polynomials, XOR, AND,
OR, products, a mixed multiply/XOR expression, and a guarded affine/XOR family.
Source is generated and recompiled after semantic verification. verified_exact
and verified_semantic are separate states: only the former reproduces the input
function bytes. Polynomial coefficients over modular rings need not be unique.
Fresh solver parameter symbols prevent collisions with input-state names.

loop_proof.hpp extracts actual one-lap transitions from compiled code. The
current contracts explicitly bind EDI/ESI to byte-valued inputs, EDX to the
iteration counter, and AL to the accumulator. A single direct back-edge header
is located from the code. These bindings are fixture contracts, not automatically
recovered loop interfaces for arbitrary executables.

The controller synthesizes a modular-add stride or an XOR/parity mask. Separate
SMT queries check initialization, preservation, exit conditions, and decrease of
the natural-number ranking function n-i. Wrong strides/masks and a constant
ranking function produce counterexamples. The XOR example is non-affine over
modular word arithmetic but linear in bit coordinates; variable products and
AND provide genuinely nonlinear expression cases in the same controller.

The seven formula cases and two compiled loops receive 589,824 independent
native input checks. The loop checker currently requires register-only contracts;
memory loop invariants and nested loops remain unsupported. Reports and proof
queries are saved under build/state-results/.

## Large executable benchmark

```sh
make -C research/graph_fibers/cpp -j4 build/benchmark
cd research/graph_fibers/cpp
./build/benchmark --binary /path/to/executable --sla .deps/spec/x86-64.sla \
  --samples 256 --probes 24 --output build/benchmark-results
```

This test does not execute its input ELF. The reader uses a read-only memory map
and builds a reusable symbol index once, rather than copying the entire file or
rescanning all symbols for each lookup. Index construction includes an address
sort; it is not claimed to have an unconditional linear bound.

The benchmark selects evenly spaced indices from address-sorted, unique-address
named functions of at most 64 KiB. Raw translation uses a linear sweep limited to
4096 bytes/256 instructions per sampled function. This is a sampled decoder test,
not reachable-control-flow coverage or whole-program decompilation. Unsymbolized
functions and bundled non-native assets are not represented by the symbol sample.

A separate small-function probe attempts symbolic lifting with two byte inputs
and an AL output. That ABI is an explicit probe hypothesis, not an inferred
signature. Up to three suitable probe models are sent through reconstruction.
Per-function TSV logs, operation/failure counts, timing, and peak RSS are recorded.

The first real target was the user's installed Claude Code 2.1.316 executable.
Its bounded-sample results are in build/claude-2.1.316/. The decoder and symbolic
reconstructor have separate success counts; translation success is not reported
as a reconstructed source function.

### Pointer and stack-aware follow-up

```sh
make -C research/graph_fibers/cpp build/abi-summary
cd research/graph_fibers/cpp
./build/abi-summary --binary /path/to/the/same/claude-executable \
  --sla .deps/spec/x86-64.sla --output build/claude-abi --timeout-ms 300000
```

This follow-up uses explicit 64-bit pointer, stack, and saved-frame-register
inputs and observes full RAX, RSP, RBP and final RAM. Candidate summaries are
supplied for four named functions in the tested executable version; offsets and
the returned version-string address are version-specific hypotheses checked
against the machine model, not automatically recovered API declarations.

The two field getters and uv_version_string passed. napi_get_version currently
remains unresolved after solver timeouts, including a case-split attempt with
stack-frame separation constraints. It is not reported as verified. Exit code 2
and the report preserve unresolved/rejected summaries separately from acceptance.
No candidate source-byte inverse is asserted by this follow-up.

--timeout-ms controls each summary-verification query (default 10000 ms).
Use 300000 for five minutes per query or 0 to leave the summary solver unbounded.
These are internal solver limits, not Bash timeouts. Instruction-lifting and
exploration safeguards remain separate. Use a different output directory to retain
the original benchmark results.

Whole-register expression caching avoids splitting and rebuilding every pointer.
Overlapping writes invalidate cached aliases; symbolic AL/AH overwrite tests
check consistency of the resulting RAX/EAX observations. The original byte model
remains the fallback for partial aliases. This optimization preserves semantics;
it does not change the worst-case complexity of the constraint problem.

## Semantics and limits

The implementation supports a subset of raw p-code for fixed-width arithmetic,
flags, comparisons, extensions, shifts, direct acyclic branches, and little-endian
RAM loads/stores. It tracks overlapping register bytes. An initial register byte
is projected away only after an SMT check proves both observed return and final
RAM independent of it. Return-path coverage must be proved for the input domain.

Observations stop just before a normal RET, under the supplied ABI. RAM is a total
array of bytes indexed by 64-bit addresses. OS page mappings, faults, permissions,
MMIO, concurrency, timing, and other register observations are outside this model.
This is not a general safety proof for executing an arbitrary binary.

The baseline acyclic lifter stops at loops; the separate contract-based checker
above handles its declared loop families. Calls, indirect jumps,
intra-instruction branches, and unsupported p-code also fail explicitly. State or
instruction limits never produce a claim of complete coverage. Solver unknown
and truncated fiber enumeration are preserved as incomplete results. Unsat results
are solver checks, not independently verified proof certificates.

## Native dependencies and provenance

The SLEIGH C++ sources are compiled from
Ghidra/Features/Decompiler/src/decompile/cpp in this checkout. The prepared native
Z3 SDK is version 4.16.0; the compiled x86-64 specification and zlib headers were
taken from the already downloaded pypcode 3.3.3 package. The specification is not
claimed to have been compiled from this fork. .deps/SHA256SUMS records the native
library and specification hashes.

sh prepare_deps.sh can copy those native artifacts from the earlier local
download without running Python. On another machine, supply a native Z3 SDK,
zlib development headers/library, and a compatible compiled x86-64 SLEIGH spec:

```sh
make Z3_ROOT=/path/to/z3-sdk ZLIB_INCLUDE=/path/to/zlib/include \
     ZLIB_LIB=-lz SLA_FILE=/path/to/x86-64.sla check
```

The default link uses Linux's libz.so.1. Generated dependencies, objects,
binaries, and reports are ignored by Git. No Ghidra core source is modified.
