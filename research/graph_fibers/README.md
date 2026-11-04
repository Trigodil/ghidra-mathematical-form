# Graph coloring and execution fibers: first experiment

**Active workflow: [native C++ implementation](cpp/README.md).** It connects this
fork's SLEIGH engine directly to Z3, adds state boxes, direct branches, and shared
memory with aliasing and partial overlap. The Python experiment below is retained
as the initial reference.

This prototype tests whether graph color refinement helps distinguish compiled
arithmetic functions. It does not recover arbitrary source code or modify Ghidra.
It uses only Python's standard library, GCC, and GNU objdump on Linux x86-64.

From the repository root:

```bash
python3 research/graph_fibers/experiment.py
```

The experiment compiles our seven small C fixtures to a native shared library,
disassembles it, and lifts a restricted subset of register arithmetic into pure
expression DAGs. It checks the lifted result against native execution on all
65,536 input pairs per function, and independently checks candidate formulas.
Artifacts are saved in research/graph_fibers/output/.

## The mathematical model

The observable function is f: (Z/256Z)^2 -> Z/256Z, with unsigned byte inputs and
the returned byte as output. Registers are projected onto their low eight bits.
This projection preserves the supported additions, subtractions, multiplications,
bitwise operations, copies/extensions, and LEA arithmetic. Upper register bits,
flags, memory, timing, exceptions, and other machine effects are outside the model.
The byte function ABI is an explicit assumption, not inferred from the binary.

Each graph vertex initially records operation, width, input role, or constant.
Directed edges record operand position; operands of commutative operations share
an unordered slot. Repeated edges are retained. Pure identical subexpressions are
merged, so this is an expression DAG rather than a complete instruction graph.

Joint 1-dimensional Weisfeiler-Leman refinement repeatedly assigns colors from:

```text
old color, multiset of (incoming slot, neighbor color),
           multiset of (outgoing slot, neighbor color)
```

Palette keys are exact tuples, with no probabilistic hash collision. The old
color prevents partition merging. Refinement stops when no color class splits.
Different stable color histograms rule out isomorphism under this labeling.
Equal histograms mean only that this refinement test cannot distinguish them.
This is color refinement, not minimum proper vertex coloring.

## What the experiment checks

- Different source expressions for the affine function collapse to matching
  arithmetic DAGs with the tested GCC optimization.
- Addition and XOR have the same untyped topology but different typed colors
  and different behavior; an explicit input witnesses the difference.
- Constants and noncommutative operand positions affect matching.
- Multiplication and shift/add expressions can have different graphs yet agree
  on every input. Structural mismatch does not imply semantic mismatch.
- Renaming graph nodes and changing serialization order preserve results.
- A six-cycle and two disjoint triangles fool 1-WL. Even perfect tuple hashing
  does not make color refinement a complete isomorphism test.
- The execution fiber of 6*x + 4 == 22 (mod 256) is {3, 131}. Adding
  x < 128 leaves {3}.
- Unsupported instructions, memory reads, calls, and branches are rejected.

The matching candidate formulas form an observational equivalence class over
this entire finite domain. They are not claimed to compile to identical bytes.
The calculated execution fiber is a preimage of a state/output transformation,
not a fiber of the source-to-binary compilation map.

## Relation to Ghidra

The initial prototype uses objdump. The native workflow uses SLEIGH. Ghidra already has a related
foundation in Ghidra/Features/Decompiler/src/decompile/cpp/signature.hh:
SignatureEntry iteratively hashes neighboring data-flow information, while
BlockSignatureEntry does so for control flow. This experiment is not evidence
that graph-based binary similarity is a new technique.

The native workflow preserves widths, operand roles, branch guards, memory effects,
and calling-convention assumptions. Use coloring to suggest matches; establish
behavior with constraints or proofs.
Neither color refinement nor source selection from a candidate list can recover
information that compilation discarded.

Reference: Shervashidze et al., [Weisfeiler-Lehman Graph Kernels (2011)](https://www.jmlr.org/papers/v12/shervashidze11a.html).
