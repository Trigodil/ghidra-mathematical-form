"""Compile real fixtures, lift their disassembly, and test graph/fiber claims."""

import argparse
import ctypes
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from graph_fibers import (Graph, color_refinement, dataflow_graph, expression,
                          lift_function)


FORMULAS = {
    "affine": "6*x + y + 4",
    "affine_shifts": "(x << 2) + (x << 1) + y + 4",
    "affine_wrong": "6*x + y + 5",
    "add": "x + y",
    "bitxor": "x ^ y",
    "subtract": "x - y",
    "subtract_swapped": "y - x",
}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def table(expr):
    return bytes(expr.evaluate(x, y) for x in range(256) for y in range(256))


def comparison(left, right, typed=True):
    return color_refinement([dataflow_graph(left, typed), dataflow_graph(right, typed)])


def first_difference(left, right):
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            x, y = divmod(index, 256)
            return {"x": x, "y": y, "left": a, "right": b}
    return None


def run(output):
    if platform.machine().lower() not in ("x86_64", "amd64") or sys.platform != "linux":
        raise RuntimeError("This first native experiment requires Linux x86-64 SysV")
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("fixtures.c")
    command = ["gcc", "-O2", "-shared", "-fPIC", "-fcf-protection=none", str(source)]
    with tempfile.TemporaryDirectory(prefix="graph-fibers-") as build:
        binary = Path(build) / "fixtures.so"
        subprocess.run(command + ["-o", str(binary)], check=True, capture_output=True, text=True)
        disassembly = subprocess.check_output(
            ["objdump", "-d", "-Mintel", "--no-show-raw-insn", str(binary)], text=True)
        library = ctypes.CDLL(str(binary))
        lifted = {name: lift_function(disassembly, name) for name in FORMULAS}
        tables = {}
        for name, formula in FORMULAS.items():
            function = getattr(library, name)
            function.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
            function.restype = ctypes.c_uint8
            native = bytes(function(x, y) for x in range(256) for y in range(256))
            tables[name] = table(lifted[name])
            check(native == tables[name], f"Lifter disagrees with native execution: {name}")
            check(native == table(expression(formula)), f"Formula disagrees with binary: {name}")

        findings = {}
        findings["compiler_collapsed_source_variants"] = comparison(
            lifted["affine"], lifted["affine_shifts"])
        check(findings["compiler_collapsed_source_variants"]["indistinguishable"],
              "Fixture expectation changed: compiler did not produce matching arithmetic DAGs")

        findings["add_vs_xor_topology_only"] = comparison(lifted["add"], lifted["bitxor"], False)
        findings["add_vs_xor_typed"] = comparison(lifted["add"], lifted["bitxor"])
        findings["add_vs_xor_counterexample"] = first_difference(tables["add"], tables["bitxor"])
        check(findings["add_vs_xor_topology_only"]["indistinguishable"], "Expected same topology")
        check(not findings["add_vs_xor_typed"]["indistinguishable"], "Opcode labels were lost")
        check(findings["add_vs_xor_counterexample"] is not None, "Expected semantic difference")

        findings["changed_constant_typed"] = comparison(lifted["affine"], lifted["affine_wrong"])
        findings["swapped_subtraction_typed"] = comparison(
            lifted["subtract"], lifted["subtract_swapped"])
        check(not findings["changed_constant_typed"]["indistinguishable"], "Constant label was lost")
        check(not findings["swapped_subtraction_typed"]["indistinguishable"], "Operand slots were lost")

        direct = expression(FORMULAS["affine"])
        shifted = expression(FORMULAS["affine_shifts"])
        findings["different_graphs_same_behavior"] = {
            "color_refinement": comparison(direct, shifted),
            "exhaustively_equivalent": table(direct) == table(shifted),
        }
        check(not findings["different_graphs_same_behavior"]["color_refinement"]["indistinguishable"],
              "Expected different source-expression DAGs")
        check(findings["different_graphs_same_behavior"]["exhaustively_equivalent"],
              "Expected arithmetic identity modulo 256")

        # Node-ID and serialization order must not affect coloring.
        graph = dataflow_graph(lifted["affine"])
        rename = {node: f"renamed-{100-node}" for node in graph.labels}
        renamed = Graph({rename[n]: v for n, v in reversed(list(graph.labels.items()))},
                        [(rename[a], rename[b], slot) for a, b, slot in reversed(graph.edges)])
        findings["node_renaming_invariant"] = color_refinement([graph, renamed])
        check(findings["node_renaming_invariant"]["indistinguishable"], "Node IDs leaked into colors")

        # Classical 1-WL limitation: C6 and two disjoint triangles have identical
        # stable color counts, despite different connected-component counts.
        def undirected(pairs):
            return Graph({n: ("vertex",) for n in range(6)},
                         [(a, b, "*") for u, v in pairs for a, b in ((u, v), (v, u))])

        cycle = undirected([(n, (n + 1) % 6) for n in range(6)])
        triangles = undirected([(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3)])
        findings["nonisomorphic_graphs_1wl_cannot_distinguish"] = color_refinement([cycle, triangles])
        check(findings["nonisomorphic_graphs_1wl_cannot_distinguish"]["indistinguishable"],
              "Expected the known 1-WL counterexample")

        # These are observational candidate classes, NOT compilation-map fibers.
        candidates = list(FORMULAS.values()) + ["y + 4 + x*6"]
        findings["candidate_formulas_matching_affine_on_entire_u8_domain"] = [
            candidate for candidate in candidates if table(expression(candidate)) == tables["affine"]]
        fiber = [x for x in range(256) if tables["affine"][x*256] == 22]
        findings["execution_fiber"] = {
            "observation": "affine(x, 0) == 22", "candidates": fiber,
            "with_x_less_than_128": [x for x in fiber if x < 128],
        }
        check(fiber == [3, 131], "Incorrect execution fiber")

        # Reject unsupported semantics rather than silently generating a graph.
        rejected = []
        for instruction in ("jne 1000", "call 2000", "mov eax,DWORD PTR [rdi]",
                            "shr eax,1", "mov eax,ah"):
            fake = f"00000000 <bad>:\n 0: {instruction}\n 1: ret\n"
            try:
                lift_function(fake, "bad")
            except ValueError:
                rejected.append(instruction)
            else:
                raise AssertionError(f"Unsupported instruction accepted: {instruction}")

        report = {
            "scope": "Seven compiled u8(u8,u8) functions; observed return byte only",
            "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
            "compiler_flags": command[1:-1],
            "native_inputs_per_function": 65536,
            "native_vs_lifted_checks": 65536 * len(FORMULAS),
            "unsupported_examples_rejected": rejected,
            "findings": findings,
            "limitations": ["No Ghidra/p-code integration yet", "No memory, branches, loops, or calls",
                            "Color agreement is not an equivalence proof",
                            "Exhaustive equivalence applies only to this complete u8 input/output model",
                            "Compiler graph-shape expectation may change with GCC version"],
        }
        # Keep native code and full disassembly for inspection; built from our own fixtures only.
        (output / "fixtures.so").write_bytes(binary.read_bytes())
        (output / "disassembly.txt").write_text(disassembly)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("output"))
    run(parser.parse_args().output.resolve())
