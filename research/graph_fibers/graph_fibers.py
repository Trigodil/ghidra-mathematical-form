"""A restricted binary-to-graph experiment, not a general x86 or p-code lifter."""

import ast
from collections import Counter
from dataclasses import dataclass
import re


MASK = 255
COMMUTATIVE = {"add", "mul", "xor", "and", "or"}


@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple = ()
    value: object = None

    def evaluate(self, x, y):
        if self.op == "input":
            return (x, y)[self.value] & MASK
        if self.op == "const":
            return self.value
        a, b = (arg.evaluate(x, y) for arg in self.args)
        if self.op == "add":
            result = a + b
        elif self.op == "sub":
            result = a - b
        elif self.op == "mul":
            result = a * b
        elif self.op == "xor":
            result = a ^ b
        elif self.op == "and":
            result = a & b
        elif self.op == "or":
            result = a | b
        else:
            raise ValueError(f"Unsupported expression operation: {self.op}")
        return result & MASK


def const(value):
    return Expr("const", value=value & MASK)


def operation(op, a, b):
    # Only these identities are normalized; no claim of a canonical semantic form.
    if op == "mul" and b == const(1):
        return a
    if op == "add" and b == const(0):
        return a
    return Expr(op, (a, b))


def expression(text):
    """Parse a small candidate formula without executing Python source."""
    operators = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul",
                 ast.BitXor: "xor", ast.BitAnd: "and", ast.BitOr: "or"}

    def visit(node):
        if isinstance(node, ast.Name) and node.id in ("x", "y"):
            return Expr("input", value=("x", "y").index(node.id))
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return const(node.value)
        if isinstance(node, ast.BinOp) and type(node.op) in operators:
            return operation(operators[type(node.op)], visit(node.left), visit(node.right))
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.LShift)
                and isinstance(node.right, ast.Constant)
                and type(node.right.value) is int and 0 <= node.right.value < 8):
            return operation("mul", visit(node.left), const(1 << node.right.value))
        raise ValueError(f"Unsupported formula: {ast.dump(node)}")

    return visit(ast.parse(text, mode="eval").body)


@dataclass
class Graph:
    labels: dict
    edges: list  # Directed (source, target, operand_slot); repeated edges matter.


def dataflow_graph(root, typed=True):
    """Hash-cons a pure expression DAG; retain input roles and operand positions."""
    labels, edges, seen = {}, [], {}

    def visit(node):
        if node in seen:
            return seen[node]
        index = len(seen)
        seen[node] = index
        labels[index] = (node.op, 8, node.value) if typed else ("value", 8)
        for position, arg in enumerate(node.args):
            child = visit(arg)
            slot = "*" if node.op in COMMUTATIVE else str(position)
            edges.append((child, index, slot))
        return index

    result = visit(root)
    output = len(labels)
    labels[output] = ("return", 8)
    edges.append((result, output, "0"))
    return Graph(labels, edges)


def color_refinement(graphs):
    """Joint directed, edge-labeled 1-WL refinement using exact palette keys.

    Equal histograms mean indistinguishable by this test, not isomorphic or
    semantically equivalent. Joint interning makes colors comparable across graphs.
    """
    keys = {(i, node): label for i, graph in enumerate(graphs)
            for node, label in graph.labels.items()}

    def intern(signatures):
        palette = {key: color for color, key in
                   enumerate(sorted(set(signatures.values()), key=repr))}
        return {node: palette[key] for node, key in signatures.items()}

    colors = intern(keys)
    incoming = {node: [] for node in keys}
    outgoing = {node: [] for node in keys}
    for i, graph in enumerate(graphs):
        for source, target, slot in graph.edges:
            incoming[i, target].append((slot, (i, source)))
            outgoing[i, source].append((slot, (i, target)))
    rounds = 0
    while True:
        signatures = {
            node: (colors[node],
                   tuple(sorted((slot, colors[other]) for slot, other in incoming[node])),
                   tuple(sorted((slot, colors[other]) for slot, other in outgoing[node])))
            for node in keys
        }
        refined = intern(signatures)
        rounds += 1
        stable = len(set(refined.values())) == len(set(colors.values()))
        colors = refined
        if stable:
            break
    histograms = [Counter(colors[i, node] for node in graph.labels)
                  for i, graph in enumerate(graphs)]
    return {"indistinguishable": all(h == histograms[0] for h in histograms[1:]),
            "rounds": rounds}


ALIASES = {}
for family in ("a", "b", "c", "d"):
    for name in (f"r{family}x", f"e{family}x", f"{family}x", f"{family}l"):
        ALIASES[name] = f"r{family}x"
for family in ("si", "di"):
    for name in (f"r{family}", f"e{family}", family, f"{family}l"):
        ALIASES[name] = f"r{family}"
for number in range(8, 16):
    for suffix in ("", "d", "w", "b"):
        ALIASES[f"r{number}{suffix}"] = f"r{number}"


def lift_function(disassembly, name):
    """Lift only low-byte, register-only, straight-line integer arithmetic.

    Linux x86-64 SysV: x is in DIL, y in SIL, result in AL. Discarding
    upper bits is exact for the supported operations. No flags, loads, calls,
    branches, right shifts, division, or high-byte registers are supported.
    Unsupported instructions fail explicitly; the caller supplies the u8 ABI.
    """
    registers = {"rdi": Expr("input", value=0), "rsi": Expr("input", value=1)}

    def register(operand):
        if operand not in ALIASES:
            raise ValueError(f"Unsupported register: {operand}")
        return ALIASES[operand]

    def read(operand):
        if operand in ALIASES:
            key = register(operand)
            if key not in registers:
                raise ValueError(f"Read of unknown register: {operand}")
            return registers[key]
        return const(int(operand, 0))

    active = False
    for line in disassembly.splitlines():
        header = re.match(r"^\s*[0-9a-f]+ <([^>]+)>:$", line)
        if header:
            if active:
                break
            active = header[1] == name
            continue
        if not active:
            continue
        instruction = re.match(r"^\s*[0-9a-f]+:\s+(\w+)\s*(.*?)\s*$", line)
        if not instruction:
            if line.strip():
                raise ValueError(f"Unparsed instruction line: {line}")
            continue
        mnemonic, operands = instruction.groups()
        if mnemonic == "ret" and not operands:
            return read("al")
        # Padding after RET is never visited. No other instruction is skipped.
        parts = [part.strip() for part in operands.split(",")]
        if mnemonic == "lea" and len(parts) == 2:
            dest, address = parts
            address = address.removeprefix("[").removesuffix("]")
            # LEA is arithmetic, not a memory read. Support base+index*scale+disp.
            if not re.fullmatch(r"[a-z0-9*+\-]+", address):
                raise ValueError(f"Unsupported LEA: {operands}")
            terms = re.findall(r"[+-]?[^+-]+", address)
            total = None
            for term in terms:
                negative = term.startswith("-")
                term = term.lstrip("+-")
                if "*" in term:
                    base, scale = term.split("*")
                    if int(scale, 0) not in (1, 2, 4, 8):
                        raise ValueError(f"Unsupported LEA scale: {scale}")
                    value = operation("mul", read(base), const(int(scale, 0)))
                else:
                    value = read(term)
                if total is None:
                    total = operation("sub", const(0), value) if negative else value
                else:
                    total = operation("sub" if negative else "add", total, value)
            if total is None:
                raise ValueError("Empty LEA")
            registers[register(dest)] = total
        elif mnemonic in ("mov", "movzx", "movsx", "movsxd") and len(parts) == 2:
            registers[register(parts[0])] = read(parts[1])
        elif mnemonic in ("add", "sub", "xor", "and", "or") and len(parts) == 2:
            registers[register(parts[0])] = operation(mnemonic, read(parts[0]), read(parts[1]))
        elif mnemonic == "imul" and len(parts) in (2, 3):
            a, b = parts if len(parts) == 2 else parts[1:]
            registers[register(parts[0])] = operation("mul", read(a), read(b))
        else:
            raise ValueError(f"Unsupported instruction in {name}: {mnemonic} {operands}")
    raise ValueError(f"Function missing or lacks a supported RET: {name}")
