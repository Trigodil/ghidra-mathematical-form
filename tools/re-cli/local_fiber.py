"""Local fiber check: one translation unit against fixed boundary conditions.

Each candidate source is compiled with `-c` under each compiler profile and
every target function is compared byte for byte with the target ELF, with
relocated fields masked on both sides. A spent budget never means that no
source exists; it only bounds the searched candidates and profiles.

Masking method: the object's own .rela.text entries give the candidate fields.
The linked target has no such entries for direct calls, so its fields come from
objdump: rel8/rel32 branches and rip-relative operands whose destination lies
outside the function, with the field located by matching the displacement
bytes. The union of both masks is zeroed on both sides before comparing.
"""

import argparse
import difflib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from elf_image import Elf
import full_recovery
import source_project

OBJDUMP = "/usr/bin/objdump"
COMPILERS = ("gcc", "g++", "clang", "clang++")
STD_FLAG = re.compile(
    r"-std=(?:c(?:89|99|11|17|2x|23)|gnu(?:89|99|11|17|2x|23)|(?:gnu\+\+|c\+\+)(?:11|14|17|20|23))"
)
EXTRA_FLAG = re.compile(
    r"-D[A-Za-z_][A-Za-z_0-9]*(?:=[^\0]*)?|-U[A-Za-z_][A-Za-z_0-9]*"
    r"|-I[^\0-][^\0]*|-W[a-z][a-z0-9=+-]*|-Wa,--noexecstack"
)
DEFAULT_PROFILES = [
    dict(compiler="gcc", flags=["-O2"]),
    dict(compiler="gcc", flags=["-O3"]),
]
# GOTPCRELX and REX_GOTPCRELX let the linker rewrite the opcode before the field.
RELAXABLE = {41, 42}
INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$")
BLOCK_HEADER = re.compile(r"^[0-9a-f]+ <(.+)>:$")
RIP_COMMENT = re.compile(r"#\s*([0-9a-f]+)\b")
BRANCH_TARGET = re.compile(r"^([0-9a-f]+)\b")


def disassemble(path, name):
    """Parse objdump output for one symbol into (address, bytes, text) rows."""
    result = subprocess.run(
        [OBJDUMP, "-d", "-w", f"--disassemble={name}", str(path)],
        capture_output=True, text=True, check=True,
    )
    rows, wanted = [], False
    for line in result.stdout.splitlines():
        header = BLOCK_HEADER.match(line)
        if header:
            wanted = header[1] == name
            continue
        match = INSN_LINE.match(line)
        if wanted and match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()))
    return rows


def target_fields(rows, function):
    """Fields (offset, width) in a linked function that refer outside of it."""
    start, end = function["address"], function["address"] + function["size"]
    fields = []
    for address, raw, text in rows:
        if not start <= address < end:
            continue
        following = address + len(raw)
        mnemonic = text.split()[0] if text else ""
        operand = text[len(mnemonic):].strip()
        branch = BRANCH_TARGET.match(operand) if re.match(r"(?:j|call|loop|xbegin)", mnemonic) else None
        comment = RIP_COMMENT.search(text)
        destination = int(branch[1], 16) if branch else int(comment[1], 16) if comment else None
        if destination is None or start <= destination < end:
            continue
        for width in ((4, 1) if branch else (4,)):
            expected = (destination - following).to_bytes(8, "little", signed=True)[:width]
            at = raw.rfind(expected) if branch else raw.find(expected, 1)
            if at >= 0:
                fields.append((address - start + at, width))
                break
    return fields


def mask_bytes(raw, spans):
    data = bytearray(raw)
    for offset, width in spans:
        data[offset:offset + width] = bytes(len(data[offset:offset + width]))
    return bytes(data)


def mnemonics(rows, function):
    start, end = function["address"], function["address"] + function["size"]
    return [text.split()[0] for address, _, text in rows if start <= address < end and text]


def compare_function(target, candidate, name, target_path, candidate_path):
    """Compare one function; the best of several same-named target symbols wins."""
    if name not in target.functions:
        return dict(function=name, status="missing_in_target", match=False)
    if name not in candidate.functions:
        return dict(
            function=name, status="missing_in_candidate", match=False,
            target_size=target.functions[name][0]["size"], candidate_size=None,
            note="not emitted by the candidate; may be inlined away or absent",
        )
    best = None
    for tfn in target.functions[name]:
        cfn = candidate.functions[name][0]
        tbytes, cbytes = target.code(tfn), candidate.code(cfn)
        spans = set(target_fields(disassemble(target_path, name), tfn))
        reloc_spans = set()
        for offset, width, kind in candidate.relocations(cfn):
            reloc_spans.add((offset, width))
            if kind in RELAXABLE and offset >= 2:
                spans.add((offset - 2, 2))
        spans |= reloc_spans
        tmasked, cmasked = mask_bytes(tbytes, spans), mask_bytes(cbytes, spans)
        common = min(len(tmasked), len(cmasked))
        first = next((i for i in range(common) if tmasked[i] != cmasked[i]), None)
        if first is None and len(tmasked) != len(cmasked):
            first = common
        tmn = mnemonics(disassemble(target_path, name), tfn)
        cmn = mnemonics(disassemble(candidate_path, name), cfn)
        row = dict(
            function=name,
            status="ok",
            match=first is None,
            target_size=len(tbytes),
            candidate_size=len(cbytes),
            first_difference_offset=first,
            masked_fields=len(spans),
            candidate_relocation_fields=len(reloc_spans),
            target_only_fields=len(spans - reloc_spans),
            byte_similarity=round(difflib.SequenceMatcher(None, tmasked, cmasked, autojunk=False).ratio(), 4),
            positional_match=round(sum(a == b for a, b in zip(tmasked, cmasked)) / max(len(tmasked), len(cmasked)), 4),
            mnemonic_similarity=round(difflib.SequenceMatcher(None, tmn, cmn, autojunk=False).ratio(), 4),
        )
        if best is None or (row["match"], row["byte_similarity"]) > (best["match"], best["byte_similarity"]):
            best = row
    return best


def validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) - {"compiler", "flags"}:
        raise ValueError("Invalid compiler profile")
    if profile.get("compiler") not in COMPILERS:
        raise ValueError("Use a supported system C/C++ compiler")
    flags = profile.get("flags", [])
    if not isinstance(flags, list) or any(
        not isinstance(flag, str)
        or not (flag in full_recovery.FLAGS or STD_FLAG.fullmatch(flag) or EXTRA_FLAG.fullmatch(flag))
        or flag in ("-shared", "-static", "-pie", "-nostdlib", "-s")
        for flag in flags
    ):
        raise ValueError("Unsupported compiler flags; plugins and link options are not allowed")
    return profile


def compile_object(profile, source, output, timeout=120):
    """Run `compiler flags -c source -o output` without a shell."""
    command = [str(Path("/usr/bin") / profile["compiler"]), *profile.get("flags", []),
               "-c", "-o", str(output), str(source)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "compile timed out"
    errors = [line for line in result.stderr.splitlines() if " error:" in line]
    return result.returncode == 0, "\n".join(errors)[:2000]


def search(target_path, names, candidates, profiles, workdir, budget=None):
    """Try candidates times profiles in order; stop at the first full TU match."""
    for profile in profiles:
        validate_profile(profile)
    target = Elf(target_path)
    attempts, status, winner = [], "no_match_in_searched_space", None
    for candidate_name, source in candidates:
        for index, profile in enumerate(profiles):
            if budget is not None and len(attempts) >= budget:
                status = "budget_exhausted"
                break
            output = Path(workdir) / f"attempt{len(attempts)}.o"
            attempt = dict(candidate=candidate_name, source=str(source),
                           profile_index=index, profile=profile)
            ok, log = compile_object(profile, source, output)
            attempt["compiled"] = ok
            if ok:
                candidate = Elf(output)
                attempt["functions"] = [
                    compare_function(target, candidate, name, target_path, output) for name in names
                ]
                attempt["tu_match"] = all(row["match"] for row in attempt["functions"])
            else:
                attempt["compiler_log_tail"] = log
                attempt["tu_match"] = False
            attempts.append(attempt)
            if attempt["tu_match"]:
                status, winner = "tu_match", len(attempts) - 1
                break
        if status != "no_match_in_searched_space":
            break
    return dict(
        status=status,
        target=str(target_path),
        functions=list(names),
        attempts_made=len(attempts),
        budget=budget,
        winning_attempt=winner,
        note="Only the listed candidates and profiles were searched; this says nothing about other sources.",
        attempts=attempts,
    )


def pseudocode_candidate(binary_report, names, directory):
    """Write the assembled decompiler source for the named functions; return its path.

    Callees outside the set are boundary symbols: they get an unprototyped extern
    declaration, so their addresses stay masked relocations. Compile with gnu17.
    """
    rows = [row for row in binary_report.get("functions", []) if row["name"] in set(names)]
    spec, metadata = source_project.assemble(dict(binary_report, functions=rows))
    if spec is None:
        raise ValueError("No decompiled pseudocode found for the requested functions")
    program = spec["files"]["program.c"]
    outside = set(metadata["unresolved_callees"])
    boundary = sorted({
        match[0] for match in re.finditer(r"\b(?:func_0x|__recovered_)([0-9a-fA-F]{1,16})\b", program)
        if int(match[1], 16) in outside
    })
    prelude = "".join(f"extern void {name}();\n" for name in boundary)
    spec["files"]["program.c"] = program.replace('#include "recovered_support.h"\n', '#include "recovered_support.h"\n' + prelude, 1)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in spec["files"].items():
        (directory / name).write_text(text)
    return directory / "program.c", metadata


def pseudocode_search(binary_report, target_path, names, profiles, workdir):
    """Search the whole-TU pseudocode, then each function alone to isolate failures."""
    path, metadata = pseudocode_candidate(binary_report, names, Path(workdir) / "pseudo-tu")
    result = dict(
        whole_tu=search(target_path, names, [("pseudocode", path)], profiles, workdir),
        unresolved_callee_addresses=metadata["unresolved_callees"],
        per_function={},
    )
    for name in names:
        single, _ = pseudocode_candidate(binary_report, [name], Path(workdir) / f"pseudo-{name}")
        result["per_function"][name] = search(target_path, [name], [("pseudocode", single)], profiles, workdir)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare candidate TU sources with target ELF functions")
    parser.add_argument("--target", required=True, help="target ELF file")
    parser.add_argument("--function", action="append", required=True, dest="functions",
                        help="target function name (repeat for the whole TU)")
    parser.add_argument("--candidate", action="append", default=[], help="candidate C source (repeat)")
    parser.add_argument("--decompiled-report", help="re- report.json; adds the decompiler pseudocode as a candidate")
    parser.add_argument("--profiles-json", help="JSON list of {compiler, flags}; default gcc -O2 and -O3")
    parser.add_argument("--budget", type=int, help="maximum number of compile attempts")
    parser.add_argument("--output", help="write the JSON report here instead of stdout")
    args = parser.parse_args(argv)
    profiles = json.loads(Path(args.profiles_json).read_text()) if args.profiles_json else DEFAULT_PROFILES
    candidates = [(Path(path).name, Path(path)) for path in args.candidate]
    if not candidates and not args.decompiled_report:
        parser.error("give --candidate or --decompiled-report")
    with tempfile.TemporaryDirectory(prefix="local-fiber-") as workdir:
        report = search(args.target, args.functions, candidates, profiles, workdir, args.budget) if candidates else {}
        if args.decompiled_report:
            binaries = json.loads(Path(args.decompiled_report).read_text())["binaries"]
            binary = next(b for b in binaries if Path(b["path"]).resolve() == Path(args.target).resolve())
            report["pseudocode"] = pseudocode_search(binary, args.target, args.functions, profiles, workdir)
    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n")
    else:
        print(text)
    return 0 if report.get("status") == "tu_match" else 2


if __name__ == "__main__":
    sys.exit(main())
