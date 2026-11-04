"""Restricted ELF inventory worker. Input is data and is never executed."""

import ctypes
import json
import mmap
import os
from pathlib import Path
import struct
import sys


def inventory(path):
    with open(path, "rb") as stream, mmap.mmap(
        stream.fileno(), 0, access=mmap.ACCESS_READ
    ) as data:

        def unpack(fmt, offset):
            if offset < 0 or offset + struct.calcsize(fmt) > len(data):
                raise ValueError("Truncated ELF record")
            return struct.unpack_from(fmt, data, offset)

        def span(offset, size):
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError("ELF range outside file")
            return data[offset : offset + size]

        h = unpack("<16sHHIQQQIHHHHHH", 0)
        if h[0][:6] != b"\x7fELF\x02\x01" or h[2] != 62 or h[1] not in (2, 3):
            raise ValueError(
                "Backend requires little-endian x86-64 ELF executable/shared object"
            )
        if h[9] != 56 or h[11] != 64 or not h[12] or h[10] == 65535:
            raise ValueError(
                "Unsupported ELF header tables (including extended/absent tables)"
            )
        span(h[5], h[9] * h[10])
        span(h[6], h[11] * h[12])
        sections = [unpack("<IIQQQQIIQQ", h[6] + 64 * i) for i in range(h[12])]
        if h[13] >= len(sections):
            raise ValueError("Invalid section-name table")
        strings = sections[h[13]]
        names = span(strings[4], strings[5])
        bun = False
        by_section_name = {}
        segments = []
        for i in range(h[10]):
            p = unpack("<IIQQQQQQ", h[5] + 56 * i)
            if p[0] == 1 and p[1] & 1:
                span(p[2], p[5])
                segments.append((p[3], p[3] + p[5]))
        symbols = {}
        ambiguous = set()
        for s in sections:
            if s[0] >= len(names):
                raise ValueError("Invalid section name")
            section_name = names[s[0] :].split(b"\0", 1)[0]
            bun |= section_name == b".bun"
            by_section_name[section_name] = s
            if s[1] not in (2, 11):
                continue
            if s[9] != 24 or s[5] % 24 or s[6] >= len(sections):
                raise ValueError("Invalid symbol table")
            span(s[4], s[5])
            strings = sections[s[6]]
            text = span(strings[4], strings[5])
            for off in range(s[4], s[4] + s[5], 24):
                n, info, _, index, address, size = unpack("<IBBHQQ", off)
                if info & 15 != 2 or not index or not size:
                    continue
                if n >= len(text) or text.find(b"\0", n) < 0:
                    raise ValueError("Invalid symbol name")
                name = text[n : text.index(b"\0", n)].decode(
                    "utf-8", errors="surrogateescape"
                )
                if not name:
                    continue
                item = (address, size)
                if name in symbols and symbols[name] != item:
                    ambiguous.add(name)
                symbols[name] = item
        # Match the backend's selection: unambiguous names, sorted by address/name,
        # one decompilation per address, including explicit failures for bad ranges.
        rows = sorted(
            (address, name, size)
            for name, (address, size) in symbols.items()
            if name not in ambiguous
        )
        seen, functions, covered = set(), [], []
        for address, name, size in rows:
            if address in seen:
                continue
            seen.add(address)
            valid = any(a <= address and address + size <= b for a, b in segments)
            functions.append(
                dict(
                    address=address,
                    name=name,
                    size=size,
                    file_backed_code=valid,
                    selector=name,
                    provenance=["symbol"],
                )
            )
            if valid:
                covered.append((address, address + size))
        # The ELF entry and unwind search table supply entry-point evidence even
        # when symbols are stripped.  Treat them as candidates, not proof of
        # source recovery or of a function's full extent.
        discovery_warnings = []
        candidates = {}

        def candidate(address, source):
            if any(left <= address < right for left, right in segments):
                candidates.setdefault(address, set()).add(source)

        candidate(h[4], "elf_entry")
        hdr = by_section_name.get(b".eh_frame_hdr")
        frame = by_section_name.get(b".eh_frame")
        if hdr is not None and frame is not None:
            try:
                start, end, base = hdr[4], hdr[4] + hdr[5], hdr[3]
                span(start, hdr[5])
                span(frame[4], frame[5])

                def read_num(pos, encoding, limit, virtual_base, data_base):
                    if encoding == 0xFF or encoding & 0x80:
                        raise ValueError("unsupported omitted/indirect unwind encoding")
                    form = encoding & 0x0F
                    formats = {
                        0: "Q",
                        2: "H",
                        3: "I",
                        4: "Q",
                        10: "h",
                        11: "i",
                        12: "q",
                    }
                    if form in formats:
                        fmt = "<" + formats[form]
                        width = struct.calcsize(fmt)
                        if pos + width > limit:
                            raise ValueError("truncated unwind value")
                        val = unpack(fmt, pos)[0]
                        newpos = pos + width
                    elif form in (1, 9):
                        val = 0
                        shift = 0
                        newpos = pos
                        for _ in range(10):
                            if newpos >= limit:
                                raise ValueError("truncated unwind LEB")
                            byte = data[newpos]
                            newpos += 1
                            val |= (byte & 127) << shift
                            shift += 7
                            if not byte & 128:
                                break
                        else:
                            raise ValueError("oversized unwind LEB")
                        if form == 9 and byte & 64:
                            val -= 1 << shift
                    else:
                        raise ValueError("unsupported unwind value encoding")
                    mode = encoding & 0x70
                    if mode == 0x10:
                        val += virtual_base + (pos - start)
                    elif mode == 0x30:
                        val += data_base
                    elif mode != 0:
                        raise ValueError("unsupported unwind relative encoding")
                    return val, newpos

                if hdr[5] < 4 or data[start] != 1:
                    raise ValueError("unsupported unwind header")
                eh_enc, count_enc, table_enc = data[start + 1 : start + 4]
                pointer, pos = read_num(start + 4, eh_enc, end, base, base)
                if pointer != frame[3]:
                    raise ValueError("unwind header points outside .eh_frame")
                count, pos = read_num(pos, count_enc, end, base, base)
                if count < 0 or count > 2000000 or count > (end - pos) // 2:
                    raise ValueError("invalid unwind entry count")
                # Fixed-width encodings are the usual ELF search table; validate
                # the referenced FDE record and its CIE before accepting a row.
                cie_encodings = {}

                def fde_encoding(cie, fde):
                    if cie in cie_encodings:
                        return cie_encodings[cie]
                    cie_length = unpack("<I", cie)[0]
                    cie_end = cie + 4 + cie_length
                    if cie_length < 5 or cie_end > fde:
                        raise ValueError("invalid unwind CIE length")
                    version = data[cie + 8]
                    cursor = cie + 9
                    if version not in (1, 3, 4):
                        raise ValueError("unsupported unwind CIE version")
                    zero = data.find(b"\0", cursor, cie_end)
                    if zero < 0:
                        raise ValueError("unterminated unwind CIE augmentation")
                    aug = data[cursor:zero]
                    cursor = zero + 1
                    if version == 4:
                        if cursor + 2 > cie_end or data[cursor] != 8:
                            raise ValueError("unsupported unwind address size")
                        cursor += 2
                    _, cursor = read_num(
                        cursor, 1, cie_end, frame[3] + start - frame[4], frame[3]
                    )
                    _, cursor = read_num(
                        cursor, 9, cie_end, frame[3] + start - frame[4], frame[3]
                    )
                    _, cursor = (
                        read_num(
                            cursor,
                            1 if version != 1 else 2,
                            cie_end,
                            frame[3] + start - frame[4],
                            frame[3],
                        )
                        if version != 1
                        else (data[cursor], cursor + 1)
                    )
                    encoding = 0
                    if aug:
                        if not aug.startswith(b"z"):
                            raise ValueError("unsupported unwind CIE augmentation")
                        length, cursor = read_num(
                            cursor, 1, cie_end, frame[3] + start - frame[4], frame[3]
                        )
                        aug_end = cursor + length
                        if aug_end > cie_end:
                            raise ValueError("truncated unwind augmentation")
                        for ch in aug[1:]:
                            if ch in (ord("R"), ord("L")):
                                if cursor >= aug_end:
                                    raise ValueError("truncated unwind augmentation")
                                if ch == ord("R"):
                                    encoding = data[cursor]
                                cursor += 1
                            elif ch == ord("P"):
                                if cursor >= aug_end:
                                    raise ValueError("truncated unwind personality")
                                personality_enc = data[cursor]
                                cursor += 1
                                # An indirect personality pointer still occupies an encoded value.
                                _, cursor = read_num(
                                    cursor,
                                    personality_enc & 0x7F,
                                    aug_end,
                                    frame[3] + start - frame[4],
                                    frame[3],
                                )
                            elif ch != ord("S"):
                                raise ValueError("unsupported unwind augmentation")
                    cie_encodings[cie] = encoding
                    return encoding

                for _ in range(count):
                    address, pos = read_num(pos, table_enc, end, base, base)
                    fde_address, pos = read_num(pos, table_enc, end, base, base)
                    off = frame[4] + fde_address - frame[3]
                    if off < frame[4] or off + 8 > frame[4] + frame[5]:
                        raise ValueError("unwind table points outside .eh_frame")
                    length, cie_delta = unpack("<II", off)
                    if (
                        length < 4
                        or length == 0xFFFFFFFF
                        or off + 4 + length > frame[4] + frame[5]
                        or not cie_delta
                    ):
                        raise ValueError("invalid unwind FDE")
                    cie = off + 4 - cie_delta
                    if cie < frame[4] or cie + 8 > off or unpack("<I", cie + 4)[0] != 0:
                        raise ValueError("invalid unwind CIE reference")
                    enc = fde_encoding(cie, off)
                    actual, _ = read_num(
                        off + 8,
                        enc,
                        off + 4 + length,
                        frame[3] + start - frame[4],
                        frame[3],
                    )
                    if actual != address:
                        raise ValueError("unwind FDE entry does not match search table")
                    candidate(address, "eh_frame_hdr")
            except (ValueError, struct.error, IndexError) as error:
                discovery_warnings.append("Unwind discovery incomplete: " + str(error))
        rows_by_address = {row["address"]: row for row in functions}
        for address, provenance in sorted(candidates.items()):
            if address in rows_by_address:
                rows_by_address[address]["provenance"].extend(sorted(provenance))
            else:
                row = dict(
                    address=address,
                    name=f"sub_{address:x}",
                    size=0,
                    file_backed_code=True,
                    selector=f"@0x{address:x}",
                    provenance=sorted(provenance),
                )
                functions.append(row)
        functions.sort(key=lambda item: (item["address"], item["name"]))

        def union_bytes(ranges):
            end, total = -1, 0
            for left, right in sorted(ranges):
                total += max(0, right - max(left, end))
                end = max(end, right)
            return total

        return dict(
            functions=functions,
            bun=bun,
            has_relocations=any(s[1] in (4, 9, 19) and s[5] for s in sections),
            executable_bytes=union_bytes(segments),
            named_code_bytes=union_bytes(covered),
            ambiguous_names=sorted(ambiguous),
            discovery=dict(
                elf_entry=sum("elf_entry" in p for p in candidates.values()),
                eh_frame_hdr=sum("eh_frame_hdr" in p for p in candidates.values()),
                unnamed=sum(row["size"] == 0 for row in functions),
                warnings=discovery_warnings,
            ),
        )


if __name__ == "__main__":
    source, destination, lockdown = map(Path, sys.argv[1:])
    lock = ctypes.CDLL(str(lockdown))
    lock.analysis_lockdown.argtypes = [ctypes.c_char_p] * 3
    lock.analysis_lockdown(os.fsencode(source), b"", os.fsencode(destination))
    try:
        result = inventory(source)
        (destination / "inventory.json").write_text(json.dumps(result, indent=2) + "\n")
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
