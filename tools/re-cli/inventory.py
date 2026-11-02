"""Restricted ELF inventory worker. Input is data and is never executed."""
import ctypes
import json
import mmap
import os
from pathlib import Path
import struct
import sys


def inventory(path):
    with open(path, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        def unpack(fmt, offset):
            if offset < 0 or offset + struct.calcsize(fmt) > len(data):
                raise ValueError('Truncated ELF record')
            return struct.unpack_from(fmt, data, offset)

        def span(offset, size):
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError('ELF range outside file')
            return data[offset:offset + size]

        h = unpack('<16sHHIQQQIHHHHHH', 0)
        if h[0][:6] != b'\x7fELF\x02\x01' or h[2] != 62 or h[1] not in (2, 3):
            raise ValueError('Backend requires little-endian x86-64 ELF executable/shared object')
        if h[9] != 56 or h[11] != 64 or not h[12] or h[10] == 65535:
            raise ValueError('Unsupported ELF header tables (including extended/absent tables)')
        span(h[5], h[9] * h[10])
        span(h[6], h[11] * h[12])
        sections = [unpack('<IIQQQQIIQQ', h[6] + 64 * i) for i in range(h[12])]
        if h[13] >= len(sections):
            raise ValueError('Invalid section-name table')
        strings = sections[h[13]]
        names = span(strings[4], strings[5])
        bun = False
        segments = []
        for i in range(h[10]):
            p = unpack('<IIQQQQQQ', h[5] + 56 * i)
            if p[0] == 1 and p[1] & 1:
                span(p[2], p[5])
                segments.append((p[3], p[3] + p[5]))
        symbols = {}
        ambiguous = set()
        for s in sections:
            if s[0] >= len(names):
                raise ValueError('Invalid section name')
            bun |= names[s[0]:].split(b'\0', 1)[0] == b'.bun'
            if s[1] not in (2, 11):
                continue
            if s[9] != 24 or s[5] % 24 or s[6] >= len(sections):
                raise ValueError('Invalid symbol table')
            span(s[4], s[5])
            strings = sections[s[6]]
            text = span(strings[4], strings[5])
            for off in range(s[4], s[4] + s[5], 24):
                n, info, _, index, address, size = unpack('<IBBHQQ', off)
                if info & 15 != 2 or not index or not size:
                    continue
                if n >= len(text) or text.find(b'\0', n) < 0:
                    raise ValueError('Invalid symbol name')
                name = text[n:text.index(b'\0', n)].decode('utf-8', errors='surrogateescape')
                if not name:
                    continue
                item = (address, size)
                if name in symbols and symbols[name] != item:
                    ambiguous.add(name)
                symbols[name] = item
        # Match the backend's selection: unambiguous names, sorted by address/name,
        # one decompilation per address, including explicit failures for bad ranges.
        rows = sorted((address, name, size) for name, (address, size) in symbols.items()
                      if name not in ambiguous)
        seen, functions, covered = set(), [], []
        for address, name, size in rows:
            if address in seen:
                continue
            seen.add(address)
            valid = any(a <= address and address + size <= b for a, b in segments)
            functions.append(dict(address=address, name=name, size=size, file_backed_code=valid))
            if valid:
                covered.append((address, address + size))
        def union_bytes(ranges):
            end, total = -1, 0
            for left, right in sorted(ranges):
                total += max(0, right - max(left, end))
                end = max(end, right)
            return total
        return dict(functions=functions, bun=bun, executable_bytes=union_bytes(segments),
                    named_code_bytes=union_bytes(covered), ambiguous_names=sorted(ambiguous))


if __name__ == '__main__':
    source, destination, lockdown = map(Path, sys.argv[1:])
    lock = ctypes.CDLL(str(lockdown))
    lock.analysis_lockdown.argtypes = [ctypes.c_char_p] * 3
    lock.analysis_lockdown(os.fsencode(source), b'', os.fsencode(destination))
    try:
        result = inventory(source)
        (destination / 'inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
