"""Code reached only by address constants (hand written asm, NOTYPE labels) as raw byte blobs.
A range is emitted only when objdump shows no rip relative operand, call, indirect jump or branch out.
"""
import re
import struct
import subprocess

OBJDUMP = '/usr/bin/objdump'
CODE_CAST = re.compile(r'\(code \*\)0x0*([0-9a-fA-F]{1,16})\b')
INSN = re.compile(r'^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$')
IDENT = re.compile(r'[A-Za-z_][A-Za-z_0-9]*')


def executable(image, address):
    section = image.section_at(address)
    return section if section and section['flags'] & 4 and section['type'] == 1 else None


def labels(image, functions_only=False):
    """Address to names of NOTYPE or size 0 FUNC symbols (only the FUNC ones if asked) in code."""
    found = {}
    for section in image.sections:
        if section['type'] != 2:
            continue
        strtab = image.sections[section['link']]
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            name, info, _, shndx, value, size = struct.unpack_from('<IBBHQQ', image.data, offset)
            if info & 0xF not in ((2,) if functions_only else (0, 2)) or size or not 0 < shndx < len(image.sections):
                continue
            text = image.string(strtab['offset'], name)
            if text and IDENT.fullmatch(text) and executable(image, value):
                found.setdefault(value, set()).add(text)
    return found


def check(binary, start, end):
    """Reason the range is not position independent, or None when it is."""
    result = subprocess.run([OBJDUMP, '-d', '-w', f'--start-address={start:#x}',
                             f'--stop-address={end:#x}', str(binary)],
                            capture_output=True, text=True)
    if result.returncode:
        return 'objdump failed'
    seen = 0
    for line in result.stdout.splitlines():
        match = INSN.match(line)
        if not match:
            continue
        address, text = int(match[1], 16), match[3]
        seen += len(match[2].split())
        mnemonic = text.split()[0] if text.split() else ''
        if '(bad)' in text or '%rip' in text:
            return f'rip relative or bad operand at {address:x}'
        if mnemonic.startswith(('call', 'syscall')) or ('*' in text and mnemonic.startswith('j')):
            return f'call or indirect jump at {address:x}'
        if mnemonic.startswith(('j', 'loop')):
            target = re.match(r'\S+\s+([0-9a-f]+)\b', text)
            if not target or not start <= int(target[1], 16) < end:
                return f'branch leaves range at {address:x}'
    return None if seen == end - start else 'decode does not cover the range'


def recover(image, source, functions, taken):
    """Return (blob source, declarations, {address: name}, metadata) for referenced ranges."""
    if image is None:
        return '', '', {}, {}
    sized = [(f['address'], f['address'] + f['size']) for rows in image.functions.values() for f in rows]
    starts = sorted({lo for lo, _ in sized} | {row['address'] for row in functions} |
                    set(labels(image, True)))
    names = labels(image)
    wanted = sorted({int(m[1], 16) for m in CODE_CAST.finditer(source)})
    regions, rejected = {}, {}
    for address in wanted:
        section = executable(image, address)
        if not section or address in starts or any(lo <= address < hi for lo, hi in sized):
            continue
        # A region never starts before the last known function entry or end below it.
        floor = max([hi for lo, hi in sized if hi <= address] + [s for s in starts if s < address] +
                    [section['addr']])
        start = min([a for a in names if floor <= a <= address and a not in starts] + [address])
        end = min([s for s in starts if s > address] + [section['addr'] + section['size']])
        regions.setdefault((start, end), set()).add(address)
    blobs, declarations, chosen, metadata = [], [], {}, dict(emitted=[], rejected=rejected)
    for (start, end), addresses in sorted(regions.items()):
        reason = check(image.path, start, end)
        if reason:
            rejected[f'{start:x}'] = reason
            continue
        points = {a for a in names if start <= a < end} | addresses
        local = {}
        for point in sorted(points):
            options = sorted(n for n in names.get(point, ()) if n not in taken)
            # Prefer the name without a leading underscore of an alias pair.
            options.sort(key=lambda n: n.startswith('_'))
            local[point] = options[0] if options else f'__code_{point:x}'
            taken.add(local[point])
        blobs.append(emit(start, image.read(start, end - start), local))
        for point, name in local.items():
            declarations.append(f'extern code {name} __attribute__((visibility("hidden")));')
            if point in addresses:
                chosen[point] = name
        metadata['emitted'].append(dict(start=f'{start:x}', end=f'{end:x}',
                                        labels={f'{p:x}': n for p, n in local.items()}))
    return '\n'.join(blobs), '\n'.join(declarations), chosen, metadata


def emit(start, data, local):
    """One top level asm statement with the bytes and a global hidden label at each entry."""
    lines = ['\t.pushsection .text', f'\t.p2align {min((start & -start).bit_length() - 1, 6)}']
    cuts = sorted({0, len(data), *(p - start for p in local)})
    for lo, hi in zip(cuts, cuts[1:]):
        name = local.get(start + lo)
        if name:
            lines += [f'\t.globl {name}', f'\t.hidden {name}', f'\t.type {name}, @function', f'{name}:']
        for offset in range(lo, hi, 16):
            lines.append('\t.byte ' + ','.join(f'{b:#x}' for b in data[offset:min(offset + 16, hi)]))
    lines.append('\t.popsection')
    body = ''.join(f'"{line}\\n"\n' for line in lines)
    return f'/* Raw code of the original at {start:#x}, reached only by address. */\n__asm__(\n{body});\n'


def rewrite(source, chosen):
    """Point (code *)0xADDR casts at the emitted labels."""
    def name(match):
        label = chosen.get(int(match[1], 16))
        return f'(code *){label}' if label else match[0]
    return CODE_CAST.sub(name, source)
