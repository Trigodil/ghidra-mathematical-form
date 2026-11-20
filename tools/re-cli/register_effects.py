"""Return registers a callee never writes, so a caller may keep a value there across the call (ipa-ra).
Read from the objdump view; any unknown call, indirect branch or implicit writer counts as a write.
"""
import bisect
import re
from pathlib import Path

INSN = re.compile(r'^\s*([0-9a-f]+):\t(?:[0-9a-f]{2} )+\s*\t?(.*)$')
# Ghidra kills these at every call unless the callee proto says otherwise.
FAMILIES = {
    'RDX': re.compile(r'%(?:rdx|edx|dx|dl|dh)\b'),
    'XMM0': re.compile(r'%[xyz]mm0\b'),
}
IMPLICIT = {
    'RDX': re.compile(r'^(?:mul|imul|div|idiv)[bwlq]?$|^(?:cqto|cltd|cwtd|cqo|cdq|cwd|rdtscp?|rdpmc|rdmsr|'
                      r'cpuid|xgetbv|rdpkru)$'),
    'XMM0': re.compile(r'^v?pcmp[ei]strm$|^vzeroall$|^f?xrstor|^aes\w*kl$|^loadiwkey$'),
}
ANY = re.compile(r'^(?:syscall|sysenter|int|int3|ud2|xabort|xbegin|enclu)$')
# These write more than their last AT&T operand.
READ_ONLY = re.compile(r'^(?:cmp[bwlq]?|test[bwlq]?|bt[wlq]?|push[wq]?|v?u?comis[sd]|v?ptest)$')
MULTI = re.compile(r'^(?:lock\s+)?(?:xchg|xadd|cmpxchg|mulx|v?p?gather|vpscatter|vscatter)')


def written_operands(mnemonic, operands):
    """Operand text that the instruction may write: the last operand outside memory brackets."""
    bare = re.sub(r'\([^)]*\)', '', operands)
    if READ_ONLY.match(mnemonic):
        return ''
    if MULTI.match(mnemonic):
        return bare
    return bare.rsplit(',', 1)[-1]


def parse(path):
    rows = []
    try:
        lines = Path(path).read_text(errors='replace').splitlines()
    except OSError:
        return rows
    for line in lines:
        match = INSN.match(line)
        if match:
            rows.append((int(match[1], 16), match[2].strip()))
    rows.sort()
    return rows


def kept(base, rows, imports=()):
    """Map function address to the sorted register names it never writes, itself or via callees."""
    listing = parse(Path(base) / 'assembly' / 'analysis.log')
    if not listing:
        return {}
    addresses = [a for a, _ in listing]
    starts = sorted({row['address'] for row in rows})
    sizes = {row['address']: row.get('size') or 0 for row in rows}
    every = set(FAMILIES)
    writes, edges = {}, {}
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else start + (sizes[start] or 1)
        if sizes[start]:
            end = min(end, start + sizes[start])
        own, out = set(), set()
        lo, hi = bisect.bisect_left(addresses, start), bisect.bisect_left(addresses, end)
        if lo == hi:
            own = set(every)
        for _, text in listing[lo:hi]:
            mnemonic = text.split()[0] if text else ''
            operands = text[len(mnemonic):].split('#')[0]
            if ANY.match(mnemonic) or '(bad)' in text:
                own = set(every)
                break
            written = written_operands(mnemonic, operands)
            for name, family in FAMILIES.items():
                if family.search(written) or IMPLICIT[name].match(mnemonic):
                    own.add(name)
            if mnemonic == 'notrack' and operands.split()[:1] == ['jmp']:
                continue	# gcc marks only switch jump tables notrack; targets stay inside
            if mnemonic.startswith(('call', 'j', 'loop')):
                target = re.match(r'\s*([0-9a-f]+)\b', operands)
                if '*' in operands or not target:
                    own = set(every)
                    break
                destination = int(target[1], 16)
                if mnemonic.startswith('call') or not start <= destination < end:
                    if destination in imports or destination not in sizes:
                        own = set(every)
                        break
                    out.add(destination)
        writes[start], edges[start] = own, out
    changed = True
    while changed:
        changed = False
        for start, out in edges.items():
            union = set(writes[start])
            for callee in out:
                union |= writes[callee]
            if union != writes[start]:
                writes[start] = union
                changed = True
    return {start: sorted(every - found) for start, found in writes.items() if every - found}


STORE_WIDTH = {'movups': 16, 'movaps': 16, 'movdqu': 16, 'movdqa': 16, 'movq': 8, 'movsd': 8, 'movss': 4,
               'movl': 4, 'movw': 2, 'movb': 1}
REGISTER_WIDTH = ((re.compile(r'^%r(?:[a-ds]x|[sd]i|[bs]p|\d+)$'), 8), (re.compile(r'^%(?:e[a-ds]x|e[sd]i|e[bs]p|r\d+d)$'), 4),
                  (re.compile(r'^%(?:[a-ds]x|[sd]i|r\d+w)$'), 2), (re.compile(r'^%(?:[a-d]l|[sd]il|r\d+b)$'), 1))


def outgoing_extents(base):
    """Map callee address to the stack argument block every direct caller writes from (%rsp) up, contiguously,
    just before the call (the smallest over its call sites)."""
    listing = parse(Path(base) / 'assembly' / 'analysis.log')
    extents = {}
    for index, (_, text) in enumerate(listing):
        call = re.match(r'call\s+([0-9a-f]+) <', text)
        if not call:
            continue
        spans = []
        for _, before in reversed(listing[max(0, index - 32):index]):
            mnemonic = before.split()[0] if before else ''
            # The block is relative to rsp at the call; any rsp change or control transfer ends it.
            if mnemonic.startswith(('call', 'j', 'ret', 'push', 'pop', 'rep')) or re.search(r',%rsp$', before):
                break
            store = re.match(r'(\w+)\s+(%\w+|\$\w+),(?:0x([0-9a-f]+))?\(%rsp\)$', before)
            if not store:
                continue
            width = STORE_WIDTH.get(store[1])
            if store[1] == 'mov':
                width = next((w for pattern, w in REGISTER_WIDTH if pattern.match(store[2])), None)
            if width:
                spans.append((int(store[3] or '0', 16), width))
        extent = 0
        for offset, width in sorted(spans):
            if offset > extent:
                break
            extent = max(extent, offset + width)
        target = int(call[1], 16)
        extents[target] = min(extents.get(target, extent), extent)
    return extents
