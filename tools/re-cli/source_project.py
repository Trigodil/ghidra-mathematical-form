"""Assemble decompiler output into a whole-program C candidate.

This is a proposal transform, not a semantic certificate. All original function
bodies remain; unresolved operations and missing definitions are reported rather
than replaced with stubs. Final acceptance requires a complete binary rebuild.
"""
from pathlib import Path
import re
import global_state

NONCODE = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
WORD = re.compile(r'\b[A-Za-z_][A-Za-z_0-9]*\b')
ADDRESS_CALL = re.compile(r'\b(?:func_0x|__recovered_)([0-9a-fA-F]{1,16})\s*\(')
WIDTHS = (1, 2, 4, 8, 16)


def code_mask(text):
    return NONCODE.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def call_addresses(text):
    return {int(m[1], 16) for m in ADDRESS_CALL.finditer(code_mask(text))}


def signature(text):
    """Recognize a simple C function declarator; leave other syntax unresolved."""
    masked = code_mask(text)
    brace = masked.find('{')
    if brace < 0:
        return None
    prefix = masked[:brace].strip()
    match = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9\s*]*?)\b([A-Za-z_][A-Za-z_0-9]*)\s*\(([^;{}]*)\)', prefix)
    if not match or '(' in match[3] or ')' in match[3]:
        return None
    return match[2], prefix


def ctype(width, signed=False):
    if not 1 <= width <= 16:
        raise ValueError('Unsupported machine word width')
    width = next(w for w in WIDTHS if w >= width)
    if width == 16:
        return '__int128' if signed else 'unsigned __int128'
    return f'{"int" if signed else "uint"}{width * 8}_t'


def word_mask(width):
    storage = next(w for w in WIDTHS if w >= width)
    t = ctype(width)
    return f'(({t})~({t})0 >> {(storage-width)*8})'


def pair_widths(suffix, concatenate=False):
    pairs = [(a, b) for a in range(1,17) for b in range(1,17) if f'{a}{b}' == suffix
             and ((a + b <= 16) if concatenate else b <= a)]
    return pairs[0] if len(pairs) == 1 else None


def helper(name):
    """Fixed-width integer p-code helpers; deliberately no memory/call stubs."""
    match = re.fullmatch(r'(CONCAT|SUB|SEXT|ZEXT)(\d+)', name)
    if match:
        operation, suffix = match.groups()
        if operation in ('SEXT', 'ZEXT'):
            pairs = [(a,b) for a in range(1,17) for b in range(1,17) if a <= b and f'{a}{b}' == suffix]
            if len(pairs) != 1:
                return None
            small, big = pairs[0]
            t = ctype(big)
            value = f'(({t})(x & {word_mask(small)}))'
            sign = f'(({t})1 << {small*8-1})'
            conversion = f'(({value} ^ {sign}) - {sign})' if operation == 'SEXT' else value
            return f'static inline {t} {name}({ctype(small)} x) {{ return ({t})({conversion}) & {word_mask(big)}; }}'
        pair = pair_widths(suffix, operation == 'CONCAT')
        if pair is None:
            return None
        a,b = pair
        if operation == 'CONCAT':
            return (f'static inline {ctype(a+b)} {name}({ctype(a)} hi, {ctype(b)} lo) '
                    f'{{ return (({ctype(a+b)})(hi & {word_mask(a)}) << {b*8}) | ({ctype(a+b)})(lo & {word_mask(b)}); }}')
        # SUBPIECE removes n low bytes. Out-of-range shifts yield zero, not C UB.
        return (f'static inline {ctype(b)} {name}({ctype(a)} x, unsigned n) '
                f'{{ return n >= {a} ? 0 : ({ctype(b)})((x & {word_mask(a)}) >> (8*n)) & {word_mask(b)}; }}')
    match = re.fullmatch(r'(CARRY|SCARRY|SBORROW)(1|2|4|8|16)', name)
    if match:
        operation, width = match[1], int(match[2])
        t = ctype(width)
        if operation == 'CARRY':
            expr = f'({t})(a+b) < a'
        elif operation == 'SCARRY':
            expr = f'((({t})~(a^b) & ({t})(a^({t})(a+b))) >> {width*8-1}) & 1'
        else:
            expr = f'((({t})(a^b) & ({t})(a^({t})(a-b))) >> {width*8-1}) & 1'
        return f'static inline bool {name}({t} a, {t} b) {{ return {expr}; }}'
    if name in ('POPCOUNT', 'LZCOUNT'):
        # sizeof retains the input's original word width; conversion alone would
        # sign-extend narrow negative operands and produce incorrect counts.
        if name == 'POPCOUNT':
            body = 'unsigned r=0; for(unsigned i=0;i<n;++i) r+=(unsigned)((x>>i)&1); return r;'
        else:
            body = 'unsigned r=0; for(unsigned i=n;i>0 && ((x>>(i-1))&1)==0;--i) ++r; return r;'
        return (f'static inline unsigned __recovery_{name}(unsigned __int128 x, unsigned n) {{ {body} }}\n'
                f'#define {name}(x) __recovery_{name}((unsigned __int128)(x), (unsigned)(sizeof(x)*8))')
    return None


def replace_identifiers(text, replacements):
    masked = code_mask(text)
    edits = [(m.start(), m.end(), replacements[m[0]]) for m in WORD.finditer(masked) if m[0] in replacements]
    for start, end, value in reversed(edits):
        text = text[:start] + value + text[end:]
    return text


def lower_storage(text):
    """Translate simple byte slices and integer-use byte arrays into C.

    Slice accesses retain object bytes through memcpy, avoiding unaligned or
    type-punning loads. Complex lvalues stay unresolved. Array retyping is an
    explicit proposal hypothesis, checked only by the whole-artifact verifier.
    """
    masked = code_mask(text)
    promoted = []
    edits = []
    declarations = list(re.finditer(r'\b(?:xunknown1|undefined1)\s+([A-Za-z_]\w*)\s*\[\s*(2|4|8|16)\s*\]\s*;', masked))
    array_names = {match[1] for match in declarations}
    integer_arrays = set()
    for multiply in re.finditer(r'\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\b', masked):
        if multiply[1] in array_names and multiply[2] in array_names:
            integer_arrays.update((multiply[1], multiply[2]))
    for match in declarations:
        name, width = match[1], int(match[2])
        # An array in a multiplication cannot be C pointer arithmetic. Preserve
        # plain buffers as arrays; only propose a word for these integer uses.
        if name in integer_arrays:
            edits.append((match.start(), match.end(), f'{ctype(width)} {name};'))
            promoted.append(dict(name=name, width=width))
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]

    used, unresolved = set(), []
    pattern = re.compile(r'\b([A-Za-z_]\w*)\._(\d+)_(\d+)_\b')

    def lower(fragment):
        mask = code_mask(fragment)
        pieces, cursor = [], 0
        for match in pattern.finditer(mask):
            if match.start() < cursor:
                continue
            name, offset, width = match[1], int(match[2]), int(match[3])
            if width not in WIDTHS or offset > 16 or offset + width > 16:
                unresolved.append(match[0])
                continue
            after = mask[match.end():].lstrip()
            before = mask[:match.start()].rstrip()
            write = after.startswith('=') and not after.startswith('==')
            if after.startswith(('++','--','+=','-=','*=','/=','%=', '&=', '|=', '^=', '<<=', '>>=')) or before.endswith(('++','--','&')):
                unresolved.append(match[0])
                continue
            end = match.end()
            if write:
                # Only a standalone assignment statement is rewritten.
                if before and before[-1] not in ';{}':
                    unresolved.append(match[0])
                    continue
                start = end + len(mask[end:]) - len(mask[end:].lstrip()) + 1
                depth = 0
                stop = None
                for position in range(start, len(mask)):
                    ch = mask[position]
                    if ch in '([{': depth += 1
                    elif ch in ')]}': depth -= 1
                    elif ch == ';' and depth == 0:
                        stop = position
                        break
                    if depth < 0:
                        break
                if stop is None:
                    unresolved.append(match[0])
                    continue
                value = lower(fragment[start:stop])
                replacement = f'__recovery_SET{width}({name}, {offset}, ({value}))'
                end = stop
            else:
                replacement = f'__recovery_GET{width}({name}, {offset})'
            used.add(width)
            pieces.extend([fragment[cursor:match.start()], replacement])
            cursor = end
        pieces.append(fragment[cursor:])
        return ''.join(pieces)

    lowered = lower(text)
    unresolved.extend(re.findall(r'\._\d+_\d+_\b', code_mask(lowered)))
    return lowered, used, dict(promoted_storage=promoted, unresolved_slices=sorted(set(unresolved)))


def slice_helpers(width):
    t = ctype(width)
    check = f'_Static_assert((off)+{width} <= sizeof(obj), "slice exceeds storage")'
    return (f'static inline {t} __recovery_read{width}(const void *p, unsigned off) {{ {t} v; '
            f'__builtin_memcpy(&v, (const unsigned char *)p+off, {width}); return v; }}\n'
            f'static inline void __recovery_write{width}(void *p, unsigned off, {t} v) {{ '
            f'__builtin_memcpy((unsigned char *)p+off, &v, {width}); }}\n'
            f'#define __recovery_GET{width}(obj, off) ({{ {check}; __recovery_read{width}(&(obj), (off)); }})\n'
            f'#define __recovery_SET{width}(obj, off, value) do {{ {check}; '
            f'__recovery_write{width}(&(obj), (off), (value)); }} while(0)')


def assemble(binary_report):
    base = Path(binary_report['output'])
    bodies, missing, definitions, prototypes = [], [], {}, []
    for row in binary_report.get('functions', []):
        path = base / 'functions' / f'{row["address"]:x}' / 'decompiled.c'
        if not path.is_file():
            missing.append(row['address'])
            continue
        text = path.read_text(errors='replace')
        parsed = signature(text)
        if parsed:
            name, declaration = parsed
            definitions[row['address']] = name
            prototypes.append(declaration + ';')
        bodies.append((row['address'], text))
    if not bodies:
        return None, dict(missing_functions=missing, function_count=0)
    # Address placeholders refer to the actual emitted definition, even when
    # its name comes from a native symbol rather than an invented function name.
    renames = {}
    calls = set()
    for _, text in bodies:
        masked = code_mask(text)
        calls.update(call_addresses(text))
        for word in WORD.findall(masked):
            match = re.fullmatch(r'(?:func_0x|__recovered_)([0-9a-fA-F]{1,16})', word)
            if match and int(match[1],16) in definitions:
                renames[word] = definitions[int(match[1],16)]
    transformed, slice_widths, storage = [], set(), []
    for address, text in bodies:
        lowered, used, detail = lower_storage(replace_identifiers(text, renames))
        transformed.append(lowered)
        slice_widths.update(used)
        if detail['promoted_storage'] or detail['unresolved_slices']:
            storage.append(dict(address=address, **detail))
    source = '\n'.join(transformed)
    tokens = set(WORD.findall(code_mask(source)))
    required = sorted(t for t in tokens if re.fullmatch(r'(?:CONCAT|SUB|SEXT|ZEXT|CARRY|SCARRY|SBORROW)\d+|POPCOUNT|LZCOUNT', t))
    implementations, unsupported = [], []
    for name in required:
        implementation = helper(name)
        if implementation:
            implementations.append(implementation)
        else:
            unsupported.append(name)
    aliases = ['#ifndef RECOVERED_SUPPORT_H', '#define RECOVERED_SUPPORT_H',
               '#include <stdint.h>', '#include <stdbool.h>',
               'typedef unsigned char byte;', 'typedef unsigned int uint;',
               'typedef unsigned long ulong;', 'typedef unsigned short ushort;',
               'typedef long long longlong;', 'typedef unsigned long long ulonglong;',
               'typedef float float4;', 'typedef double float8;',
               'typedef void code(void);', 'typedef uint8_t undefined;']
    for width in WIDTHS:
        aliases.extend([f'typedef {ctype(width, True)} int{width};',
                        f'typedef {ctype(width)} uint{width}, undefined{width}, xunknown{width};'])
    header = '\n'.join(aliases + implementations + [slice_helpers(w) for w in sorted(slice_widths)] + ['#endif', ''])
    globals_source, global_metadata = global_state.recover(base, binary_report.get('functions', []), definitions)
    # Avoid accepting implicit int-return declarations for cross-function calls.
    program = '#include "recovered_support.h"\n\n' + '\n'.join(prototypes) + '\n\n' + globals_source + '\n\n' + source
    metadata = dict(function_count=len(bodies), missing_functions=missing,
                    unresolved_callees=sorted(calls - set(definitions)),
                    helper_implementations=[name for name in required if name not in unsupported],
                    unsupported_helpers=unsupported,
                    unparsed_signatures=[address for address, _ in bodies if address not in definitions],
                    renamed_identifiers=renames, storage_lowering=storage,
                    slice_widths=sorted(slice_widths), global_state=global_metadata, semantic_equivalence_proved=False)
    spec = dict(origin='whole-program decompiler proposal with integer operation lowering',
                files={'program.c': program, 'recovered_support.h': header}, holes={},
                profiles=[dict(compiler='gcc', flags=['-O2'], sources=['program.c'])])
    return spec, metadata
