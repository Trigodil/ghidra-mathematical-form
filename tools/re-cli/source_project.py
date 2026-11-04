"""Assemble decompiler output into a whole-program C candidate.

This is a proposal transform, not a semantic certificate. All original function
bodies remain; unresolved operations and missing definitions are reported rather
than replaced with stubs. Final acceptance requires a complete binary rebuild.
"""
from pathlib import Path
import re
from elf_image import Elf
import global_state
import abi_evidence

NONCODE = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
WORD = re.compile(r'\b[A-Za-z_][A-Za-z_0-9]*\b')
ADDRESS_CALL = re.compile(r'\b(?:func_0x|__recovered_)([0-9a-fA-F]{1,16})\s*\(')
WIDTHS = (1, 2, 4, 8, 16)
ODD_TYPE = re.compile(r'unk(?:u?int|byte)\d+')
# Imports and p-code user operations have no body in the image; declare, never define.
# Variadic form keeps calls whose arguments the decompiler dropped well formed.
USEROPS = {
    'invalidInstructionException': 'extern code *invalidInstructionException(void);',
    **{name: f'extern void {name}(...);' for name in ('abort', 'exit', '__assert_fail', '__stack_chk_fail')},
}
# Return types of libc imports (names as in the backend's importSignatures). Arguments stay variadic
# because the decompiler already shaped each call site; only the result type
# must be right, or pointer results become integers.
IMPORT_RETURNS = {
    'void': 'free exit _exit abort perror qsort rewind srand __stack_chk_fail __assert_fail '
            '__cxa_finalize pthread_exit longjmp backtrace_symbols_fd',
    'int': 'printf __printf_chk fprintf __fprintf_chk sprintf __sprintf_chk snprintf __snprintf_chk '
           'scanf sscanf __isoc99_sscanf __isoc99_scanf puts putchar fputs fputc fgetc getc getchar '
           'ungetc fclose fflush fileno feof ferror fseek fseeko setvbuf open open64 close stat fstat '
           'lstat chmod chown fchmod fchown mkdir remove rename unlink rmdir isatty raise strcmp '
           'strncmp memcmp closedir atoi atexit backtrace clock_gettime setpriority utimensat '
           'munmap dup dup2 pipe kill fsync ftruncate access chdir sigaction usleep nanosleep '
           '__libc_start_main pthread_cond_broadcast pthread_cond_destroy pthread_cond_init '
           'pthread_cond_signal pthread_cond_wait pthread_create pthread_join pthread_mutex_destroy '
           'pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock pthread_mutex_trylock '
           'pthread_attr_init pthread_attr_destroy toupper tolower isalpha isdigit isspace',
    'long': 'ftell ftello clock time sysconf read write lseek pread pwrite readlink atol atoll '
            'strtol strtoll __isoc23_strtol __isoc23_strtoll labs llabs',
    'unsigned long': 'fread fwrite strlen strnlen strtoul strtoull __isoc23_strtoul __isoc23_strtoull '
              '__fread_chk strspn strcspn',
    'double': 'sqrt pow exp log sin cos floor ceil fabs strtod atof',
    'char *': 'strchr strrchr strstr strcpy strncpy strcat strncat strdup strerror strtok getenv '
              'fgets __fgets_chk getcwd realpath basename dirname',
    'void *': 'malloc calloc realloc memcpy __memcpy_chk memmove memset __memset_chk memchr '
              'mmap fopen fopen64 fdopen opendir readdir __errno_location __sysv_signal signal '
              'backtrace_symbols',
}
IMPORT_RETURN = {name: ctype for ctype, names in IMPORT_RETURNS.items() for name in names.split()}
# Defined by the hosted C start files (Scrt1.o, crti.o, crtbeginS.o, crtn.o), which
# the compiler driver links again; emitting them would define them twice.
PLT_SECTIONS = {'.plt', '.plt.sec', '.plt.got'}
GOT_CALL = re.compile(r'\(\*[A-Za-z_]*Ram([0-9a-fA-F]{16})\)')
TOOLCHAIN_RUNTIME = {
    '_start', '_init', '_fini', '_dl_relocate_static_pie', '__libc_csu_init',
    '__libc_csu_fini', 'deregister_tm_clones', 'register_tm_clones',
    '__do_global_dtors_aux', 'frame_dummy',
}
CLONE_NAME = re.compile(r'\b[A-Za-z_]\w*(?:\.(?:part|constprop|isra|cold|lto_priv|localalias|\d+))+(?!\w)')


def code_mask(text):
    return NONCODE.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def clone_identifiers(text):
    """Make compiler clone symbols such as f.part.0 valid C identifiers."""
    masked = code_mask(text)
    edits = [(m.start(), m.end(), m[0].replace('.', '_')) for m in CLONE_NAME.finditer(masked)]
    for start, end, value in reversed(edits):
        text = text[:start] + value + text[end:]
    return text


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


VECTOR_ELEMENT = r'(?:xunknown1|undefined1)'
HELPER_CALLEE = re.compile(r'(?:CONCAT|SUB|SEXT|ZEXT|CARRY|SCARRY|SBORROW)\d+|POPCOUNT|LZCOUNT')


def lower_vectors(text):
    """Lower the array type xunknown1 [16] to the word xunknown16 (unsigned __int128).

    Odd byte-array locals widen to the next word; locals passed to calls stay arrays.
    """
    masked = code_mask(text)
    edits = []
    pointers = set()
    for match in re.finditer(VECTOR_ELEMENT + r'\s*\(\s*\*(\s*\w*)\s*\)\s*\[\s*16\s*\]', masked):
        edits.append((match.start(), match.end(), 'xunknown16 *' + match[1].strip()))
        if match[1].strip():
            pointers.add(match[1].strip())
    for match in re.finditer(VECTOR_ELEMENT + r'\s+\[\s*16\s*\]', masked):
        edits.append((match.start(), match.end(), 'xunknown16'))

    def decays(name, source):
        for use in re.finditer(rf'\b{name}\b', source):
            before, after = source[:use.start()].rstrip(), source[use.end():].lstrip()
            if before[-1:] in '(,' and after[:1] in ',)':
                depth, index = 0, len(before) - 1
                while index >= 0:
                    depth += {')': 1, '(': -1}.get(before[index], 0)
                    if depth < 0:
                        break
                    index -= 1
                callee = re.search(r'(\w+)\s*$', before[:index])
                if callee and callee[1] not in ('if', 'while', 'switch', 'return') \
                        and not HELPER_CALLEE.fullmatch(callee[1]):
                    return True
        return False

    words = set(pointers)
    for match in re.finditer(VECTOR_ELEMENT + r'\s+([A-Za-z_]\w*)\s*\[\s*(3|5|6|7|9|1[0-6])\s*\]\s*;', masked):
        if not decays(match[1], masked[:match.start()] + masked[match.end():]):
            edits.append((match.start(), match.end(), f'{ctype(int(match[2]))} {match[1]};'))
            words.add(match[1])
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    # Byte indexing: p[k][i] and (*p)[i] on a pointer, w[i] on a word.
    for name in sorted(words):
        escaped = re.escape(name)
        if name in pointers:
            text = re.sub(rf'\(\s*\*\s*{escaped}\s*\)\s*\[', f'((xunknown1 *){name})[', text)
            text = re.sub(rf'\b{escaped}\s*\[([^\[\]]*)\]\s*\[', rf'((xunknown1 *)&{name}[\1])[', text)
        else:
            text = re.sub(rf'(?<![\w.&]){escaped}\s*\[', f'((xunknown1 *)&{name})[', text)
    return text, sorted(words)


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
            if not 1 <= width <= 16 or offset + width > 16:
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
                # Only an assignment that is a whole statement or comma operand is rewritten.
                # A braceless if, else, case label or do body also starts a statement.
                if before and not re.search(r'(?:[;{}:),]|\belse|\bdo)$', before):
                    unresolved.append(match[0])
                    continue
                start = end + len(mask[end:]) - len(mask[end:].lstrip()) + 1
                depth = 0
                stop = None
                for position in range(start, len(mask)):
                    ch = mask[position]
                    if depth == 0 and ch in ';,)':
                        stop = position
                        break
                    if ch in '([{': depth += 1
                    elif ch in ')]}': depth -= 1
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


def lower_odd_widths(text):
    """Lower proven-width loads, value casts and value locals, leaving other uses explicit.

    The backend is x86-64 little endian. A five-byte load must read exactly five
    bytes; substituting a uint64_t pointer would read three bytes too many. A cast
    or local of such a width is a value, held in the next larger machine word.
    """
    widths = set()
    load = re.compile(r'\*\s*\(\s*unkuint(\d+)\s*\*\s*\)\s*\(')
    cast = re.compile(r'\(\s*unk(u?int|byte)(\d+)\s*\)\s*')
    local = re.compile(r'\bunk(u?int|byte)(\d+)(\s+)([A-Za-z_]\w*\s*;)')

    def odd(width):
        return width not in WIDTHS and 1 <= width <= 16

    def lowered_pass(source):
        mask = code_mask(source)

        def close_paren(start):
            depth = 0
            for index in range(start, len(mask)):
                if mask[index] == '(':
                    depth += 1
                elif mask[index] == ')':
                    depth -= 1
                    if depth == 0:
                        return index
            return None

        def operand_end(start):
            """End of a parenthesized expression, a name, or a call of a name."""
            if mask[start:start + 1] == '(':
                end = close_paren(start)
                return None if end is None else end + 1
            name = re.compile(r'\*?\s*[A-Za-z_]\w*|\d\w*').match(mask, start)
            if name is None:
                return None
            end = name.end()
            if mask[end:end + 1] == '(':
                end = close_paren(end)
                return None if end is None else end + 1
            return end

        edits = []
        for match in load.finditer(mask):
            width = int(match[1])
            end = close_paren(match.end() - 1)
            if not odd(width) or end is None:
                continue
            before, tail = mask[:match.start()].rstrip(), mask[end + 1:].lstrip()
            # Only direct rvalues are supported: writes, address-taking and
            # parenthesized lvalues must retain their original representation.
            if before.endswith(('&', '++', '--')) or re.match(
                    r'(?:=(?!=)|\+\+|--|[+*/%&|^\-]=|<<=|>>=|\))', tail):
                continue
            edits.append((match.start(), end + 1, width,
                          f'__recovery_load{width}((const void *)(uintptr_t)'
                          f'({source[match.end():end]}))'))
        for match in cast.finditer(mask):
            width = int(match[2])
            end = operand_end(match.end())
            if not odd(width) or end is None or mask[end:].lstrip()[:1] in ('[', '.') or \
                    mask[end:].lstrip().startswith('->'):
                continue
            expression, signed = source[match.end():end], match[1] == 'int'
            if signed:
                shift = (next(w for w in WIDTHS if w >= width) - width) * 8
                value = (f'(({ctype(width, True)})(({ctype(width)})({expression}) << {shift}) >> {shift})')
            else:
                value = f'(({ctype(width)})({expression}) & {word_mask(width)})'
            edits.append((match.start(), end, width, value))
        edits.sort()
        kept, cursor = [], -1
        for start, end, width, value in edits:
            # Nested or overlapping matches wait for the next pass.
            if start >= cursor:
                kept.append((start, end, width, value))
                cursor = end
        for start, end, width, value in reversed(kept):
            source = source[:start] + value + source[end:]
            widths.add(width)
        return source, bool(kept)

    changed = True
    for _ in range(8):
        if not changed:
            break
        text, changed = lowered_pass(text)

    def declare(match):
        width = int(match[2])
        if not odd(width):
            return match[0]
        widths.add(width)
        return ctype(width, match[1] == 'int') + match[3] + match[4]
    return local.sub(declare, text), widths


def odd_width_helper(width):
    return (
        f'static inline {ctype(width)} __recovery_load{width}(const void *p) {{\n'
        f'    {ctype(width)} value = 0;\n'
        f'    __builtin_memcpy(&value, p, {width});\n'
        '    return value;\n'
        '}'
    )


def slice_helpers(width):
    t = ctype(width)
    check = f'_Static_assert((off)+{width} <= sizeof(obj), "slice exceeds storage")'
    return (f'static inline {t} __recovery_read{width}(const void *p, unsigned off) {{ {t} v = 0; '
            f'__builtin_memcpy(&v, (const unsigned char *)p+off, {width}); return v; }}\n'
            f'static inline void __recovery_write{width}(void *p, unsigned off, {t} v) {{ '
            f'__builtin_memcpy((unsigned char *)p+off, &v, {width}); }}\n'
            f'#define __recovery_GET{width}(obj, off) ({{ {check}; __recovery_read{width}(&(obj), (off)); }})\n'
            f'#define __recovery_SET{width}(obj, off, value) ({{ {check}; {t} __v = ({t})(value); '
            f'__recovery_write{width}(&(obj), (off), __v); __v; }})')


def link_boundary(binary_path):
    """Read what the linker supplies: PLT stub ranges, GOT imports, start files."""
    try:
        image = Elf(binary_path)
    except (OSError, TypeError, ValueError, IndexError):
        return [], {}, set()
    # Calls reach an import through its GOT slot or its PLT stub; key both by address.
    imports = {**image.imports(), **image.plt_stubs(PLT_SECTIONS)}
    hosted = '__libc_start_main' in imports.values() or '__libc_start_main' in image.functions
    return (image.section_ranges(PLT_SECTIONS), imports,
            TOOLCHAIN_RUNTIME if hosted else set())


def call_imports(text, imports):
    """Name imports called via a GOT slot, (*pcRam...3fd0)(x), or a PLT stub, __recovered_1050(x)."""
    used = set()

    def rename(match):
        name = imports.get(int(match[1], 16))
        if name is None:
            return match[0]
        used.add(name)
        return name

    text = GOT_CALL.sub(rename, text)
    return ADDRESS_CALL.sub(
        lambda m: rename(m) + '(' if int(m[1], 16) in imports else m[0], text), used


def assemble(binary_report):
    base = Path(binary_report['output'])
    bodies, missing, definitions, prototypes = [], [], {}, []
    stubs, imports, runtime = link_boundary(binary_report.get('path'))
    excluded, called_imports = [], set()
    for row in binary_report.get('functions', []):
        if row.get('name') in runtime or any(lo <= row['address'] < hi for lo, hi in stubs):
            excluded.append(row['name'])
            continue
        path = base / 'functions' / f'{row["address"]:x}' / 'decompiled.c'
        if not path.is_file():
            missing.append(row['address'])
            continue
        text, used = call_imports(clone_identifiers(path.read_text(errors='replace')), imports)
        called_imports.update(used)
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
    transformed, slice_widths, odd_widths, storage = [], set(), set(), []
    for address, text in bodies:
        lowered, vectors = lower_vectors(replace_identifiers(text, renames))
        lowered, used, detail = lower_storage(lowered)
        lowered, odd_used = lower_odd_widths(lowered)
        transformed.append(lowered)
        odd_widths.update(odd_used)
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
    # Imports are declared with their libc result type but no parameter list, which
    # the real header would otherwise constrain; the builtin mismatch is expected.
    aliases = ['#ifndef RECOVERED_SUPPORT_H', '#define RECOVERED_SUPPORT_H',
               '#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"',
               # Decompiled values are untyped words and pointers; GCC 14 made these errors.
               '#pragma GCC diagnostic warning "-Wint-conversion"',
               '#pragma GCC diagnostic warning "-Wincompatible-pointer-types"',
               '#include <stdint.h>', '#include <stdbool.h>',
               'typedef unsigned char byte;', 'typedef unsigned int uint;',
               'typedef unsigned long ulong;', 'typedef unsigned short ushort;',
               'typedef long long longlong;', 'typedef unsigned long long ulonglong;',
               'typedef float float4;', 'typedef double float8;',
               'typedef long code(...);', 'typedef uint8_t undefined;']
    for width in WIDTHS:
        aliases.extend([f'typedef {ctype(width, True)} int{width};',
                        f'typedef {ctype(width)} uint{width}, undefined{width}, xunknown{width};'])
    for name in sorted(t for t in tokens if ODD_TYPE.fullmatch(t)):
        width, signed = int(re.search(r'\d+', name)[0]), name.startswith('unkint')
        if width in WIDTHS:
            aliases.append(f'typedef {ctype(width, signed)} {name};')
        else:
            # Array typedefs let unresolved odd-width pointers and prototypes declare.
            aliases.append(f'typedef {"signed" if signed else "unsigned"} char {name}[{width}];')
    aliases.extend(USEROPS[t] for t in sorted(tokens & USEROPS.keys()))
    # Imports the decompiler already names are referenced too; none has a body here.
    called_imports |= (tokens & set(imports.values())) - set(definitions.values())
    aliases.extend(f'extern {IMPORT_RETURN.get(name, "long")} {name}(...);'
                   for name in sorted(called_imports - USEROPS.keys()))
    header = '\n'.join(aliases + implementations + [slice_helpers(w) for w in sorted(slice_widths)] + [odd_width_helper(w) for w in sorted(odd_widths)] + ['#endif', ''])
    globals_source, global_metadata = global_state.recover(base, binary_report.get('functions', []), definitions)
    # Local symbols such as __PRETTY_FUNCTION__.18 are renamed like the function clones.
    globals_source = clone_identifiers(globals_source)
    declared = [clone_identifiers(name) for name in
                global_metadata['exported_globals'] + global_metadata['external_globals']]
    missing_source, missing_names = global_state.declare_missing(code_mask(source), set(declared))
    global_metadata['name_declared_globals'] = missing_names
    globals_source = '\n'.join(filter(None, [globals_source, missing_source]))
    # Avoid accepting implicit int-return declarations for cross-function calls.
    program = '#include "recovered_support.h"\n\n' + '\n'.join(prototypes) + '\n\n' + globals_source + '\n\n' + source
    metadata = dict(function_count=len(bodies), missing_functions=missing,
                    toolchain_runtime_excluded=sorted(excluded),
                    imports_called=sorted(called_imports),
                    unresolved_callees=sorted(calls - set(definitions)),
                    helper_implementations=[name for name in required if name not in unsupported],
                    unsupported_helpers=unsupported,
                    unparsed_signatures=[address for address, _ in bodies if address not in definitions],
                    renamed_identifiers=renames, storage_lowering=storage,
                    slice_widths=sorted(slice_widths), odd_widths_lowered=sorted(odd_widths),
                    unresolved_odd_width_types=sorted(t for t in tokens if re.fullmatch(r'unk(?:u)?int\d+', t)),
                    global_state=global_metadata,
                    abi_evidence=abi_evidence.compare(base, binary_report.get('functions', [])),
                    semantic_equivalence_proved=False)
    spec = dict(origin='whole-program decompiler proposal with integer operation lowering',
                files={'program.c': program, 'recovered_support.h': header}, holes={},
                profiles=[dict(compiler='gcc', flags=['-O2'], sources=['program.c'])])
    return spec, metadata
