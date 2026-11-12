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
import machine_types

NONCODE = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
WORD = re.compile(r'\b[A-Za-z_][A-Za-z_0-9]*\b')
ADDRESS_CALL = re.compile(r'\b(?:func_0x|__recovered_)([0-9a-fA-F]{1,16})\s*\(')
WIDTHS = (1, 2, 4, 8, 16)
ODD_TYPE = re.compile(r'unk(?:u?int|byte)\d+')
# Imports and p-code user operations have no body in the image; declare, never define.
# Variadic form keeps calls whose arguments the decompiler dropped well formed.
USEROPS = {
    # UD2 raises SIGILL; the userop never returns a target.
    'invalidInstructionException': 'static inline code *invalidInstructionException(void) { __builtin_trap(); }',
    **{name: f'extern void {name}(...);' for name in ('abort', 'exit', '__assert_fail', '__stack_chk_fail')},
}
# SSE userops on xunknown16 with their instruction semantics; operand 1 is the destination register.
_LANES = ('static inline xunknown16 {name}(xunknown16 d, xunknown16 c) {{ uint16_t w[8]; uint64_t n = (uint64_t)c; '
          '__builtin_memcpy(w, &d, 16); for (int i = 0; i < 8; i++) w[i] = {body}; '
          'xunknown16 r; __builtin_memcpy(&r, w, 16); return r; }}')
SSE_OPS = {
    'pshuflw': 'static inline xunknown16 pshuflw(xunknown16 d, xunknown16 s, uint8_t m) { uint16_t w[8], r[8]; '
               '(void)d; __builtin_memcpy(w, &s, 16); __builtin_memcpy(r, w, 16); '
               'for (int i = 0; i < 4; i++) r[i] = w[(m >> (2 * i)) & 3]; xunknown16 v; __builtin_memcpy(&v, r, 16); return v; }',
    'psllw': _LANES.format(name='psllw', body='n > 15 ? 0 : (uint16_t)(w[i] << n)'),
    'psraw': _LANES.format(name='psraw', body='(uint16_t)((int16_t)w[i] >> (n > 15 ? 15 : n))'),
    'psubusb': 'static inline xunknown16 psubusb(xunknown16 a, xunknown16 b) { uint8_t x[16], y[16]; '
               '__builtin_memcpy(x, &a, 16); __builtin_memcpy(y, &b, 16); for (int i = 0; i < 16; i++) x[i] = x[i] > y[i] ? x[i] - y[i] : 0; '
               'xunknown16 r; __builtin_memcpy(&r, x, 16); return r; }',
}
# CPUID ops return the address of {eax, ebx, ecx, edx} for the requested leaf (sub-leaf 0).
for _name in ('cpuid_basic_info', 'cpuid_Extended_Feature_Enumeration_info'):
    SSE_OPS[_name] = (f'static inline unsigned long {_name}(unsigned int leaf) {{ static __thread unsigned int r[4]; '
                      '__asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(0)); '
                      'return (unsigned long)r; }')
USEROPS.update(SSE_OPS)
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
# Real parameters, variadic calls make gcc zero eax.
_P, _S = 'void *', 'unsigned long'
IMPORT_PARAMS = {
    'free': _P, 'malloc': _S, 'calloc': f'{_S}, {_S}', 'realloc': f'{_P}, {_S}',
    'memcpy': f'{_P}, const void *, {_S}', 'memmove': f'{_P}, const void *, {_S}',
    'memset': f'{_P}, int, {_S}', 'memcmp': f'const void *, const void *, {_S}',
    '__memcpy_chk': f'{_P}, const void *, {_S}, {_S}', '__memset_chk': f'{_P}, int, {_S}, {_S}',
    'strlen': 'const char *', 'strcmp': 'const char *, const char *',
    'strncmp': f'const char *, const char *, {_S}', 'strchr': 'const char *, int',
    'strrchr': 'const char *, int', 'strstr': 'const char *, const char *',
    'strcpy': 'char *, const char *', 'strdup': 'const char *', 'strerror': 'int',
    'getenv': 'const char *', '__isoc23_strtol': 'const char *, char **, int',
    'exit': 'int', 'abort': 'void', 'perror': 'const char *', 'raise': 'int',
    '__stack_chk_fail': 'void', '__assert_fail': 'const char *, const char *, unsigned int, const char *',
    '__errno_location': 'void', 'sysconf': 'int', 'clock': 'void', 'isatty': 'int',
    'close': 'int', 'fclose': _P, 'fflush': _P, 'fileno': _P, 'feof': _P, 'ferror': _P,
    'fopen': 'const char *, const char *', 'fdopen': 'int, const char *',
    'fread': f'{_P}, {_S}, {_S}, {_P}', 'fwrite': f'const void *, {_S}, {_S}, {_P}',
    '__fread_chk': f'{_P}, {_S}, {_S}, {_S}, {_P}', 'fseek': f'{_P}, long, int', 'ftell': _P,
    'fgets': f'char *, int, {_P}', '__fgets_chk': f'char *, {_S}, int, {_P}',
    'fputs': f'const char *, {_P}', 'fputc': f'int, {_P}', 'getc': _P,
    'setvbuf': f'{_P}, char *, int, {_S}', 'remove': 'const char *',
    'stat': f'const char *, {_P}', 'lstat': f'const char *, {_P}', 'fstat': f'int, {_P}',
    'chmod': 'const char *, unsigned int', 'fchmod': 'int, unsigned int',
    'chown': 'const char *, unsigned int, unsigned int', 'fchown': 'int, unsigned int, unsigned int',
    'mkdir': 'const char *, unsigned int', 'utimensat': f'int, const char *, {_P}, int',
    'opendir': 'const char *', 'readdir': _P, 'closedir': _P,
    'mmap': f'{_P}, {_S}, int, int, int, long', 'munmap': f'{_P}, {_S}',
    'clock_gettime': f'int, {_P}', 'setpriority': 'int, unsigned int, int',
    'qsort': f'{_P}, {_S}, {_S}, {_P}', 'backtrace': f'{_P}, int', 'backtrace_symbols': f'{_P}, int',
    '__sysv_signal': f'int, {_P}',
    **{n: _P for n in ('pthread_mutex_lock', 'pthread_mutex_unlock', 'pthread_mutex_destroy',
                       'pthread_cond_signal', 'pthread_cond_broadcast', 'pthread_cond_destroy')},
    'pthread_mutex_init': f'{_P}, const void *', 'pthread_cond_init': f'{_P}, const void *',
    'pthread_cond_wait': f'{_P}, {_P}', 'pthread_create': f'{_P}, const void *, {_P}, {_P}',
    'pthread_join': f'{_S}, void **',
}


def call_arities(name, text):
    counts = set()
    for m in re.finditer(rf'\b{re.escape(name)}\s*\(', text):
        depth, n, i, empty = 1, 1, m.end(), True
        while i < len(text) and depth:
            c = text[i]
            depth += (c in '([{') - (c in ')]}')
            n += c == ',' and depth == 1
            empty &= c.isspace() or (c == ')' and depth == 0)
            i += 1
        counts.add(0 if empty else n)
    return counts


def import_decl(name, text=''):
    # Variadic if a call site disagrees.
    params = IMPORT_PARAMS.get(name, '...')
    want = 0 if params == 'void' else params.count(',') + 1
    if params != '...' and call_arities(name, text) - {want}:
        params = '...'
    return f'extern {IMPORT_RETURN.get(name, "long")} {name}({params});'


USEROPS.update({name: import_decl(name) for name in ('abort', 'exit', '__assert_fail', '__stack_chk_fail')})
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
    # Vector types are words in the emitted definition, so the prototype must say the same.
    prefix = lower_vectors(masked[:brace].strip())[0]
    match = re.fullmatch(r'([A-Za-z_][A-Za-z_0-9\s*]*?)\b([A-Za-z_][A-Za-z_0-9]*)\s*\(([^;{}]*)\)', prefix)
    # Pointer-to-array parameters such as (*param_2) [144] are plain declarators.
    params = re.sub(r'\(\s*\*\s*\w+\s*\)\s*\[\s*\d+\s*\]', '', match[3]) if match else ''
    if not match or '(' in params or ')' in params:
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


def element_address(text, match, name):
    """Decay p[k] to its address unless it is the whole 16 byte value of an assignment or return."""
    before, after = text[:match.start()].rstrip(), text[match.end():].lstrip()
    if re.search(r'\*\s*\)$', before):
        return f'((xunknown1 *)&{name}[{match[1]}])'
    if re.match(r'=(?!=)', after) or re.search(r'(?<![=!<>+\-*/%&|^])=$|\breturn$', before):
        return match[0]
    return f'((xunknown1 *)&{name}[{match[1]}])'


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
            # A word cast to a pointer type can only mean the array's address.
            if re.search(r'\(\s*[A-Za-z_][\w\s]*\*[\s*]*\)$', before):
                return True
            if before[-1:] in '(,' and after[:1] in ',)':
                depth, index = 0, len(before) - 1
                while index >= 0:
                    depth += {')': 1, '(': -1}.get(before[index], 0)
                    if depth < 0:
                        break
                    index -= 1
                callee = re.search(r'(\w+)\s*$', before[:index])
                if callee and callee[1] not in ('if', 'while', 'switch', 'return') \
                        and callee[1] not in SSE_OPS and not HELPER_CALLEE.fullmatch(callee[1]):
                    return True
        return False

    words = set(pointers)
    buffers = []
    for match in re.finditer(VECTOR_ELEMENT + r'\s+([A-Za-z_]\w*)\s*\[\s*(3|5|6|7|9|1[0-6])\s*\]\s*;', masked):
        if not decays(match[1], masked[:match.start()] + masked[match.end():]):
            edits.append((match.start(), match.end(), f'{ctype(int(match[2]))} {match[1]};'))
            words.add(match[1])
        else:
            buffers.append(match)
    # A buffer that is also copied whole to or from a word keeps its address; the copy is explicit.
    for match in buffers:
        name = re.escape(match[1])
        zero = re.compile(r'\(\s*' + VECTOR_ELEMENT + r'\s*\[\s*(\d+)\s*\]\s*\)\s*0x0\s*')
        copies = [(m.start(), m.end(), f'__builtin_memset({match[1]}, 0, {zero.fullmatch(m[1])[1]});' if zero.fullmatch(m[1])
                   else f'__builtin_memcpy({match[1]}, &(__typeof__({m[1]})){{{m[1]}}}, sizeof({m[1]}));')
                  for m in re.finditer(rf'(?m)^[ \t]*{name}[ \t]*=(?!=)[ \t]*([^;{{}}]+);', masked)]
        copies += [(m.start(), m.end(), f'__builtin_memcpy(&({m[1]}), {match[1]}, sizeof({m[1]}));')
                   for m in re.finditer(rf'(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*{name};', masked)]
        if copies:
            # The word is 16 bytes, so the buffer must hold one whole.
            edits.append((match.start(), match.end(), f'xunknown1 {match[1]} [16];'))
            edits.extend(copies)
    for start, end, value in sorted(edits, reverse=True):
        text = text[:start] + value + text[end:]
    # Byte indexing: p[k][i] and (*p)[i] on a pointer, w[i] on a word.
    for name in sorted(words):
        escaped = re.escape(name)
        if name in pointers:
            text = re.sub(rf'\(\s*\*\s*{escaped}\s*\)\s*\[', f'((xunknown1 *){name})[', text)
            text = re.sub(rf'\b{escaped}\s*\[([^\[\]]*)\]\s*\[', rf'((xunknown1 *)&{name}[\1])[', text)
            # A bare *p is the array itself, which decays to the address p.
            text = re.sub(rf'(\*\s*\)\s*)\*\s*{escaped}\b(?!\s*[\[.])', rf'\1{name}', text)
            text = re.sub(rf'([(,]\s*)\*\s*{escaped}\b(?=\s*[+-])', rf'\1((xunknown1 *){name})', text)
            # An integer cast of *p is pointer arithmetic on the decayed address.
            text = re.sub(rf'(\(\s*u?int\d*\s*\)\s*)\*\s*{escaped}\b(?!\s*[\[.])', rf'\1((xunknown1 *){name})', text)
            # A bare element p[k] is an array that decays to the address of that element.
            text = re.sub(rf'(?<![\w.&]){escaped}\s*\[([^\[\]]*)\]', lambda m: element_address(text, m, name), text)
        else:
            text = re.sub(rf'(?<![\w.&]){escaped}\s*\[', f'((xunknown1 *)&{name})[', text)
    return text, sorted(words)


def statement_end(mask, start):
    """Index of the ; , or ) that ends the expression beginning at start, at depth zero."""
    depth = 0
    for position in range(start, len(mask)):
        ch = mask[position]
        if depth == 0 and ch in ';,)':
            return position
        if ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
    return None


STRUCT_CAST = re.compile(r'\(\s*(\w+_stackargs)\s*\)')


def cast_operand_end(mask, start):
    """End of the cast-expression that begins at start: unary operators, a primary and its postfix chain."""
    position = start
    while position < len(mask) and mask[position] in ' \t\n*&-!~':
        position += 1
    if position < len(mask) and mask[position] == '(':
        depth = 0
        while position < len(mask):
            depth += {'(': 1, ')': -1}.get(mask[position], 0)
            position += 1
            if depth == 0:
                break
    else:
        match = re.compile(r'[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+').match(mask, position)
        if not match:
            return None
        position = match.end()
    while position < len(mask):
        if mask[position] in '([':
            close = ')' if mask[position] == '(' else ']'
            depth = 0
            while position < len(mask):
                depth += {'(': 1, '[': 1, ')': -1, ']': -1}.get(mask[position], 0)
                position += 1
                if depth == 0:
                    break
        else:
            match = re.compile(r'(?:\.|->)\s*[A-Za-z_]\w*').match(mask, position)
            if not match:
                break
            position = match.end()
    return position


def lower_struct_casts(text):
    """A value cannot be cast to a struct type in C; copy its bytes into a zeroed temporary."""
    while True:
        mask = code_mask(text)
        for match in STRUCT_CAST.finditer(mask):
            end = cast_operand_end(mask, match.end())
            if end is None or end <= match.end():
                continue
            operand = text[match.end():end].strip()
            name = match[1]
            stars = operand.startswith('*') or re.fullmatch(r'[A-Za-z_][\w.>\[\]-]*', operand)
            holder = f'&({operand})' if stars else f'(__typeof__({operand}) []){{ {operand} }}'
            size = f'sizeof({operand})' if stars else f'sizeof(__typeof__({operand}))'
            replacement = (f'({{ {name} t__ = {{0}}; __builtin_memcpy(&t__, {holder}, '
                           f'{size} < sizeof t__ ? {size} : sizeof t__); t__; }})')
            text = text[:match.start()] + replacement + text[end:]
            break
        else:
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
    # The object is a whole postfix chain such as a.b, a->b or a[i].b.
    pattern = re.compile(r'(?<![\w.>])([A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\[\]]*\])*)\._(\d+)_(\d+)_\b')
    # Scalar locals a slice may overrun; those are widened below so the slice stays in storage.
    scalars = {}
    for m in re.finditer(r'^[ \t]*(?:(xunknown|uint|int|undefined)(\d+)|\w+[ \t]*\*)[ \t]*([A-Za-z_]\w*)[ \t]*;',
                         code_mask(text), re.M):
        scalars[m[3]] = int(m[2]) if m[2] else 8
    widened = {}

    def lower(fragment):
        mask = code_mask(fragment)
        pieces, cursor = [], 0
        for match in pattern.finditer(mask):
            if match.start() < cursor:
                continue
            name, offset, width = match[1], int(match[2]), int(match[3])
            if width > 16 and width <= 4096:
                # Pieces wider than a word are byte ranges of the object, copied or viewed in place.
                after = mask[match.end():].lstrip()
                before = mask[:match.start()].rstrip()
                if after.startswith('=') and not after.startswith('=='):
                    if before and not re.search(r'(?:[;{}:(),]|\belse|\bdo)$', before):
                        unresolved.append(match[0])
                        continue
                    start = match.end() + len(mask[match.end():]) - len(mask[match.end():].lstrip()) + 1
                    stop = statement_end(mask, start)
                    if stop is None:
                        unresolved.append(match[0])
                        continue
                    value = lower(fragment[start:stop]).strip()
                    source = f'&({value})' if value.startswith(('*', '(*')) else \
                        f'(__typeof__({value}) []){{ {value} }}'
                    replacement = f'__builtin_memcpy((char *)&{name} + {offset}, (const char *){source}, {width})'
                    end = stop
                else:
                    replacement = f'(*(xunknown1 (*)[{width}])((char *)&{name} + {offset}))'
                    end = match.end()
                pieces.extend([fragment[cursor:match.start()], replacement])
                cursor = end
                continue
            if not 1 <= width <= 16:
                unresolved.append(match[0])
                continue
            if offset + width > scalars.get(name, 1 << 30):
                widened[name] = max(widened.get(name, 0), offset + width)
                name += '__w'
            after = mask[match.end():].lstrip()
            before = mask[:match.start()].rstrip()
            write = after.startswith('=') and not after.startswith('==')
            if after.startswith(('++','--','+=','-=','*=','/=','%=', '&=', '|=', '^=', '<<=', '>>=')) or before.endswith(('++','--')) or re.search(r'(?<!&)&$', before) and not re.search(r'[\w)\]]\s*&$', before):
                unresolved.append(match[0])
                continue
            end = match.end()
            if write:
                # Only an assignment that is a whole statement or comma operand is rewritten.
                # A braceless if, else, case label or do body also starts a statement.
                if before and not re.search(r'(?:[;{}:(),]|\belse|\bdo)$', before):
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
    for name, size in widened.items():
        mask = code_mask(lowered)
        decl = re.compile(rf'^([ \t]*)((?:\w+)[ \t]*\*?)[ \t]*\b{name}\b[ \t]*;', re.M).search(mask)
        if decl is None:
            continue
        kind = lowered[decl.start(2):decl.end(2)].strip()
        pad = f'xunknown1 pad[{size - scalars[name]}]; ' if size > scalars[name] else ''
        scalar = re.sub(r'\s+', ' ', kind)
        lowered = (lowered[:decl.start()] + f'{decl[1]}struct {{ {scalar} value__; {pad}}} {name}__w;' +
                   lowered[decl.end():])
        mask = code_mask(lowered)
        mask = code_mask(lowered)
        pieces, cursor = [], 0
        for use in re.finditer(rf'(?<![\w.>]){name}\b', mask):
            pieces.extend([lowered[cursor:use.start()], f'{name}__w.value__'])
            cursor = use.end()
        lowered = ''.join(pieces) + lowered[cursor:]
    unresolved.extend(re.findall(r'\._\d+_\d+_\b', code_mask(lowered)))
    return lowered, used, dict(promoted_storage=promoted, unresolved_slices=sorted(set(unresolved)))


def initialize_tls_base(text):
    """The decompiler leaves the FS base, used for stack canary and TLS reads, uninitialized."""
    return re.sub(r'^([ \t]*(?:int8|uint8|xunknown8)[ \t]+in_FS_OFFSET)[ \t]*;',
                  r'\1 = __recovery_fs_base();', text, flags=re.M)


def array_pointer_edits(source, mask, name, width, signed):
    """Edits that load or store the whole odd-width element behind `*name` when it is used as a value."""
    edits = []
    for use in re.finditer(rf'\*\s*{re.escape(name)}\b(?!\s*[\[.(]|->)', mask):
        before, tail = mask[:use.start()].rstrip(), mask[use.end():].lstrip()
        if before and (before[-1].isalnum() or before[-1] in '_)]') and not re.search(r'\breturn$', before):
            if before[-1] == ')':
                depth, index = 0, len(before) - 1
                while index >= 0:
                    depth += {')': 1, '(': -1}.get(before[index], 0)
                    if depth == 0:
                        break
                    index -= 1
                head = before[:index].rstrip()
                inner = before[index + 1:-1]
                # Only an integer cast keeps the dereference a value.
                if not re.fullmatch(r'[\w\s]+', inner) or re.search(r'\w$', head) and not re.search(r'\b(?:return|else|case|do)$', head):
                    continue
            else:
                continue
        elif before.endswith('&') or before.endswith(('(', ',')) and re.search(r'\w\s*\($|,$', before) and \
                _is_call_argument(before):
            continue
        store = tail.startswith('=') and not tail.startswith('==')
        if tail.startswith(('++', '--')) or re.match(r'[-+*/%&|^]=|<<=|>>=', tail):
            continue
        if store:
            if before and before[-1] not in ';{}':
                continue
            start = use.end() + len(mask[use.end():]) - len(mask[use.end():].lstrip()) + 1
            stop = statement_end(mask, start)
            if stop is None:
                continue
            edits.append((use.start(), stop, width,
                          f'{{ {ctype(next(w for w in WIDTHS if w >= width))} v__ = ({source[start:stop].strip()}); '
                          f'__builtin_memcpy({name}, &v__, {width}); }}'))
            continue
        load = f'__recovery_load{width}((const void *){name})'
        if signed:
            wide = next(w for w in WIDTHS if w >= width)
            shift = (wide - width) * 8
            load = f'(({ctype(wide, True)})(({ctype(wide)}){load} << {shift}) >> {shift})'
        edits.append((use.start(), use.end(), width, load))
    return edits


def _is_call_argument(before):
    """True when the text ends inside call parentheses, `f(` or `f(x,`."""
    depth = 0
    for index in range(len(before) - 1, -1, -1):
        depth += {')': 1, '(': -1}.get(before[index], 0)
        if depth < 0:
            head = before[:index].rstrip()
            return bool(re.search(r'[\w\]]$', head)) and not re.search(
                r'\b(?:if|while|switch|for|return)$', head)
    return False


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

    # Pointers to odd-width integer arrays: their dereference is a value, not a decayed address.
    pointers = sorted({(m[3], int(m[2]), m[1] == 'int') for m in
                       re.finditer(r'\bunk(u?int)(\d+)\s*\*\s*([A-Za-z_]\w*)\b', code_mask(text))
                       if odd(int(m[2])) and not re.match(r'\s*[\[(]', code_mask(text)[m.end():])})

    def lowered_pass(source):
        mask = code_mask(source)

        def close_paren(start, opener='('):
            closer, depth = ')' if opener == '(' else ']', 0
            for index in range(start, len(mask)):
                if mask[index] == opener:
                    depth += 1
                elif mask[index] == closer:
                    depth -= 1
                    if depth == 0:
                        return index
            return None

        def operand_end(start):
            """End of a parenthesized expression or name, with its call, index and member suffixes."""
            if mask[start:start + 1] == '(':
                end = close_paren(start)
                end = None if end is None else end + 1
            else:
                name = re.compile(r'\*?\s*[A-Za-z_]\w*|\d\w*').match(mask, start)
                end = None if name is None else name.end()
            while end is not None:
                suffix = re.compile(r'\s*(?:\.|->)\s*[A-Za-z_]\w*').match(mask, end)
                if suffix:
                    end = suffix.end()
                    continue
                opener = re.compile(r'\s*([(\[])').match(mask, end)
                if opener is None:
                    break
                closer = close_paren(opener.end() - 1, opener[1])
                end = None if closer is None else closer + 1
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
        for name, width, signed in pointers:
            edits.extend(array_pointer_edits(source, mask, name, width, signed))
        for match in cast.finditer(mask):
            width = int(match[2])
            end = operand_end(match.end())
            if not odd(width) or end is None:
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


FRAME_LOCAL = re.compile(r'^([ \t]+)(?P<type>[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*?[ \t]*\*?)(?:[ \t]+|(?<=\*))'
                         r'(?P<name>[A-Za-z]*Stack_(?P<off>[0-9a-f]+))[ \t]*(?:\[[ \t]*(?P<count>\d+)[ \t]*\])?[ \t]*;[ \t]*$', re.M)
FRAME_WIDENED = re.compile(r'^[ \t]+struct \{ (?P<type>[\w ]+?) value__; (?:xunknown1 pad\[(?P<pad>\d+)\]; )?\} '
                           r'(?P<name>[A-Za-z]*Stack_(?P<off>[0-9a-f]+)__w);[ \t]*$', re.M)
FRAME_TYPE_SIZE = re.compile(r'(?:u?int|xunknown|undefined|unkbyte|unkuint|unkint)(\d+)|(bool|char)|float(\d)')


FRAME_STDINT = re.compile(r'u?int(?:8|16|32|64)_t')


def type_size(kind):
    """Return the size of a stack local type, or None for one not understood."""
    kind = re.sub(r'\s+', ' ', kind.strip()).replace(' *', '*')
    if kind.endswith('*'):
        return 8
    if kind in ('__int128', 'unsigned __int128'):
        return 16
    if FRAME_STDINT.fullmatch(kind):
        return int(re.search(r'\d+', kind)[0]) // 8
    match = FRAME_TYPE_SIZE.fullmatch(kind)
    if match is None:
        return None
    return int(match[1] or match[3] or 1)


def lower_frame(text):
    """Gather stack locals into one struct at their frame offsets when an address escapes.

    Adjacent stack objects are one memory block to the code; separate C locals let a
    pointer or callee run past its own object. Offsets come from the Stack_ names.
    """
    mask = code_mask(text)
    fields = []
    for pattern in (FRAME_LOCAL, FRAME_WIDENED):
        for m in pattern.finditer(mask):
            if m['type'].split()[0] in ('return', 'goto', 'else', 'case'):
                continue
            widened = pattern is FRAME_WIDENED
            base = type_size(m['type'])
            if base is None:
                return text, dict(reason='unsized_local')
            size = base + int(m['pad'] or 0) if widened else base * int(m['count'] or 1)
            fields.append(dict(span=(m.start(), m.end()), name=m['name'], offset=int(m['off'], 16),
                               size=size, align=16 if 'int128' in m['type'] else min(base, 8) if base < 16 else 1, text=text[m.start():m.end()].strip(),
                               array=bool(not widened and m['count'])))
    if not fields:
        return text, None
    names = '|'.join(re.escape(n) for n in sorted((f['name'] for f in fields), key=len, reverse=True))
    uses = [u for u in re.finditer(rf'(?<![\w.>])({names})\b', mask)
            if not any(f['span'][0] <= u.start() < f['span'][1] for f in fields)]
    by_name = {f['name']: f for f in fields}

    def escapes(use):
        before = mask[:use.start()].rstrip()
        if before.endswith('&') and not before.endswith('&&'):
            # Unary unless an operand precedes it; a parenthesized type is a cast, not an operand.
            if not re.search(r'[\w\]]\s*&$', before) and (
                    not before[:-1].rstrip().endswith(')') or re.search(r'\(\s*[A-Za-z_][\w\s*]*\)\s*&$', before)):
                return True
        return by_name[use[1]]['array'] and not mask[use.end():].lstrip().startswith('[')
    if not any(escapes(u) for u in uses):
        return text, None
    fields.sort(key=lambda f: -f['offset'])
    # An object at 8 modulo 16 below the return address is 16-aligned, so the struct starts there.
    start = fields[0]['offset'] + (8 - fields[0]['offset']) % 16
    for f in fields:
        f['position'] = start - f['offset']
    fields.sort(key=lambda f: (f['position'], -f['size']))
    clusters = []
    for f in fields:
        # Locals the decompiler overlaps share storage, so they become a union.
        if clusters and f['position'] < clusters[-1]['end']:
            clusters[-1]['fields'].append(f)
            clusters[-1]['end'] = max(clusters[-1]['end'], f['position'] + f['size'])
        else:
            clusters.append(dict(position=f['position'], end=f['position'] + f['size'], fields=[f]))
    members, cursor, packed = [], 0, False
    for cluster in clusters:
        if cluster['position'] > cursor:
            members.append(f'xunknown1 gap__{cursor}[{cluster["position"] - cursor}];')
        if len(cluster['fields']) == 1:
            f = cluster['fields'][0]
            packed = packed or f['position'] % f['align'] != 0
            members.append(f['text'])
        else:
            packed = True
            inner = []
            for f in cluster['fields']:
                gap = f['position'] - cluster['position']
                inner.append('struct { ' + (f'xunknown1 pad__{f["position"]}[{gap}]; ' if gap else '') + f['text'] +
                             ' } __attribute__((packed));')
            members.append('union { ' + ' '.join(inner) +
                           f' xunknown1 extent__{cluster["position"]}[{cluster["end"] - cluster["position"]}]; }};')
        cursor = cluster['end']
    declaration = '  struct {\n' + ''.join(f'    {m}\n' for m in members) + '  } __attribute__((' + ('packed, ' if packed else '') + 'aligned(16))) frame__;'
    # The frame as an asm operand lets a callee reach every member through any member address.
    declaration += '\n  __asm__ volatile("" : : "r"(&frame__) : "memory");'
    edits = [(u.start(), u.end(), 'frame__.' + u[1]) for u in uses]
    first = min(f['span'][0] for f in fields)
    for f in fields:
        begin, end = f['span']
        edits.append((begin, end + 1 if text[end:end + 1] == '\n' else end, declaration + '\n' if begin == first else ''))
    for begin, end, value in sorted(edits, reverse=True):
        text = text[:begin] + value + text[end:]
    return text, dict(frame_locals=len(fields), frame_size=start)


def odd_width_helper(width):
    if width == 3:
        # A halfword and a byte, as compilers read a little-endian 24-bit field.
        return (
            'static inline uint32_t __recovery_load3(const void *p) {\n'
            '    uint16_t lo;\n'
            '    __builtin_memcpy(&lo, p, 2);\n'
            '    return (uint32_t)lo + ((uint32_t)((const uint8_t *)p)[2] << 16);\n'
            '}'
        )
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


def lower_pointer_floats(text):
    """Store a pointer into a float-typed slot bitwise; a C cast would convert, or not compile."""
    def store(match):
        indent, target, value = match.groups()
        if value[0] != '"' and not re.search(rf'\*\s*{value}\s*[;,\[]', text):
            return match.group(0)
        return f'{indent}__builtin_memcpy(&({target}), &(void *){{{value}}}, sizeof(void *));'
    return re.sub(r'^(\s*)([^=;{}\n]+?) = \(float8\)("(?:[^"\\\n]|\\.)*"|[A-Za-z_]\w*);$', store, text, flags=re.M)


def stack_structs(base, binary_report, source):
    """Definitions of the by-value stack argument structs that the emitted text names."""
    lines = []
    # A subset of functions still names the structs of callees outside the subset.
    for row in binary_report.get('all_functions', binary_report.get('functions', [])):
        try:
            records = abi_evidence.read_evidence(base / 'functions' / f'{row["address"]:x}' / 'prototype-evidence.tsv')
        except (OSError, ValueError):
            continue
        block = next((r['stackargs'] for r in records if r['kind'] == 'function' and r['stackargs']), None)
        if block and block['name'] != '-' and re.search(rf'\b{re.escape(block["name"])}\b', source):
            lines.append(abi_evidence.stack_struct_source(block['name'], block))
    return '\n'.join(lines) + '\n\n' if lines else ''


def assemble(binary_report):
    base = Path(binary_report['output'])
    bodies, missing, definitions, prototypes = [], [], {}, []
    stubs, imports, runtime = link_boundary(binary_report.get('path'))
    try:
        image = Elf(binary_report['path'])
    except (KeyError, OSError, TypeError, ValueError, IndexError):
        image = None
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
    machine = None
    if machine_types.enabled():
        bodies, machine = machine_types.apply_all(bodies, signature)
        prototypes = [parsed[1] + ';' for parsed in map(signature, (t for _, t in bodies)) if parsed]
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
    transformed, slice_widths, odd_widths, storage, frames = [], set(), set(), [], []
    for address, text in bodies:
        lowered, vectors = lower_vectors(replace_identifiers(text, renames))
        lowered, used, detail = lower_storage(lowered)
        lowered = lower_struct_casts(lowered)
        lowered, odd_used = lower_odd_widths(initialize_tls_base(lower_pointer_floats(lowered)))
        lowered, frame = lower_frame(lowered)
        if frame:
            frames.append(dict(address=address, **frame))
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
        aliases.append(f'typedef {ctype(width, True)} int{width};')
        # Decompiled 16-byte accesses are not 16-aligned, so GCC must not emit aligned vector moves.
        tail = ' __attribute__((aligned(1)))' if width == 16 else ''
        aliases.extend(f'typedef {ctype(width)} {name}{width}{tail};'
                       for name in ('uint', 'undefined', 'xunknown'))
    for name in sorted(t for t in tokens if ODD_TYPE.fullmatch(t)):
        width, signed = int(re.search(r'\d+', name)[0]), name.startswith('unkint')
        if width in WIDTHS:
            aliases.append(f'typedef {ctype(width, signed)} {name};')
        else:
            # Array typedefs let unresolved odd-width pointers and prototypes declare.
            aliases.append(f'typedef {"signed" if signed else "unsigned"} char {name}[{width}];')
    masked = code_mask(source)
    aliases.extend(import_decl(t, masked) if t in IMPORT_PARAMS else USEROPS[t] for t in sorted(tokens & USEROPS.keys()))
    if 'in_FS_OFFSET' in tokens:
        aliases.append('static inline uint64_t __recovery_fs_base(void) { uint64_t b; '
                       '__asm__("mov %%fs:0, %0" : "=r"(b)); return b; }')
    # Imports the decompiler already names are referenced too; none has a body here.
    called_imports |= (tokens & set(imports.values())) - set(definitions.values())
    aliases.extend(import_decl(name, masked) for name in sorted(called_imports - USEROPS.keys()))
    header = '\n'.join(aliases + implementations + [slice_helpers(w) for w in sorted(slice_widths)] + [odd_width_helper(w) for w in sorted(odd_widths)] + ['#endif', ''])
    globals_source, global_metadata = global_state.recover(base, binary_report.get('functions', []), definitions,
                                                              code_mask(source), image)
    # Local symbols such as __PRETTY_FUNCTION__.18 are renamed like the function clones.
    globals_source = clone_identifiers(globals_source)
    declared = [clone_identifiers(name) for name in
                global_metadata['exported_globals'] + global_metadata['external_globals']]
    missing_source, missing_names = global_state.declare_missing(code_mask(source), set(declared))
    global_metadata['name_declared_globals'] = missing_names
    globals_source = '\n'.join(filter(None, [globals_source, missing_source]))
    # Avoid accepting implicit int-return declarations for cross-function calls.
    program = '#include "recovered_support.h"\n\n' + stack_structs(base, binary_report, source) + '\n'.join(prototypes) + '\n\n' + globals_source + '\n\n' + source
    metadata = dict(function_count=len(bodies), missing_functions=missing,
                    toolchain_runtime_excluded=sorted(excluded),
                    imports_called=sorted(called_imports),
                    unresolved_callees=sorted(calls - set(definitions)),
                    helper_implementations=[name for name in required if name not in unsupported],
                    unsupported_helpers=unsupported,
                    unparsed_signatures=[address for address, _ in bodies if address not in definitions],
                    renamed_identifiers=renames, storage_lowering=storage, frame_lowering=frames,
                    slice_widths=sorted(slice_widths), odd_widths_lowered=sorted(odd_widths),
                    unresolved_odd_width_types=sorted(t for t in tokens if re.fullmatch(r'unk(?:u)?int\d+', t)),
                    global_state=global_metadata,
                    abi_evidence=abi_evidence.compare(base, binary_report.get('functions', [])),
                    semantic_equivalence_proved=False)
    if machine is not None:
        metadata['machine_types'] = {f'{a:x}': n for a, n in machine.items() if n}
    spec = dict(origin='whole-program decompiler proposal with integer operation lowering',
                files={'program.c': program, 'recovered_support.h': header}, holes={},
                profiles=[dict(compiler='gcc', flags=['-O2'], sources=['program.c'])])
    return spec, metadata
