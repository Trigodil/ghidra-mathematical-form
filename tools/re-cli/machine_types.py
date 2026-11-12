"""Opt-in machine typed rewriting of decompiler C (RE_MACHINE_TYPES=1).
Comparisons get the width and signedness the decompiler meant, as explicit casts,
where C conversion rules would choose differently; narrow returns widen to a register.
"""
import os
import re

TOKEN = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*|'
                   r'<<=|>>=|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[^\s\w]')
SCALARS = {'bool': ('B', 1), 'char': ('S', 1), 'byte': ('U', 1), 'uchar': ('U', 1),
           'ushort': ('U', 2), 'short': ('S', 2), 'uint': ('U', 4), 'int': ('S', 4),
           'ulong': ('U', 8), 'long': ('S', 8), 'longlong': ('S', 8), 'ulonglong': ('U', 8),
           'unsigned char': ('U', 1), 'signed char': ('S', 1), 'unsigned short': ('U', 2),
           'unsigned int': ('U', 4), 'unsigned long': ('U', 8), 'unsigned': ('U', 4),
           'float4': ('F', 4), 'float8': ('F', 8), 'float': ('F', 4), 'double': ('F', 8)}
for _w in (1, 2, 4, 8):
    SCALARS.update({f'int{_w}': ('S', _w), f'uint{_w}': ('U', _w), f'xunknown{_w}': ('X', _w),
                    f'undefined{_w}': ('X', _w), f'int{_w * 8}_t': ('S', _w), f'uint{_w * 8}_t': ('U', _w)})
TYPE_WORDS = set(SCALARS) | {'void', 'code', 'unsigned', 'signed', 'undefined', 'xunknown16',
                             'uint16', 'int16', 'undefined16'}
NARROW_RETURN = {'bool', 'char', 'byte', 'uchar', 'ushort', 'short', 'int1', 'uint1', 'int2',
                 'uint2', 'xunknown1', 'xunknown2', 'undefined1', 'undefined2'}
RELATIONAL = {'<', '<=', '>', '>='}
STOP = {'==', '!=', '&', '^', '|', '&&', '||', '?', ':', '=', ',', ';', '{', '}', '<', '<=',
        '>', '>=', 'return', 'if', 'while', 'else', 'case', 'do', 'switch', 'for', 'goto'}


def enabled():
    return os.environ.get('RE_MACHINE_TYPES') == '1'


def is_type_word(word):
    return word in TYPE_WORDS or word.endswith('_stackargs') or re.fullmatch(r'unk(?:u?int|byte)\d+', word)


def scalar(words, stars):
    """Machine type (kind, width) of a declared C type, or None when not an integer word."""
    if stars:
        return ('P', 8)
    return SCALARS.get(' '.join(words))


class Unknown(Exception):
    pass


def tokens(text):
    return [(m.start(), m.end(), m[0]) for m in TOKEN.finditer(text) if not m[0].startswith(('/*', '//'))]


def constant(tok):
    """(ghidra type, c type) of an integer literal."""
    digits = tok.rstrip('uUlL')
    suffix = tok[len(digits):].lower()
    value = int(digits, 16) if digits[:2].lower() == '0x' else int(digits)
    hexa = digits[:2].lower() == '0x'
    if 'u' in suffix:
        c = ('U', 8 if 'l' in suffix or value > 0xffffffff else 4)
    elif 'l' in suffix:
        c = ('S', 8) if value <= 0x7fffffffffffffff else ('U', 8)
    elif value <= 0x7fffffff:
        c = ('S', 4)
    elif hexa and value <= 0xffffffff:
        c = ('U', 4)
    else:
        c = ('S', 8) if value <= 0x7fffffffffffffff else ('U', 8)
    return ('UK' if 'u' in suffix else 'K', 0), c


def promote(c):
    return ('S', 4) if c[1] < 4 else c


def c_common(a, b):
    a, b = promote(a), promote(b)
    if a[0] == b[0]:
        return (a[0], max(a[1], b[1]))
    s, u = (a, b) if a[0] == 'S' else (b, a)
    return s if s[1] > u[1] else u


GHIDRA_RANK = {'U': 0, 'B': 1, 'S': 2, 'X': 3}


def g_common(a, b):
    """Decompiler output type of a binary integer op: wider wins, then uint, int, unknown."""
    if a[0] == 'K':
        return b
    if b[0] == 'K':
        return a
    if a[0] == 'UK':
        return ('UK', 0) if b[0] == 'UK' else ('U', b[1])
    if b[0] == 'UK':
        return ('U', a[1])
    if a[1] != b[1]:
        return a if a[1] > b[1] else b
    return a if GHIDRA_RANK[a[0]] <= GHIDRA_RANK[b[0]] else b


class Expr:
    """Types a token span holding a shift-level C expression.

    Each node is (ghidra, c, wide): wide means C may carry bits above the ghidra width."""

    def __init__(self, toks, names, returns):
        self.t, self.i, self.returns = toks, 0, returns
        self.names, self.pointees = names

    def peek(self, k=0):
        return self.t[self.i + k][2] if self.i + k < len(self.t) else None

    def take(self):
        self.i += 1
        return self.t[self.i - 1][2]

    def run(self):
        node = self.binary(0)
        if self.i != len(self.t):
            raise Unknown()
        return node

    PREC = {'*': 3, '/': 3, '%': 3, '+': 2, '-': 2, '<<': 1, '>>': 1}

    def binary(self, level):
        left = self.unary()
        while self.peek() in self.PREC and self.PREC[self.peek()] > level:
            op = self.take()
            right = self.binary(self.PREC[op])
            left = self.combine(op, left, right)
        return left

    def combine(self, op, a, b):
        if a[0][0] in ('P', 'F') or b[0][0] in ('P', 'F'):
            raise Unknown()
        if op in ('<<', '>>'):
            g, c = a[0], promote(a[1])
        else:
            g, c = g_common(a[0], b[0]), c_common(a[1], b[1])
        wide = op not in ('/', '%', '>>') or a[2] or b[2]
        return g, c, wide and g[0] not in ('K', 'UK') and g[1] < c[1]

    def cast_ahead(self):
        if self.peek() != '(':
            return None
        k, words, stars = 1, [], 0
        while self.peek(k) and (is_type_word(self.peek(k)) or (words and self.peek(k) == '*')):
            if self.peek(k) == '*':
                stars += 1
            elif stars:
                return None
            else:
                words.append(self.peek(k))
            k += 1
        if not words or self.peek(k) != ')':
            return None
        return k + 1, words, stars

    def unary(self):
        tok = self.peek()
        cast = self.cast_ahead()
        if cast:
            self.i += cast[0]
            self.unary()
            ty = scalar(cast[1], cast[2])
            if ty is None:
                raise Unknown()
            return ty, ty, False
        if tok in ('-', '~'):
            self.take()
            g, c, w = self.unary()
            return g, promote(c), w or c[1] < 4
        if tok == '!':
            self.take()
            self.unary()
            return ('K', 0), ('S', 4), False
        if tok == '*':
            self.take()
            cast = self.cast_ahead()
            if cast and cast[2] == 1:
                self.i += cast[0]
                self.unary()
                ty = scalar(cast[1], 0)
            else:
                name = self.take()
                ty = self.pointees.get(name)
                if self.peek() in ('[', '.', '->', '('):
                    raise Unknown()
            if ty is None:
                raise Unknown()
            return ty, ty, False
        if tok == '&':
            raise Unknown()
        return self.postfix()

    def postfix(self):
        tok = self.take()
        if tok is None:
            raise Unknown()
        if tok == '(':
            node = self.binary(0)
            if self.take() != ')':
                raise Unknown()
        elif re.fullmatch(r'\d\w*|0[xX]\w+', tok):
            g, c = constant(tok)
            node = (g, c, False)
        elif tok.startswith("'"):
            node = (('K', 0), ('S', 4), False)
        elif re.fullmatch(r'[A-Za-z_]\w*', tok):
            if self.peek() == '(':
                ty = self.returns.get(tok)
                self.skip_group()
                if ty is None:
                    raise Unknown()
                node = (ty, ty, False)
            elif self.peek() == '[':
                ty = self.pointees.get(tok)
                self.skip_group()
                if ty is None:
                    raise Unknown()
                node = (ty, ty, False)
            else:
                ty = self.names.get(tok)
                if ty is None:
                    raise Unknown()
                node = (ty, ty, False)
        else:
            raise Unknown()
        if self.peek() in ('[', '.', '->', '(', '++', '--'):
            raise Unknown()
        return node

    def skip_group(self):
        depth = 0
        while True:
            tok = self.take()
            if tok is None:
                raise Unknown()
            depth += (tok in '([') - (tok in ')]')
            if depth == 0:
                return


def declarations(body, params):
    """Scalar machine types of the parameters and locals a function declares."""
    names, pointees = {}, {}
    for decl in params:
        m = re.fullmatch(r'\s*([A-Za-z_][\w ]*?)\s*(\**)\s*([A-Za-z_]\w*)\s*', decl)
        if m:
            ty = scalar(m[1].split(), len(m[2]))
            if ty:
                names[m[3]] = ty
            if len(m[2]) == 1 and scalar(m[1].split(), 0):
                pointees[m[3]] = scalar(m[1].split(), 0)
    for m in re.finditer(r'^[ \t]+([A-Za-z_][\w ]*?)[ \t]*(\**)[ \t]*([A-Za-z_]\w*)[ \t]*(\[[^\]\n]*\])?[ \t]*;', body, re.M):
        words = m[1].split()
        if words[0] in ('return', 'goto', 'else', 'case', 'break', 'continue') or m[4]:
            continue
        ty = scalar(words, len(m[2]))
        if ty:
            names[m[3]] = ty
        if len(m[2]) == 1 and scalar(words, 0):
            pointees[m[3]] = scalar(words, 0)
    return names, pointees


def operand(toks, at, step):
    """Index range of the relational operand next to toks[at], walking by step."""
    depth, k = 0, at + step
    while 0 <= k < len(toks):
        tok = toks[k][2]
        if tok in ('(', '['):
            depth += step == 1 and 1 or -1
        elif tok in (')', ']'):
            depth += step == -1 and 1 or -1
        if depth < 0:
            break
        if depth == 0 and tok in STOP:
            if tok != '&' or step == 1 or not (k == 0 or toks[k - 1][2] in STOP | {'('}):
                break
        k += step
    lo, hi = (k + 1, at) if step == -1 else (at + 1, k)
    return lo, hi


def rewrite_compares(text, names, returns):
    """One pass: wrap the operands of comparisons whose C semantics differ from the decompiler's."""
    toks = tokens(text)
    edits = []
    for k, (_, _, tok) in enumerate(toks):
        if tok not in RELATIONAL and tok not in ('==', '!='):
            continue
        spans = [operand(toks, k, -1), operand(toks, k, 1)]
        if any(lo >= hi for lo, hi in spans):
            continue
        try:
            nodes = [Expr(toks[lo:hi], names, returns).run() for lo, hi in spans]
        except (Unknown, IndexError, ValueError, RecursionError):
            continue
        kinds = {nodes[0][0][0], nodes[1][0][0]}
        if kinds & {'P', 'F'}:
            continue
        g = g_common(nodes[0][0], nodes[1][0])
        # Bare unknown against signed has no single decompiler reading; leave it.
        if g[0] in ('K', 'UK') or kinds == {'S', 'X'}:
            continue
        width, signed = g[1], g[0] == 'S'
        c = c_common(nodes[0][1], nodes[1][1])
        wide = any(n[2] for n in nodes)
        narrow = [n[1] for n in nodes if n[0][0] not in ('K', 'UK')]
        if tok in RELATIONAL and not wide and all(t[1] < 4 for t in narrow):
            # Narrow values promote to int exactly; only their own sign matters.
            need = any((t[0] == 'S') != signed for t in narrow)
        elif tok in RELATIONAL:
            need = (c[0] == 'S') != signed or wide
        else:
            need = wide
        if not need:
            continue
        name = f'{"int" if signed else "uint"}{width}'
        for lo, hi in spans:
            edits.append((toks[lo][0], toks[hi - 1][1], name))
    edits.sort()
    kept, cursor = [], -1
    for start, end, name in edits:
        if start >= cursor:
            kept.append((start, end, name))
            cursor = end
    for start, end, name in reversed(kept):
        text = f'{text[:start]}({name})({text[start:end]}){text[end:]}'
    return text, len(kept)


def widen_return(prefix):
    """Declarator prefix with a narrow integer return type widened to the 32 bit register."""
    m = re.match(r'(\s*)([A-Za-z_]\w*)(\s+)(?=[A-Za-z_]\w*\s*\()', prefix)
    if m and m[2] in NARROW_RETURN:
        return prefix[:m.start(2)] + 'uint4' + prefix[m.end(2):]
    return prefix


def split_params(prefix):
    inner = prefix[prefix.index('(') + 1:prefix.rindex(')')]
    return [] if inner.strip() in ('', 'void') else inner.split(',')


def apply_all(bodies, signature):
    """Rewrite every parsed function body; returns new bodies and per-function edit counts."""
    returns, parsed = {}, {}
    for address, text in bodies:
        sig = signature(text)
        if not sig:
            continue
        name, prefix = sig
        parsed[address] = (name, prefix)
        head = re.match(r'\s*([A-Za-z_][\w ]*?)\s*(\**)\s*\b' + re.escape(name) + r'\s*\(', prefix)
        if head:
            ty = scalar(head[1].split(), len(head[2]))
            if ty and head[1].strip() in NARROW_RETURN:
                ty = ('U', 4)
            if ty:
                returns[name] = ty
    out, counts = [], {}
    for address, text in bodies:
        if address not in parsed:
            out.append((address, text))
            continue
        name, prefix = parsed[address]
        brace = text.find('{')
        head, body = text[:brace], text[brace:]
        names = declarations(body, split_params(prefix))
        total = 0
        for _ in range(4):
            body, n = rewrite_compares(body, names, returns)
            total += n
            if not n:
                break
        new_head = widen_return(head)
        if new_head != head:
            total += 1
        counts[address] = total
        out.append((address, new_head + body))
    return out, counts
