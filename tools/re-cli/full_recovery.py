"""Whole-artifact compiler-fiber search, never function-byte acceptance.

Candidates are complete C/C++ projects from finite, explicitly declared source
choices and compiler profiles. Exhaustion is relative to that grammar, never an
impossibility claim about source recovery. Decompiler text is only a proposal.
"""
import hashlib
import heapq
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

HERE = Path(__file__).resolve().parent
TOKEN = re.compile(r'@@([A-Za-z_][A-Za-z_0-9]*)@@')
SOURCE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx'}
FILE_SUFFIXES = SOURCE_SUFFIXES | {'.h', '.hpp', '.inc'}
FLAGS = {
    '-O0', '-O1', '-O2', '-O3', '-Os', '-Og', '-Oz', '-g', '-g0', '-s',
    '-fPIC', '-fpic', '-fPIE', '-fpie', '-fno-pie', '-pie', '-no-pie', '-shared',
    '-nostdlib', '-nostartfiles', '-nodefaultlibs', '-static', '-pthread',
    '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fstack-protector-strong',
    '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fno-ident',
    '-fno-if-conversion', '-fno-if-conversion2', '-fno-omit-frame-pointer',
    '-fno-exceptions', '-fno-rtti', '-fwrapv', '-fno-strict-aliasing',
    '-fcf-protection=none', '-fcf-protection=full',
    '-Wl,--build-id=none', '-Wl,--build-id=sha1', '-Wl,--gc-sections',
    '-ffunction-sections', '-fdata-sections', '-lm', '-ldl',
}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def relative_name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]*', name):
        raise ValueError('Project paths must be plain relative paths')
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(p in ('.', '..') or p.startswith('-') for p in name.split('/')):
        raise ValueError('Project paths cannot escape their project')
    return path


def validate(spec):
    if not isinstance(spec, dict) or set(spec) - {'files', 'holes', 'profiles', 'origin'}:
        raise ValueError('Recovery project requires files, holes and profiles')
    files, holes, profiles = spec.get('files'), spec.get('holes', {}), spec.get('profiles')
    if not isinstance(files, dict) or not files or not isinstance(holes, dict):
        raise ValueError('Recovery files must be a nonempty map and holes a map')
    for name, content in files.items():
        path = relative_name(name)
        if path.suffix not in FILE_SUFFIXES or not isinstance(content, str) or '\0' in content:
            raise ValueError('Only textual C/C++ sources and headers are accepted')
    names = set(files)
    if any(str(p) in names for name in files for p in PurePosixPath(name).parents if str(p) != '.'):
        raise ValueError('Project file/directory collision')
    referenced = set(TOKEN.findall('\n'.join(files.values())))
    if referenced != set(holes):
        raise ValueError('Every source hole must have choices and every choice must be used')
    for name, choices in holes.items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) or not isinstance(choices, list) or not choices:
            raise ValueError('Holes need valid names and nonempty choice lists')
        for choice in choices:
            if (not isinstance(choice, dict) or set(choice) != {'text', 'cost'}
                    or not isinstance(choice['text'], str) or '\0' in choice['text']
                    or '@@' in choice['text'] or type(choice['cost']) is not int or choice['cost'] < 0):
                raise ValueError('Choices need literal text and a nonnegative integer cost')
    if not isinstance(profiles, list) or not profiles:
        raise ValueError('At least one compiler profile is required')
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile) - {'compiler', 'flags', 'sources', 'cost'}:
            raise ValueError('Invalid compiler profile')
        if profile.get('compiler') not in ('gcc', 'g++', 'clang', 'clang++'):
            raise ValueError('Use a supported system C/C++ compiler')
        if type(profile.get('cost', 0)) is not int or profile.get('cost', 0) < 0:
            raise ValueError('Profile cost must be a nonnegative integer')
        flags = profile.get('flags', [])
        if not isinstance(flags, list) or any(not isinstance(f, str) or not (
                f in FLAGS or re.fullmatch(r'-std=(?:c(?:89|99|11|17|2x|23)|gnu(?:89|99|11|17|2x|23)|(?:gnu\+\+|c\+\+)(?:11|14|17|20|23))', f)) for f in flags):
            raise ValueError('Unsupported compiler flags; plugins, build scripts and binary inputs are not allowed')
        sources = profile.get('sources')
        if (not isinstance(sources, list) or not sources or any(not isinstance(s, str) or s not in files or
                PurePosixPath(s).suffix not in SOURCE_SUFFIXES for s in sources) or len(set(sources)) != len(sources)):
            raise ValueError('Profile sources must list project translation units without duplicates')
        if set(sources) != {name for name in files if PurePosixPath(name).suffix in SOURCE_SUFFIXES}:
            raise ValueError('Every translation unit must participate in the whole-project build')
    return spec


def candidates(spec):
    """Lazy increasing declared-cost traversal of the entire finite product."""
    names = sorted(spec.get('holes', {}))
    axes = [sorted(enumerate(spec['holes'][name]), key=lambda pair: (pair[1]['cost'], pair[0])) for name in names]
    axes.append(sorted(enumerate(spec['profiles']), key=lambda pair: (pair[1].get('cost', 0), pair[0])))
    initial = (0,) * len(axes)
    def cost(indices):
        return sum(axis[i][1].get('cost', 0) for axis, i in zip(axes, indices))
    heap, seen = [(cost(initial), initial)], {initial}
    while heap:
        score, indices = heapq.heappop(heap)
        choices = {name: axes[i][indices[i]][1]['text'] for i, name in enumerate(names)}
        files = {name: TOKEN.sub(lambda match: choices[match[1]], content) for name, content in spec['files'].items()}
        yield dict(cost=score, choices={name: axes[i][indices[i]][0] for i, name in enumerate(names)},
                   profile_index=axes[-1][indices[-1]][0], files=files,
                   profile=axes[-1][indices[-1]][1])
        for dim, axis in enumerate(axes):
            if indices[dim] + 1 >= len(axis):
                continue
            next_indices = list(indices)
            next_indices[dim] += 1
            next_indices = tuple(next_indices)
            if next_indices not in seen:
                seen.add(next_indices)
                heapq.heappush(heap, (cost(next_indices), next_indices))


def compare_files(target, rebuilt):
    """Stream every byte; retain a bounded mismatch witness, including EOF."""
    offset, first, count = 0, None, 0
    target_hash, rebuilt_hash = hashlib.sha256(), hashlib.sha256()
    with target.open('rb') as left, rebuilt.open('rb') as right:
        while True:
            a, b = left.read(1024 * 1024), right.read(1024 * 1024)
            if not a and not b:
                break
            target_hash.update(a); rebuilt_hash.update(b)
            if a != b:
                count += abs(len(a) - len(b))
                for i, (x, y) in enumerate(zip(a, b)):
                    if x != y:
                        count += 1
                        if first is None:
                            first = dict(offset=offset + i, target=x, rebuilt=y)
                if first is None and len(a) != len(b):
                    i = min(len(a), len(b))
                    first = dict(offset=offset + i, target=a[i] if i < len(a) else None,
                                 rebuilt=b[i] if i < len(b) else None)
            offset += max(len(a), len(b))
    return dict(equal=first is None, first_difference=first, different_bytes=count,
                target_sha256=target_hash.hexdigest(), rebuilt_sha256=rebuilt_hash.hexdigest(),
                target_size=target.stat().st_size, rebuilt_size=rebuilt.stat().st_size)


def decompiler_project(binary_report):
    """Keep all emitted functions in the proposal, without inventing bodies."""
    base = Path(binary_report['output'])
    texts, missing = [], []
    for row in binary_report.get('functions', []):
        source = base / 'functions' / f'{row["address"]:x}' / 'decompiled.c'
        if source.is_file():
            texts.append(source.read_text(errors='replace'))
        else:
            missing.append(row['address'])
    if not texts:
        return None, missing
    # These are type spelling adapters, not a claim that recovered types are correct.
    aliases = ['#include <stdint.h>', '#include <stdbool.h>', 'typedef unsigned char byte;',
               'typedef unsigned int uint;', 'typedef unsigned long ulong;', 'typedef void code(void);']
    for width in (1, 2, 4, 8):
        aliases.extend([f'typedef int{width * 8}_t int{width};',
                        f'typedef uint{width * 8}_t uint{width}, undefined{width}, xunknown{width};'])
    aliases.append('typedef uint8_t undefined;')
    return dict(origin='all decompiler outputs; unverified proposal',
                files={'program.c': '\n'.join(aliases + texts)}, holes={},
                profiles=[dict(compiler='gcc', flags=['-O2'], sources=['program.c'])]), missing


def recover(target, spec, folder, run, emit, timeout=60, memory=2048, max_candidates=64):
    """Search full source projects. The callback supplies resource/process limits."""
    validate(spec)
    if max_candidates < 1:
        raise ValueError('Candidate budget must be positive')
    target, folder = Path(target).resolve(), Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    baseline = sha(target)
    write_json(folder / 'grammar.json', spec)
    cardinality = len(spec['profiles'])
    for choices in spec.get('holes', {}).values():
        cardinality *= len(choices)
    report = dict(objective='full_source_recovery', acceptance='entire_binary_byte_equality',
                  status='running', whole_binary_recovered=False, historical_source_recovered=False,
                  target_executed=False, rebuilt_executed=False, target_sha256=baseline,
                  grammar_candidates=cardinality, attempts=[], unresolved_attempts=0,
                  source_admissibility='C/C++ project grammar supplied by proposal source; not independently certified',
                  scope='one complete ELF artifact, including metadata; external dependency sources are not recovered')
    write_json(folder / 'report.json', report)
    for index, candidate in enumerate(candidates(spec)):
        if index >= max_candidates:
            report['status'] = 'budget_exhausted'
            break
        # Never reuse an old executable or compiler result as new evidence.
        attempt = folder / 'attempts' / f'{index:06d}'
        if attempt.exists():
            shutil.rmtree(attempt)
        attempt.mkdir(parents=True)
        for name, content in candidate['files'].items():
            path = attempt / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        profile = candidate['profile']
        compiler = Path('/usr/bin') / profile['compiler']
        row = dict(index=index, cost=candidate['cost'], choices=candidate['choices'],
                   profile_index=candidate['profile_index'], project=str(attempt))
        report['attempts'].append(row)
        if not compiler.is_file():
            row.update(status='compiler_unavailable', compiler=str(compiler))
            report['unresolved_attempts'] += 1
            write_json(folder / 'report.json', report)
            continue
        # Profiles cannot supply arbitrary executables, output paths or object files.
        diagnostic_limit = '-fmax-errors=20' if profile['compiler'] in ('gcc', 'g++') else '-ferror-limit=20'
        command = [str(compiler), diagnostic_limit, *profile['sources'], *profile.get('flags', []), '-o', 'rebuilt.elf']
        build = dict(command=command, compiler_sha256=sha(compiler),
                     sources_sha256={name: sha(attempt / name) for name in candidate['files']},
                     environment=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', SOURCE_DATE_EPOCH='0'),
                     worker_sha256=sha(HERE / 'recovery_build.py'))
        write_json(attempt / 'build.json', build)
        shutil.copyfile(HERE / 'recovery_build.py', attempt / 'rebuild.py')
        emit(f'[full recovery] candidate {index + 1}/{cardinality}; cost={candidate["cost"]}')
        result = run([sys.executable, attempt / 'rebuild.py'], attempt, timeout, memory,
                     cwd=attempt, label=f'whole-project build {index + 1}')
        row['build'] = result
        rebuilt = attempt / 'rebuilt.elf'
        if result['status'] != 'ok' or not rebuilt.is_file():
            isolated = (attempt / 'build-isolation.json').is_file()
            row['status'] = 'compile_failed' if isolated and result.get('exit_code') == 1 else 'build_unresolved'
            if row['status'] == 'build_unresolved':
                report['unresolved_attempts'] += 1
        else:
            comparison = compare_files(target, rebuilt)
            row['comparison'] = comparison
            write_json(attempt / 'comparison.json', comparison)
            if comparison['target_sha256'] != baseline or sha(target) != baseline:
                row['status'] = 'input_changed'
                report['status'] = 'input_changed'
                break
            row['status'] = 'verified_exact' if comparison['equal'] else 'byte_mismatch'
            if comparison['equal']:
                report.update(status='verified_exact', whole_binary_recovered=True,
                              recovered_project=str(attempt), rebuilt_binary=str(rebuilt),
                              minimal_declared_cost=report['unresolved_attempts'] == 0)
                break
        write_json(folder / 'report.json', report)
    else:
        report['status'] = 'unresolved' if report['unresolved_attempts'] else 'grammar_exhausted'
    report['target_unchanged'] = sha(target) == baseline
    if not report['target_unchanged']:
        report.update(status='input_changed', whole_binary_recovered=False)
    write_json(folder / 'report.json', report)
    return report
