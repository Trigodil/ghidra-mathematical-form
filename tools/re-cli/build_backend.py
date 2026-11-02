#!/usr/bin/env python3
"""Build only the CLI's native analyzers from this checkout; no target is run."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import subprocess

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / 'research/graph_fibers/cpp'
CORE = REPO / 'Ghidra/Features/Decompiler/src/decompile/cpp'


def build(jobs):
    # Use the prepared native dependencies; never download or execute an input app.
    for path in (ROOT / '.deps/z3/include/z3++.h', ROOT / '.deps/zlib/zlib.h',
                 ROOT / '.deps/spec/x86-64.sla'):
        if not path.exists():
            raise ValueError(f'Missing native dependency: {path}; supply Z3 SDK, zlib headers and compiled x86 specs in .deps')
    directory = ROOT / 'build/cli-objects'
    directory.mkdir(parents=True, exist_ok=True)
    makefile = (CORE / 'Makefile').read_text().replace('\\\n', ' ')
    names = re.search(r'^DECCORE=(.*)$', makefile, re.M).group(1).split()
    names = [name for name in names if not name.startswith('$')]
    names += ['xml_arch', 'loadimage_xml', 'sleigh_arch', 'inject_sleigh', 'libdecomp']
    sleigh = ('xml marshal space float address pcoderaw translate opcodes metatype globalcontext '
              'sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics '
              'context slaformat compression filemanage loadimage').split()
    compiler = os.environ.get('CXX', 'g++')
    flags = [compiler, '-O1', '-g0', '-std=c++17', '-Wno-sign-compare',
             '-I' + str(CORE), '-I' + str(ROOT / '.deps/zlib'),
             '-isystem', str(ROOT / '.deps/z3/include')]
    header_time = max(p.stat().st_mtime for p in [*CORE.glob('*.hh'), *ROOT.glob('*.hpp')])

    def compile_one(name):
        source, obj = CORE / (name + '.cc'), directory / (name + '.o')
        if not obj.exists() or obj.stat().st_mtime < max(header_time, source.stat().st_mtime):
            subprocess.run([*flags, '-c', str(source), '-o', str(obj)], check=True)
        return obj

    all_names = list(dict.fromkeys(names + sleigh))
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        objects = dict(zip(all_names, pool.map(compile_one, all_names)))
    common = ['-L' + str(ROOT / '.deps/z3/lib'), '-Wl,-rpath,$ORIGIN/../.deps/z3/lib',
              '-lz3', '-l:libz.so.1']
    for name, source, group in [('core-decompile', 'core_decompile.cpp', all_names),
                                ('native-audit', 'native_audit.cpp', sleigh),
                                ('native-discover', 'native_discover.cpp', sleigh)]:
        subprocess.run([*flags, str(ROOT / source), *(str(objects[n]) for n in group),
                        *common, '-o', str(ROOT / 'build' / name)], check=True)
    subprocess.run([os.environ.get('CC', 'gcc'), '-shared', '-fPIC', '-O2', '-Wall', '-Wextra',
                    str(ROOT / 'analysis_lockdown.c'), '-o', str(ROOT / 'build/analysis-lockdown.so')], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-j', '--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    try:
        build(args.jobs)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Build failed: {error}\n')
