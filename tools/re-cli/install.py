#!/usr/bin/env python3
"""Install the CLI, prepared native backend and specs; register the re- command."""
import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def install(prefix, repo):
    source = repo / 'research/graph_fibers/cpp'
    binaries = ['core-decompile', 'native-audit', 'native-discover', 'analysis-lockdown.so']
    required = [source / 'build' / name for name in binaries]
    required += [source / '.deps/spec/x86-64.sla', source / 'extract_bun_static.py']
    z3libs = list((source / '.deps/z3/lib').glob('libz3.so*'))
    languages = repo / 'Ghidra/Processors/x86/data/languages'
    specs = [p for pattern in ('*.ldefs', '*.pspec', '*.cspec') for p in languages.glob(pattern)]
    for path in required:
        if not path.is_file():
            raise ValueError(f'Missing backend: {path}. Run tools/re-cli/build_backend.py first.')
    if not z3libs or not (languages / 'x86.ldefs').is_file():
        raise ValueError('Missing native Z3 runtime or x86 language specifications')
    destination = prefix / 'lib/re-cli'
    command = prefix / 'bin/re-'
    # Refuse to replace unrelated commands, even with an otherwise valid prefix.
    if os.path.lexists(command) and not (command.is_symlink()
            and command.resolve() == (destination / 'bin/re-').resolve()):
        raise ValueError(f'Existing unrelated command would be overwritten: {command}')
    for path in (HERE, repo):
        if destination == path or destination in path.parents or path in destination.parents:
            raise ValueError('Install prefix must be outside the source checkout')

    def copy(src, relative):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        # Replace rather than truncate an analyzer that may still be running.
        fd, temporary = tempfile.mkstemp(prefix='.' + target.name + '.', dir=target.parent)
        os.close(fd)
        try:
            shutil.copy2(src, temporary)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    for name in ('re_cli.py', 'inventory.py', 'bin/re-'):
        copy(HERE / name, name)
    native = Path('backend/research/graph_fibers/cpp')
    for name in binaries:
        copy(source / 'build' / name, native / 'build' / name)
    copy(source / 'extract_bun_static.py', native / 'extract_bun_static.py')
    for lib in z3libs:
        copy(lib, native / '.deps/z3/lib' / lib.name)
    for spec in (source / '.deps/spec').glob('*.sla'):
        copy(spec, native / '.deps/spec' / spec.name)
    for spec in specs:
        copy(spec, Path('backend/Ghidra/Processors/x86/data/languages') / spec.name)
    (destination / 'bin/re-').chmod(0o755)
    command.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.re-.', dir=command.parent)
    os.close(fd)
    os.unlink(temporary)
    try:
        os.symlink('../lib/re-cli/bin/re-', temporary)
        os.replace(temporary, command)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    print(f'Installed command: {command}')
    if str(command.parent) not in os.environ.get('PATH', '').split(os.pathsep):
        print(f'Add {command.parent} to PATH to invoke re- directly.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path.home() / '.local')
    parser.add_argument('--repo', type=Path, default=HERE.parents[1])
    args = parser.parse_args()
    try:
        install(args.prefix.expanduser().resolve(), args.repo.resolve())
    except (OSError, ValueError) as error:
        print(f'Install failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
