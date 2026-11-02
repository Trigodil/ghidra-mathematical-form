"""Standalone, resumable application-folder frontend for the native Ghidra research tools."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE / 'backend' if (HERE / 'backend').is_dir() else HERE.parents[1]
VERSION = '0.1.0'
CHILDREN = set()
CHILD_LOCK = threading.Lock()
STOP = threading.Event()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def within(path, parent):
    return path == parent or parent in path.parents


def stop_children():
    STOP.set()
    with CHILD_LOCK:
        for process in list(CHILDREN):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def run(command, folder, timeout, memory, cpu=None, env=None, marker=False, cwd=HERE):
    folder.mkdir(parents=True, exist_ok=True)
    mark = folder / 'sandbox-active.json'
    mark.unlink(missing_ok=True)
    command = ['/usr/bin/prlimit', f'--as={memory * 1024 * 1024}',
               f'--cpu={cpu or max(1, math.ceil(timeout))}', '--fsize=536870912',
               '--nofile=96', '--core=0', '--', *map(str, command)]
    start = time.monotonic()
    with (folder / 'analysis.log').open('w') as log:
        with CHILD_LOCK:
            if STOP.is_set():
                return dict(status='interrupted')
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=env or {'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                       cwd=cwd, start_new_session=True)
            CHILDREN.add(process)
        try:
            code = process.wait(timeout=timeout)
            status = 'ok' if code == 0 else 'failed'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            status = 'timeout'
        finally:
            with CHILD_LOCK:
                CHILDREN.discard(process)
    if STOP.is_set():
        status = 'interrupted'
    elif marker and not mark.exists():
        status = 'sandbox_failed'
    return dict(status=status, exit_code=code, seconds=round(time.monotonic() - start, 3),
                log=str(folder / 'analysis.log'))


def scan(target, output):
    """Do not follow links, FIFOs, devices or directories inside output."""
    paths, skipped = [], []
    def check(path):
        try:
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                skipped.append(dict(path=str(path), reason='symlink or special file'))
                return
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic == b'\x7fELF':
                paths.append(path)
            elif magic[:2] == b'MZ' or magic in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                      b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe',
                      b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
                skipped.append(dict(path=str(path), reason='unsupported binary format (PE/Mach-O/fat)'))
        except OSError as error:
            skipped.append(dict(path=str(path), reason=str(error)))
    if target.is_file():
        check(target)
    else:
        def onerror(error):
            skipped.append(dict(path=error.filename, reason=str(error)))
        for root, dirs, files in os.walk(target, followlinks=False, onerror=onerror):
            keep = []
            for name in sorted(dirs):
                path = Path(root) / name
                if path.is_symlink():
                    skipped.append(dict(path=str(path), reason='symlink directory'))
                elif not within(path, output):
                    keep.append(name)
            dirs[:] = keep
            for name in sorted(files):
                check(Path(root) / name)
    return paths, skipped


class Workflow:
    def __init__(self, args):
        self.args = args
        self.repo = args.repo.resolve()
        self.backend = self.repo / 'research/graph_fibers/cpp'
        self.output = args.output.resolve()
        if within(self.output, self.repo):
            raise ValueError('Output must be outside the checkout')
        # Fail early instead of implicitly building/writing into the checkout.
        self.tools = {name: self.backend / 'build' / name for name in
                      ('core-decompile', 'analysis-lockdown.so', 'native-audit')}
        for path in [*self.tools.values(), self.backend / '.deps/spec/x86-64.sla']:
            if not path.is_file():
                raise ValueError(f'Missing prepared backend: {path}')
        if not Path('/usr/bin/objdump').is_file():
            raise ValueError('Missing /usr/bin/objdump (binutils)')
        self.specs = self.output / 'specs'
        self.runtime = self.output / 'runtime'
        languages = self.repo / 'Ghidra/Processors/x86/data/languages'
        sources = [p for pattern in ('*.ldefs', '*.pspec', '*.cspec') for p in languages.glob(pattern)]
        sources += list((self.backend / '.deps/spec').glob('*.sla'))
        if not sources or not (languages / 'x86.ldefs').exists():
            raise ValueError('Missing x86 language specifications')
        fingerprint = hashlib.sha256()
        for source in sorted([*sources, *self.tools.values(), HERE / 're_cli.py', HERE / 'inventory.py',
                              Path('/usr/bin/objdump')]):
            fingerprint.update(str(source).encode())
            fingerprint.update(bytes.fromhex(digest(source)))
        self.spec_sources = sources
        self.identity = fingerprint.hexdigest()

    def prepare(self):
        self.specs.mkdir(exist_ok=True)
        self.runtime.mkdir(exist_ok=True)
        for source in self.spec_sources:
            shutil.copyfile(source, self.specs / source.name)
        # LD_PRELOAD splits absolute filenames at spaces. A relative filename
        # in a dedicated working directory also works when output has spaces.
        shutil.copyfile(self.tools['analysis-lockdown.so'], self.runtime / 'analysis-lockdown.so')

    def restricted(self, command, source, folder, timeout=None):
        env = dict(PATH='/usr/bin:/bin', LANG='C', LD_PRELOAD='./analysis-lockdown.so',
                   ANALYSIS_INPUT=str(source), ANALYSIS_SPEC=str(self.specs),
                   ANALYSIS_OUTPUT=str(folder), ANALYSIS_MARKER=str(folder / 'sandbox-active.json'))
        # Apply LD_PRELOAD to the analyzer, after prlimit (not to prlimit itself).
        command = ['/usr/bin/env', '-i', *(f'{k}={v}' for k, v in env.items()), *map(str, command)]
        return run(command, folder, timeout or self.args.function_timeout, self.args.memory_mb,
                   cpu=self.args.cpu_seconds if timeout is None else None, marker=True, cwd=self.runtime)

    def analyze(self, source):
        sha = digest(source)
        key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
        folder = self.output / 'binaries' / key
        folder.mkdir(parents=True, exist_ok=True)
        settings = dict(backend=self.identity, sha256=sha, timeout=self.args.function_timeout,
                        cpu=self.args.cpu_seconds, memory=self.args.memory_mb,
                        symbolic=self.args.symbolic, stage_timeout=self.args.stage_timeout)
        fingerprint = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()
        # Separate generations prevent stale source/artifacts after inputs/options change.
        folder = folder / fingerprint[:16]
        folder.mkdir(parents=True, exist_ok=True)
        result = dict(path=str(source), sha256=sha, output=str(folder), target_executed=False)
        print(f'[binary] {source}', flush=True)
        inv = folder / 'inventory'
        check = run([sys.executable, HERE / 'inventory.py', source, inv,
                     self.tools['analysis-lockdown.so']], inv, self.args.stage_timeout, self.args.memory_mb)
        result['inventory'] = check
        if check['status'] != 'ok':
            result['status'] = 'failed'
            save(folder / 'report.json', result)
            return result
        inventory = json.loads((inv / 'inventory.json').read_text())
        tasks = inventory['functions']
        result.update(executable_bytes=inventory['executable_bytes'],
                      named_code_bytes=inventory['named_code_bytes'], functions_discovered=len(tasks),
                      ambiguous_names=inventory['ambiguous_names'], whole_binary_recovered=False)
        # Keep an assembly view of executable sections, including stripped code
        # outside named sized function ranges. This does not infer function bounds.
        assembly = folder / 'assembly'
        result['assembly'] = self.restricted(['/usr/bin/objdump', '-d', '-w', '--', source],
                                              source, assembly, self.args.stage_timeout)
        # Decode every named range; this is distinct from decompilation success.
        decode = folder / 'decoder'
        result['decoder'] = self.restricted([self.tools['native-audit'], 'decode', source,
            self.specs / 'x86-64.sla', decode], source, decode, self.args.stage_timeout)
        if inventory['bun']:
            bun = folder / 'bun'
            result['bun_extraction'] = run([sys.executable, self.backend / 'extract_bun_static.py',
                '--binary', source, '--output', bun, '--lockdown', self.tools['analysis-lockdown.so']],
                bun, self.args.stage_timeout, self.args.memory_mb)

        def work(item):
            out = folder / 'functions' / f'{item["address"]:x}'
            checkpoint = out / 'result.json'
            if checkpoint.exists() and not self.args.fresh:
                row = json.loads(checkpoint.read_text())
                if (row.get('fingerprint') == fingerprint and row.get('status') == 'ok'
                        and (out / 'decompiled.c').is_file()):
                    row['resumed'] = True
                    return row
            row = dict(**item, fingerprint=fingerprint)
            (out / 'decompiled.c').unlink(missing_ok=True)
            row['decompile'] = self.restricted([self.tools['core-decompile'], source, self.specs,
                                                item['name'], out], source, out)
            row['status'] = row['decompile']['status']
            if row['status'] == 'ok' and not (out / 'decompiled.c').is_file():
                row['status'] = 'missing_pseudocode'
            if self.args.symbolic:
                symbolic = out / 'symbolic'
                row['symbolic'] = self.restricted([self.tools['native-audit'], 'lift', source,
                    self.specs / 'x86-64.sla', symbolic, item['name']], source, symbolic)
                if row['symbolic']['status'] != 'ok':
                    row['status'] = 'partial'
            save(checkpoint, row)
            return row

        rows = []
        pool = ThreadPoolExecutor(max_workers=self.args.jobs)
        try:
            # Bound queued work as well as active processes for very large inputs.
            for offset in range(0, len(tasks), self.args.jobs * 4):
                futures = [pool.submit(work, item) for item in tasks[offset:offset + self.args.jobs * 4]]
                for future in as_completed(futures):
                    rows.append(future.result())
                    if len(rows) % 16 == 0 or len(rows) == len(tasks):
                        print(f'[functions] {len(rows)}/{len(tasks)}', flush=True)
        except BaseException:
            stop_children()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        result['functions'] = sorted(rows, key=lambda row: row['address'])
        result['pseudocode_emitted'] = sum(row.get('decompile', {}).get('status') == 'ok' for row in rows)
        result['resumed_functions'] = sum(row.get('resumed', False) for row in rows)
        result['target_unchanged'] = digest(source) == sha
        incomplete = (not tasks or inventory['named_code_bytes'] < inventory['executable_bytes']
                      or any(row['status'] != 'ok' for row in rows) or not result['target_unchanged']
                      or result['assembly']['status'] != 'ok'
                      or result['decoder']['status'] != 'ok' or bool(inventory['ambiguous_names'])
                      or result.get('bun_extraction', {}).get('status', 'ok') != 'ok')
        result['status'] = 'partial' if incomplete else 'ok'
        result['limits'] = ['Named sized functions only; stripped/unsymbolized code is not decompiled.',
                           'Executable-section assembly is linear disassembly, not recovered source or flow coverage.',
                           'Pseudocode is heuristic; original source and equivalence are not established.',
                           'External dependencies and files behind symlinks are outside this scan.',
                           'PE, Mach-O, non-x86-64 and archive contents are not supported.']
        save(folder / 'report.json', result)
        return result


def main(argv=None):
    STOP.clear()
    parser = argparse.ArgumentParser(prog='re-', description=__doc__,
        epilog='Example: re- /path/to/application folder\n'
               'Space-separated folder words are joined. Shell metacharacters still use normal shell escaping.\n'
               'Exit codes: 0 supported work completed; 1 error; 2 partial/unsupported results; 130 interrupted.\n'
               'This launches static analysis, not the application. Requires Linux and the prepared native backend.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('folder', nargs='+', help='Application folder (or single ELF binary)')
    parser.add_argument('--repo', type=Path, default=Path(os.environ.get('RE_REPO', DEFAULT_REPO)))
    parser.add_argument('-o', '--output', type=Path, help='Results directory outside the checkout')
    parser.add_argument('-j', '--jobs', type=int, default=2)
    parser.add_argument('--function-timeout', type=float, default=30)
    parser.add_argument('--cpu-seconds', type=int, default=20)
    parser.add_argument('--stage-timeout', type=float, default=300)
    parser.add_argument('--memory-mb', type=int, default=2048, help='Per-worker memory ceiling')
    parser.add_argument('--symbolic', action='store_true', help='Also attempt generic GPR/RAM symbolic lifting')
    parser.add_argument('--fresh', action='store_true', help='Retry functions instead of resuming successful work')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    if (args.jobs < 1 or args.cpu_seconds < 1 or args.memory_mb < 128
            or not math.isfinite(args.function_timeout) or args.function_timeout <= 0
            or not math.isfinite(args.stage_timeout) or args.stage_timeout <= 0):
        parser.error('Jobs/CPU/timeouts must be positive and memory must be at least 128 MiB')
    target = Path(' '.join(args.folder)).expanduser().absolute()
    if not target.exists() or target.is_symlink():
        parser.error('Application path must exist and must not itself be a symlink')
    target = target.resolve()
    if not target.is_file() and not target.is_dir():
        parser.error('Application path must be a regular file or directory')
    if args.output is None:
        tag = hashlib.sha256(str(target).encode()).hexdigest()[:12]
        base = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state'))
        args.output = base / 're-cli' / f'{target.name}-{tag}'
    if within(target, args.output.resolve()):
        parser.error('Output must not contain the input path')
    try:
        workflow = Workflow(args)
        # One writer per output directory; the lock is automatically released on exit.
        import fcntl
        workflow.output.mkdir(parents=True, exist_ok=True)
        with (workflow.output / '.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another re- process is already writing to this output')
            workflow.prepare()
            paths, skipped = scan(target, workflow.output)
            report = dict(input=str(target), version=VERSION, binaries=[], skipped=skipped,
                          target_executed=False, whole_application_recovered=False, status='running')
            save(workflow.output / 'report.json', report)
            print(f'[scan] {len(paths)} ELF files; {len(skipped)} skipped; results: {workflow.output}', flush=True)
            for source in paths:
                try:
                    result = workflow.analyze(source)
                except (OSError, ValueError) as error:
                    result = dict(path=str(source), status='failed', error=str(error))
                report['binaries'].append(result)
                save(workflow.output / 'report.json', report)
            report['status'] = 'partial' if (not paths or skipped or any(
                row['status'] != 'ok' for row in report['binaries'])) else 'ok'
            save(workflow.output / 'report.json', report)
            print(f'[{report["status"]}] Report: {workflow.output / "report.json"}', flush=True)
            return 0 if report['status'] == 'ok' else 2
    except KeyboardInterrupt:
        stop_children()
        if args.output and (args.output / 'report.json').exists():
            report = json.loads((args.output / 'report.json').read_text())
            report['status'] = 'interrupted'
            save(args.output / 'report.json', report)
        print('Interrupted. Completed function checkpoints are retained; rerun to resume.', file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f're-: {error}', file=sys.stderr)
        return 1
