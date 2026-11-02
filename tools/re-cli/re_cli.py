"""Standalone, resumable application-folder frontend for the native Ghidra research tools."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import os
import re
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
VERSION = '0.1.2'
CHILDREN = set()
CHILD_LOCK = threading.Lock()
STOP = threading.Event()
PRINT_LOCK = threading.Lock()
ACTIVE_PROGRESS = None


class FunctionProgress:
    def __init__(self, total):
        self.total = total
        self.done = self.succeeded = self.issues = 0
        self.tty = sys.stdout.isatty() and os.environ.get('TERM') != 'dumb'

    def line(self):
        columns = shutil.get_terminal_size(fallback=(100, 24)).columns
        width = max(1, min(24, columns - 75))
        fraction = self.done / self.total if self.total else 1
        filled = int(width * fraction)
        bar = '#' * filled + '-' * (width - filled)
        text = (f'[progress] [{bar}] {self.done}/{self.total} functions; {100 * fraction:.1f}% '
                f'| ok: {self.succeeded} | issues: {self.issues}')
        return text[:max(1, columns - 1)] if self.tty else text

    def draw(self):
        sys.stdout.write('\r\x1b[2K' + self.line())
        sys.stdout.flush()

    def start(self):
        global ACTIVE_PROGRESS
        with PRINT_LOCK:
            if self.tty:
                ACTIVE_PROGRESS = self
                self.draw()
            else:
                print(self.line(), flush=True)

    def update(self, row):
        with PRINT_LOCK:
            self.done += 1
            self.succeeded += row['status'] == 'ok'
            self.issues += row['status'] != 'ok'
            if self.tty:
                self.draw()
            else:
                print(self.line(), flush=True)

    def close(self):
        global ACTIVE_PROGRESS
        with PRINT_LOCK:
            if ACTIVE_PROGRESS is self:
                self.draw()
                sys.stdout.write('\n')
                sys.stdout.flush()
                ACTIVE_PROGRESS = None


def emit(message):
    # Binary-provided names/logs must not inject terminal control sequences.
    message = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', str(message))
    message = ''.join(ch if ch == '\t' or (ch.isprintable() and ch not in '\r\n')
                      else '?' for ch in message)
    with PRINT_LOCK:
        if ACTIVE_PROGRESS:
            sys.stdout.write('\r\x1b[2K')
        print(message, flush=True)
        if ACTIVE_PROGRESS:
            ACTIVE_PROGRESS.draw()


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


def run(command, folder, timeout, memory, cpu=None, env=None, marker=False, cwd=HERE, label=None):
    label = label or folder.name
    emit(f'[{label}] started')
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
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='replace',
                                       env=env or {'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                       cwd=cwd, start_new_session=True)
            CHILDREN.add(process)
        def relay():
            with process.stdout:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    emit(f'[{label}] {line.rstrip()}')
        reader = threading.Thread(target=relay, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
            status = 'ok' if code == 0 else 'failed'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            status = 'timeout'
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        finally:
            with CHILD_LOCK:
                CHILDREN.discard(process)
            reader.join()
    if STOP.is_set():
        status = 'interrupted'
    elif marker and not mark.exists():
        status = 'sandbox_failed'
    elapsed = round(time.monotonic() - start, 3)
    emit(f'[{label}] {status}; exit={code}; {elapsed:.3f}s; log: {folder / "analysis.log"}')
    return dict(status=status, exit_code=code, seconds=elapsed,
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
                      ('core-decompile', 'analysis-lockdown.so', 'native-audit', 'native-discover')}
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

    def restricted(self, command, source, folder, timeout=None, label=None):
        env = dict(PATH='/usr/bin:/bin', LANG='C', LD_PRELOAD='./analysis-lockdown.so',
                   ANALYSIS_INPUT=str(source), ANALYSIS_SPEC=str(self.specs),
                   ANALYSIS_OUTPUT=str(folder), ANALYSIS_MARKER=str(folder / 'sandbox-active.json'))
        # Apply LD_PRELOAD to the analyzer, after prlimit (not to prlimit itself).
        command = ['/usr/bin/env', '-i', *(f'{k}={v}' for k, v in env.items()), *map(str, command)]
        return run(command, folder, timeout or self.args.function_timeout, self.args.memory_mb,
                   cpu=self.args.cpu_seconds if timeout is None else None, marker=True, cwd=self.runtime,
                   label=label)

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
        emit(f'[binary] {source}')
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
        discovery = folder / 'recursive-discovery'
        discovery.mkdir(parents=True, exist_ok=True)
        (discovery / 'seeds.txt').write_text(''.join(f'{row["address"]:x}\n' for row in tasks
                                                     if row['file_backed_code']))
        result['recursive_discovery'] = self.restricted([self.tools['native-discover'], source,
            self.specs / 'x86-64.sla', discovery / 'seeds.txt', discovery, '2000000'],
            source, discovery, self.args.stage_timeout)
        if result['recursive_discovery']['status'] == 'ok':
            stats = json.loads((discovery / 'recursive-stats.json').read_text())
            inventory['discovery']['recursive'] = stats
            known = {row['address']: row for row in tasks}
            for line in (discovery / 'recursive.tsv').read_text().splitlines()[1:]:
                address_text, caller_text = line.split('\t')
                address, caller = int(address_text, 16), int(caller_text, 16)
                if address not in known:
                    row = dict(address=address, name=f'sub_{address:x}', size=0,
                               file_backed_code=True, selector=f'@0x{address:x}',
                               provenance=['direct_call'], discovered_from=caller)
                    tasks.append(row); known[address] = row
                elif 'direct_call' not in known[address]['provenance']:
                    known[address]['provenance'].append('direct_call')
            tasks.sort(key=lambda row: (row['address'], row['name']))
            inventory['discovery']['direct_call'] = sum('direct_call' in row['provenance'] for row in tasks)
            if stats['truncated'] or stats['decode_errors']:
                inventory['discovery']['warnings'].append('Recursive discovery was truncated or encountered decode errors')
        else:
            inventory['discovery']['warnings'].append('Recursive discovery stage failed or timed out')
        result.update(executable_bytes=inventory['executable_bytes'],
                      named_code_bytes=inventory['named_code_bytes'], functions_discovered=len(tasks),
                      ambiguous_names=inventory['ambiguous_names'], discovery=inventory.get('discovery', {}),
                      whole_binary_recovered=False)
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
                    emit(f'[function {item["name"]} @ 0x{item["address"]:x}] resumed successful result')
                    return row
            row = dict(**item, fingerprint=fingerprint)
            (out / 'decompiled.c').unlink(missing_ok=True)
            row['decompile'] = self.restricted([self.tools['core-decompile'], source, self.specs,
                                                item.get('selector', item['name']), out], source, out,
                                                label=f'decompile {item["name"]} @ 0x{item["address"]:x}')
            row['status'] = row['decompile']['status']
            if row['status'] == 'ok' and not (out / 'decompiled.c').is_file():
                row['status'] = 'missing_pseudocode'
            if self.args.symbolic:
                if item.get('selector', item['name']).startswith('@0x'):
                    row['symbolic'] = dict(status='unsupported', reason='Symbolic lifting requires a named, sized ELF symbol')
                    if row['status'] == 'ok':
                        row['status'] = 'partial'
                else:
                    symbolic = out / 'symbolic'
                    row['symbolic'] = self.restricted([self.tools['native-audit'], 'lift', source,
                        self.specs / 'x86-64.sla', symbolic, item['name']], source, symbolic,
                        label=f'symbolic {item["name"]} @ 0x{item["address"]:x}')
                    if row['symbolic']['status'] != 'ok':
                        row['status'] = 'partial'
            emit(f'[function {item["name"]} @ 0x{item["address"]:x}] {row["status"]}')
            save(checkpoint, row)
            return row

        rows = []
        pool = ThreadPoolExecutor(max_workers=self.args.jobs)
        progress = FunctionProgress(len(tasks))
        progress.start()
        try:
            # Bound queued work as well as active processes for very large inputs.
            for offset in range(0, len(tasks), self.args.jobs * 4):
                futures = [pool.submit(work, item) for item in tasks[offset:offset + self.args.jobs * 4]]
                for future in as_completed(futures):
                    rows.append(future.result())
                    progress.update(rows[-1])
        except BaseException:
            stop_children()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
            progress.close()
        result['functions'] = sorted(rows, key=lambda row: row['address'])
        result['pseudocode_emitted'] = sum(row.get('decompile', {}).get('status') == 'ok' for row in rows)
        result['resumed_functions'] = sum(row.get('resumed', False) for row in rows)
        result['target_unchanged'] = digest(source) == sha
        incomplete = (not tasks or inventory['named_code_bytes'] < inventory['executable_bytes']
                      or any(row['status'] != 'ok' for row in rows) or not result['target_unchanged']
                      or result['assembly']['status'] != 'ok'
                      or result['decoder']['status'] != 'ok' or bool(inventory['ambiguous_names'])
                      or bool(inventory.get('discovery', {}).get('warnings'))
                      or result.get('bun_extraction', {}).get('status', 'ok') != 'ok')
        result['status'] = 'partial' if incomplete else 'ok'
        result['limits'] = ['Recursive discovery follows direct calls and reachable branches within budgets; indirect transfers and tail calls remain unresolved, and unnamed function sizes are unknown.',
                           'Executable-section assembly is linear disassembly, not recovered source or flow coverage.',
                           'Pseudocode is heuristic; original source and equivalence are not established.',
                           'External dependencies and files behind symlinks are outside this scan.',
                           'PE, Mach-O, non-x86-64 and archive contents are not supported.']
        save(folder / 'report.json', result)
        return result


def print_summary(report, elapsed):
    binaries = report['binaries']
    counts = dict(succeeded=0, failed=0, timed_out=0, partial=0, interrupted=0)
    resumed = emitted = total = 0
    stages = []
    for binary in binaries:
        rows = binary.get('functions', [])
        total += len(rows)
        resumed += sum(bool(row.get('resumed')) for row in rows)
        emitted += binary.get('pseudocode_emitted', 0)
        stages.extend(binary[name] for name in ('inventory', 'assembly', 'decoder', 'bun_extraction')
                      if name in binary)
        for row in rows:
            stages.extend(row[name] for name in ('decompile', 'symbolic') if name in row)
            decompile = row.get('decompile', {}).get('status', row['status'])
            if decompile == 'timeout':
                category = 'timed_out'
            elif decompile == 'interrupted':
                category = 'interrupted'
            elif decompile != 'ok' or row['status'] == 'missing_pseudocode':
                category = 'failed'
            elif row['status'] == 'ok':
                category = 'succeeded'
            else:
                category = 'partial'
            counts[category] += 1
        executable = binary.get('executable_bytes', 0)
        named = binary.get('named_code_bytes', 0)
        emit(f'[binary result] {binary["path"]}: {binary["status"]}; '
             f'{binary.get("pseudocode_emitted", 0)}/{len(rows)} pseudocode files; '
             f'named code {named}/{executable} bytes')
    emit('=== Final summary ===')
    emit(f'Binaries: {len(binaries)} total | '
         f'{sum(b["status"] == "ok" for b in binaries)} succeeded | '
         f'{sum(b["status"] == "partial" for b in binaries)} partial | '
         f'{sum(b["status"] == "failed" for b in binaries)} failed')
    emit(f'Functions: {total} total | {counts["succeeded"]} succeeded | '
         f'{counts["failed"]} failed | {counts["timed_out"]} timed out | '
         f'{counts["partial"]} partial | {counts["interrupted"]} interrupted')
    emit(f'Analysis stages: {sum(s["status"] == "ok" for s in stages)} succeeded | '
         f'{sum(s["status"] not in ("ok", "timeout", "interrupted") for s in stages)} failed | '
         f'{sum(s["status"] == "timeout" for s in stages)} timed out | '
         f'{sum(s["status"] == "interrupted" for s in stages)} interrupted')
    emit(f'Pseudocode files: {emitted} | Resumed functions: {resumed} | '
         f'Skipped files/directories: {len(report["skipped"])} | Elapsed: {elapsed:.2f}s')
    emit('Function totals cover named and discovered entry candidates; other code may remain undiscovered.')


def main(argv=None):
    STOP.clear()
    started = time.monotonic()
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
            emit(f'[scan] {len(paths)} ELF files; {len(skipped)} skipped; results: {workflow.output}')
            for item in skipped:
                emit(f'[skipped] {item["path"]}: {item["reason"]}')
            for source in paths:
                try:
                    result = workflow.analyze(source)
                except (OSError, ValueError) as error:
                    result = dict(path=str(source), status='failed', error=str(error))
                    emit(f'[error] {source}: {error}')
                report['binaries'].append(result)
                save(workflow.output / 'report.json', report)
            report['status'] = 'partial' if (not paths or skipped or any(
                row['status'] != 'ok' for row in report['binaries'])) else 'ok'
            save(workflow.output / 'report.json', report)
            print_summary(report, time.monotonic() - started)
            emit(f'[{report["status"]}] Report: {workflow.output / "report.json"}')
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
