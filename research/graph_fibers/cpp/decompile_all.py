#!/usr/bin/env python3
"""One-command static decompilation audit. Never executes the input executable.

Builds this checkout (including RulePeelMultiRegion), runs its focused tests,
extracts the Bun graph, decodes/decompiles every named native function, checks
candidate summaries, and records unsupported/limited work explicitly.
Completed stages are resumed only when their input/source fingerprint matches.
"""
import argparse
import collections
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import errno
import hashlib
import json
import math
import mmap
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
CORE = REPO/'Ghidra/Features/Decompiler/src/decompile/cpp'
KNOWN_TARGET = 'fd13c70000fec3f2116dfbcbb6121210b4a29328bf0e46210a59dd594a67d824'


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(path)


def selftest(args):
    """Run in a separate process; never apply Landlock to the supervisor."""
    output = args.output.resolve()
    library = ctypes.CDLL(str(ROOT/'build/analysis-lockdown.so'))
    library.analysis_lockdown.argtypes = [ctypes.c_char_p]*3
    library.analysis_lockdown(os.fsencode(args.binary.resolve()), b'', os.fsencode(output))
    checks = {}

    def deny(name, operation):
        try:
            operation()
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EROFS):
                raise
            checks[name] = 'blocked'
        else:
            raise RuntimeError(name+' unexpectedly allowed')

    deny('network', lambda: socket.socket())
    deny('unrelated_read', lambda: open('/etc/passwd', 'rb'))
    deny('target_write', lambda: os.open(args.binary, os.O_WRONLY))
    deny('outside_write', lambda: open(ROOT/'build/forbidden-audit-write', 'w'))
    deny('exec_benign_true', lambda: os.execve('/usr/bin/true', ['true'], {}))
    deny('fork', os.fork)
    deny('executable_mapping', lambda: mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_EXEC))
    with args.binary.open('rb') as f:
        if f.read(4) != b'\x7fELF':
            raise RuntimeError('Expected ELF')
    checks['input_read'] = 'allowed'
    save(output/'selftest.json', checks)


class Audit:
    def __init__(self, args):
        self.args = args
        self.target = args.binary.resolve()
        self.output = args.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.logs = self.output/'logs'
        self.logs.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self.children = set()
        self.stages = {}
        self.started = time.monotonic()
        self.target_hash = digest(self.target)
        self.source_hash = hashlib.sha256()
        sources = list(CORE.glob('*.cc'))+list(CORE.glob('*.hh'))+list(ROOT.glob('*.py'))
        sources += list(ROOT.glob('*.cpp'))+list(ROOT.glob('*.hpp'))+list(ROOT.glob('*.c'))
        sources += [ROOT/'validate_extracted_js.cjs', CORE.parent/'unittests/testpeelregion.cc',
                    ROOT/'.deps/spec/x86-64.sla']
        for source in sorted(sources):
            self.source_hash.update(str(source).encode())
            self.source_hash.update(bytes.fromhex(digest(source)))
        self.fingerprint = hashlib.sha256(json.dumps(dict(target=self.target_hash,
            sources=self.source_hash.hexdigest(), cpu=args.cpu_seconds, wall=args.function_timeout,
            summary_timeout=args.summary_timeout_ms), sort_keys=True).encode()).hexdigest()
        save(self.output/'provenance.json', dict(binary=str(self.target), sha256=self.target_hash,
            source_fingerprint=self.source_hash.hexdigest(), fingerprint=self.fingerprint,
            target_executed=False, scope='Named native functions and stored Bun graph; not all native code is symbolized.'))

    def run(self, command, log, timeout=600, environment=None, sandbox=None, cpu=None):
        log = Path(log)
        log.parent.mkdir(parents=True, exist_ok=True)
        env = {'PATH':'/usr/bin:/bin', 'LANG':'C'}
        if environment:
            env.update(environment)
        marker = None
        if sandbox:
            source, spec, destination, runtime = sandbox
            destination = Path(destination).resolve()
            destination.mkdir(parents=True, exist_ok=True)
            marker = destination/'sandbox-active.json'
            marker.unlink(missing_ok=True)
            restricted = dict(LD_PRELOAD='./build/analysis-lockdown.so',
                ANALYSIS_INPUT=str(source), ANALYSIS_SPEC=str(spec),
                ANALYSIS_OUTPUT=str(destination), ANALYSIS_MARKER=str(marker))
            if runtime:
                restricted['ANALYSIS_RUNTIME'] = str(runtime)
            command = ['/usr/bin/env', '-i']+[f'{k}={v}' for k,v in {**env, **restricted}.items()]+list(command)
            env = {'PATH':'/usr/bin:/bin', 'LANG':'C'}
        # Launch trusted programs only. The target path is never argv[0].
        command = ['/usr/bin/prlimit', '--as=2147483648',
                   f'--cpu={cpu or max(1, math.ceil(timeout))}', '--fsize=536870912',
                   '--nofile=96', '--core=0', '--']+[str(x) for x in command]
        begin = time.monotonic()
        with log.open('w') as stream:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            with self.lock:
                self.children.add(process)
            try:
                code = process.wait(timeout=timeout)
                result = dict(exit_code=code, status='ok' if code==0 else 'failed')
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                result = dict(exit_code=None, status='wall_time_limit')
            except BaseException:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
            finally:
                with self.lock:
                    self.children.discard(process)
        result['seconds'] = round(time.monotonic()-begin, 3)
        result['log'] = str(log)
        if marker is not None and not marker.exists():
            result['status'] = 'sandbox_not_installed'
        return result

    def stage(self, name, work):
        checkpoint = self.output/(name+'.stage.json')
        if checkpoint.exists() and not self.args.fresh:
            cached = json.loads(checkpoint.read_text())
            if cached.get('fingerprint') == self.fingerprint and cached.get('completed'):
                print(f'[{name}] reused completed result', flush=True)
                self.stages[name] = cached['result']
                return cached['result']
        print(f'[{name}] running', flush=True)
        result = work()
        self.stages[name] = result
        save(checkpoint, dict(fingerprint=self.fingerprint, completed=True, result=result))
        print(f'[{name}] finished', flush=True)
        return result

    def build(self):
        result = self.run(['make', '-f', 'Makefile', '-f', 'audit.mk', f'-j{self.args.jobs}',
                          'build/native-audit', 'build/abi-summary', 'build/analysis-lockdown.so'],
                         self.logs/'build-tools.log', timeout=1200)
        if result['status'] != 'ok':
            raise RuntimeError('Native tool build failed: '+result['log'])
        text = (CORE/'Makefile').read_text().replace('\\\n', ' ')
        deccore = re.search(r'^DECCORE=(.*)$', text, re.M).group(1)
        names = [x for x in deccore.split() if not x.startswith('$')]
        names += ['xml_arch','loadimage_xml','sleigh_arch','inject_sleigh','libdecomp']
        directory = ROOT/'build/core-audit-objects'
        directory.mkdir(exist_ok=True)
        header_time = max(p.stat().st_mtime for p in CORE.glob('*.hh'))
        flags = ['g++','-O1','-g0','-std=c++17','-Wno-sign-compare', '-I'+str(CORE),
                 '-I'+str(ROOT/'.deps/zlib'), '-isystem',str(ROOT/'.deps/z3/include')]

        def compile_one(name):
            source = CORE/(name+'.cc')
            obj = directory/(name+'.o')
            if not obj.exists() or obj.stat().st_mtime < max(header_time, source.stat().st_mtime):
                check = self.run(flags+['-c',str(source),'-o',str(obj)], self.logs/('compile-'+name+'.log'), timeout=300)
                if check['status'] != 'ok':
                    raise RuntimeError('Core build failed: '+check['log'])
            return obj

        objects = []
        with ThreadPoolExecutor(max_workers=self.args.jobs) as pool:
            futures = [pool.submit(compile_one, name) for name in dict.fromkeys(names)]
            for future in as_completed(futures):
                objects.append(future.result())
                if len(objects)%16==0:
                    print(f'[build] core objects {len(objects)}/{len(futures)}', flush=True)
        common = [str(x) for x in objects]+[str(ROOT/'build/libsleigh.a'),
                  '-L'+str(ROOT/'.deps/z3/lib'), '-Wl,-rpath,$ORIGIN/../.deps/z3/lib',
                  '-lz3','-l:libz.so.1']
        for name, sources in [('core-decompile',[ROOT/'core_decompile.cpp']),
                              ('core-tests',[ROOT/'core_test_main.cpp', CORE.parent/'unittests/testpeelregion.cc'])]:
            check = self.run(flags+[str(x) for x in sources]+common+['-o',str(ROOT/'build'/name)],
                             self.logs/('link-'+name+'.log'),timeout=300)
            if check['status'] != 'ok':
                raise RuntimeError('Core link failed: '+check['log'])
        specs = self.output/'specs'
        specs.mkdir(exist_ok=True)
        languages = REPO/'Ghidra/Processors/x86/data/languages'
        for pattern in ('*.ldefs','*.pspec','*.cspec'):
            for path in languages.glob(pattern):
                shutil.copyfile(path, specs/path.name)
        for path in (ROOT/'.deps/spec').glob('*.sla'):
            shutil.copyfile(path, specs/path.name)
        return dict(status='ok', core_objects=len(objects), specs=str(specs))

    def restrictions(self):
        destination = self.output/'restrictions'
        destination.mkdir(exist_ok=True)
        check = self.run([sys.executable,__file__,'--_selftest','--binary',self.target,'--output',destination],
                         self.logs/'restrictions.log',timeout=30)
        if check['status']!='ok' or not (destination/'selftest.json').exists():
            raise RuntimeError('Restriction verification failed: '+check['log'])
        return json.loads((destination/'selftest.json').read_text())

    def core_tests(self):
        output = self.output/'core-tests'
        check = self.run([ROOT/'build/core-tests',self.output/'specs'],self.logs/'core-tests.log',
            timeout=120,sandbox=(self.target,self.output/'specs',output,None))
        check['transcript'] = Path(check['log']).read_text()
        # Do not hide regressions, but still collect target results if tests fail.
        return check

    def extraction(self):
        output = self.output/'bun'
        check = self.run([sys.executable,ROOT/'extract_bun_static.py','--binary',self.target,
            '--output',output,'--lockdown',ROOT/'build/analysis-lockdown.so'],
            self.logs/'extraction.log',timeout=180)
        if check['status']!='ok':
            raise RuntimeError('Bun extraction failed: '+check['log'])
        return json.loads((output/'inventory.json').read_text())

    def decoder(self):
        output = self.output/'decoder'
        check = self.run([ROOT/'build/native-audit','decode',self.target,
            ROOT/'.deps/spec/x86-64.sla',output],self.logs/'decoder.log',timeout=300,
            sandbox=(self.target,ROOT/'.deps/spec/x86-64.sla',output,None))
        check['report'] = (output/'report.txt').read_text() if (output/'report.txt').exists() else ''
        return check

    def summaries(self):
        if self.target_hash!=KNOWN_TARGET:
            return dict(status='skipped',reason='The four candidate summaries are specific to the recorded 2.1.316 binary.')
        output = self.output/'summaries'
        check = self.run([ROOT/'build/abi-summary','--binary',self.target,'--sla',
            ROOT/'.deps/spec/x86-64.sla','--output',output,'--timeout-ms',str(self.args.summary_timeout_ms)],
            self.logs/'summaries.log',timeout=max(180,8*self.args.summary_timeout_ms/1000+60),
            sandbox=(self.target,ROOT/'.deps/spec/x86-64.sla',output,None))
        check['report'] = (output/'report.txt').read_text() if (output/'report.txt').exists() else ''
        return check

    def native_functions(self):
        inventory = json.loads((self.output/'bun/native_symbols.json').read_text())
        directory = self.output/'native'
        directory.mkdir(exist_ok=True)
        rows = {}
        log = directory/'functions.jsonl'
        if log.exists() and not self.args.fresh:
            for line in log.read_text().splitlines():
                try:
                    row = json.loads(line)
                    if row.get('fingerprint')==self.fingerprint:
                        rows[row['address']] = row
                except ValueError:
                    pass
        pending = [item for item in inventory if item['address'] not in rows]

        def attempt(item):
            result = dict(**item, fingerprint=self.fingerprint)
            out = directory/f'{item["address"]:x}'
            result['decompile'] = self.run([ROOT/'build/core-decompile',self.target,
                self.output/'specs',item['name'],out],out/'decompile.log',
                timeout=self.args.function_timeout, cpu=self.args.cpu_seconds,
                sandbox=(self.target,self.output/'specs',out,None))
            source = out/'decompiled.c'
            result['pseudocode_bytes'] = source.stat().st_size if source.exists() else 0
            transcript = (out/'decompile.log').read_text()
            match = re.search(r'peel_tests=(\d+); peel_applications=(\d+)',transcript)
            if match:
                result['peel_tests'], result['peel_applications'] = map(int,match.groups())
            if not self.args.skip_symbolic:
                symbolic = out/'symbolic'
                result['symbolic'] = self.run([ROOT/'build/native-audit','lift',self.target,
                    ROOT/'.deps/spec/x86-64.sla',symbolic,item['name']],symbolic/'analysis.log',
                    timeout=self.args.function_timeout,cpu=self.args.cpu_seconds,
                    sandbox=(self.target,ROOT/'.deps/spec/x86-64.sla',symbolic,None))
            return result

        with log.open('a') as stream, ThreadPoolExecutor(max_workers=self.args.jobs) as pool:
            futures = [pool.submit(attempt,item) for item in pending]
            for future in as_completed(futures):
                row = future.result()
                rows[row['address']] = row
                stream.write(json.dumps(row)+'\n')
                stream.flush()
                if len(rows)%32==0 or len(rows)==len(inventory):
                    print(f'[native] {len(rows)}/{len(inventory)} functions checked',flush=True)
        values = list(rows.values())
        summary = dict(functions=len(values),
            pseudocode_emitted=sum(x['decompile']['status']=='ok' and x['pseudocode_bytes']>0 for x in values),
            decompile_statuses=dict(collections.Counter(x['decompile']['status'] for x in values)),
            symbolic_models=sum(x.get('symbolic',{}).get('status')=='ok' for x in values),
            peel_tests=sum(x.get('peel_tests',0) for x in values),
            peel_applications=sum(x.get('peel_applications',0) for x in values),
            scope='All unique sized named function ranges; pseudocode is heuristic, not a semantic or source-byte inverse proof.')
        save(directory/'summary.json',summary)
        return summary

    def syntax(self):
        output = self.output/'syntax'
        empty = self.output/'bun/empty-openssl.cnf'
        empty.touch()
        check = self.run(['node','--jitless','--no-addons','--experimental-vm-modules',
            '--js-explicit-resource-management',ROOT/'validate_extracted_js.cjs',self.output/'bun',output],
            self.logs/'syntax.log',timeout=120,
            environment={'OPENSSL_CONF':str(empty)},
            sandbox=(self.output/'bun',ROOT/'validate_extracted_js.cjs',output,'/usr/share/nodejs'))
        if (output/'syntax.json').exists():
            check['summary'] = json.loads((output/'syntax.json').read_text())['summary']
        return check

    def addons(self):
        modules = json.loads((self.output/'bun/modules.json').read_text())
        checks = []
        for item in modules:
            if not item['path'].endswith('.node'):
                continue
            source = self.output/'bun'/item['extracted']
            output = self.output/'addons'/source.name
            check = self.run([ROOT/'build/native-audit','decode',source,ROOT/'.deps/spec/x86-64.sla',output],
                self.logs/('addon-'+source.name+'.log'),timeout=180,
                sandbox=(source,ROOT/'.deps/spec/x86-64.sla',output,None))
            check['module'] = item['path']
            checks.append(check)
        return checks

    def execute(self):
        for name,work in [('build',self.build),('restrictions',self.restrictions),
                          ('core-tests',self.core_tests),('extraction',self.extraction),
                          ('decoder',self.decoder),('summaries',self.summaries),
                          ('syntax',self.syntax),('addons',self.addons),('native',self.native_functions)]:
            self.stage(name,work)
        if digest(self.target)!=self.target_hash:
            raise RuntimeError('Target content changed during the audit')
        inventory = self.stages['extraction']
        result = dict(target_sha256=self.target_hash,target_unchanged=True,target_executed=False,
            whole_application_decompiled=False,
            stored_modules_extracted=inventory['module_count'],
            stored_content_bytes=inventory['extracted_content_bytes'],
            native=self.stages['native'],core_tests=self.stages['core-tests'],
            syntax=self.stages['syntax'],candidate_summaries=self.stages['summaries'],
            executable_section_bytes=inventory['executable_section_bytes'],
            named_function_bytes=inventory['named_function_bytes'],
            named_byte_coverage_percent=round(100*inventory['named_function_bytes']/inventory['executable_section_bytes'],5),
            elapsed_seconds=round(time.monotonic()-self.started,3),
            limits=dict(function_cpu_seconds=self.args.cpu_seconds,function_wall_seconds=self.args.function_timeout,
                        summary_query_timeout_ms=self.args.summary_timeout_ms),
            limits_of_result=['Unsymbolized native code was not decompiled.',
                'Stored JavaScript extraction is distinct from native reconstruction.',
                'Emitted pseudocode has not been recompiled or proved equivalent.',
                'Timeouts, unsupported cases, parser rejections and failed tests remain visible.'])
        save(self.output/'report.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in ('syntax','core_tests','candidate_summaries')},indent=2))
        print('Results: '+str(self.output/'report.json'),flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=Path('/home/ayush/.local/share/claude/versions/2.1.316'))
    parser.add_argument('--output',type=Path,default=ROOT/'build/decompile-all')
    parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--cpu-seconds',type=int,default=3)
    parser.add_argument('--function-timeout',type=float,default=5)
    parser.add_argument('--summary-timeout-ms',type=int,default=300000)
    parser.add_argument('--skip-symbolic',action='store_true',help='Skip the additional generic GPR/Z3 lifting sweep.')
    parser.add_argument('--fresh',action='store_true',help='Ignore completed stage checkpoints.')
    parser.add_argument('--_selftest',action='store_true',help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.jobs<1 or args.cpu_seconds<1 or args.function_timeout<=0 or args.summary_timeout_ms<1:
        parser.error('jobs, CPU seconds, function timeout and summary timeout must be positive')
    if args._selftest:
        selftest(args)
        return
    audit = Audit(args)
    try:
        audit.execute()
    except KeyboardInterrupt:
        print('Interrupted; completed function results retained for resume.',flush=True)
        raise SystemExit(130)
    except Exception as error:
        save(audit.output/'failure.json',dict(error=str(error),stages=audit.stages))
        print(str(error),file=sys.stderr)
        raise SystemExit(1)


if __name__=='__main__':
    main()
