"""End-to-end checks against real compiled ELF inputs and the prepared backend."""
import fcntl
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import re_cli


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='re-cli-test-')
        cls.root = Path(cls.temp.name)
        cls.app = cls.root / 'application folder'
        (cls.app / 'nested').mkdir(parents=True)
        source = cls.root / 'fixture.c'
        source.write_text('__attribute__((noinline)) int add(int x,int y){return x+y+7;}\n'
                          'int main(int argc,char**argv){return add(argc,2);}\n')
        cls.binary = cls.app / 'demo'
        subprocess.run(['cc', '-O1', str(source), '-o', str(cls.binary)], check=True)
        subprocess.run(['cc', '-shared', '-fPIC', '-O1', str(source), '-o',
                        str(cls.app / 'nested/libdemo.so')], check=True)
        cls.before = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, *args):
        return subprocess.run([str(ROOT / 'bin/re-'), *map(str, args)],
                              text=True, capture_output=True, timeout=90)

    def test_recursive_unquoted_spaces_sandbox_pseudocode_and_resume(self):
        output = self.root / 'output folder'
        # Separate argv words emulate an unquoted space-containing folder.
        args = [*str(self.app).split(' '), '--output', str(output)]
        run = self.invoke(*args)
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('[inventory] started', run.stdout)
        self.assertIn('[assembly] ok', run.stdout)
        self.assertIn('[decompile add @', run.stdout)
        self.assertIn('[progress]', run.stdout)
        self.assertIn('[progress] [', run.stdout)
        self.assertIn('100.0%', run.stdout)
        self.assertNotIn('\x1b', run.stdout)
        self.assertIn('=== Final summary ===', run.stdout)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(len(report['binaries']), 2)
        self.assertFalse(report['target_executed'])
        self.assertFalse(report['whole_application_recovered'])
        for binary in report['binaries']:
            self.assertGreater(binary['pseudocode_emitted'], 0)
            self.assertTrue(binary['target_unchanged'])
            self.assertEqual(binary['assembly']['status'], 'ok')
            assembly = Path(binary['assembly']['log']).read_text()
            self.assertIn('<add>', assembly)
            functions = binary['functions']
            add = next(f for f in functions if f['name'] == 'add')
            self.assertEqual(add['status'], 'ok')
            source = Path(binary['output']) / 'functions' / f'{add["address"]:x}' / 'decompiled.c'
            self.assertIn('add(', source.read_text())
            marker = json.loads((source.parent / 'sandbox-active.json').read_text())
            self.assertTrue(marker['landlock'] and marker['seccomp'])
        total = sum(len(binary['functions']) for binary in report['binaries'])
        self.assertIn(f'Functions: {total} total | {total} succeeded | 0 failed', run.stdout)
        again = self.invoke(*args)
        self.assertEqual(again.returncode, 2, again.stderr)
        report = json.loads((output / 'report.json').read_text())
        for binary in report['binaries']:
            self.assertEqual(binary['resumed_functions'], binary['functions_discovered'])
        self.assertEqual(hashlib.sha256(self.binary.read_bytes()).hexdigest(), self.before)

    def test_malformed_unsupported_symlink_and_empty(self):
        folder = self.root / 'bad'
        folder.mkdir()
        (folder / 'truncated').write_bytes(b'\x7fELF')
        (folder / 'windows.exe').write_bytes(b'MZxx')
        (folder / 'escape').symlink_to(self.binary)
        output = self.root / 'bad-output'
        run = self.invoke(folder, '-o', output)
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        report = json.loads((output / 'report.json').read_text())
        self.assertEqual(report['binaries'][0]['status'], 'failed')
        self.assertEqual(len(report['skipped']), 2)
        self.assertIn('Truncated ELF record', run.stdout)
        self.assertIn('[inventory] failed; exit=1', run.stdout)
        self.assertIn('[skipped]', run.stdout)
        self.assertIn('Binaries: 1 total | 0 succeeded | 0 partial | 1 failed', run.stdout)
        empty = self.root / 'empty'
        empty.mkdir()
        self.assertEqual(self.invoke(empty, '-o', self.root / 'empty-output').returncode, 2)

    def test_stripped_binary_preserves_assembly_and_reports_no_functions(self):
        binary = self.root / 'stripped'
        shutil.copyfile(self.binary, binary)
        subprocess.run(['strip', '--strip-all', str(binary)], check=True)
        output = self.root / 'stripped-output'
        run = self.invoke(binary, '-o', output)
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        report = json.loads((output / 'report.json').read_text())['binaries'][0]
        self.assertEqual(report['functions_discovered'], 0)
        self.assertEqual(report['assembly']['status'], 'ok')
        self.assertGreater(Path(report['assembly']['log']).stat().st_size, 100)

    def test_output_lock_and_checkout_write_rejection(self):
        output = self.root / 'locked-output'
        output.mkdir()
        with (output / '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run = self.invoke(self.binary, '-o', output)
            self.assertEqual(run.returncode, 1)
            self.assertIn('already writing', run.stderr)
            self.assertFalse((output / 'specs').exists())
        forbidden = re_cli.DEFAULT_REPO / 'cli-results-must-not-exist'
        self.assertFalse(forbidden.exists())
        self.assertEqual(self.invoke(self.binary, '-o', forbidden).returncode, 1)
        self.assertFalse(forbidden.exists())

    def test_time_limit_and_option_validation(self):
        folder = self.root / 'timeout'
        result = re_cli.run(['/usr/bin/sleep', '5'], folder, 0.02, 128)
        self.assertEqual(result['status'], 'timeout')
        self.assertFalse(re_cli.CHILDREN)
        self.assertEqual(self.invoke(self.binary, '--jobs', '0').returncode, 2)
        self.assertEqual(self.invoke(self.binary, '--function-timeout', 'nan').returncode, 2)

    def test_installer_registers_self_contained_default_command(self):
        prefix = self.root / 'installed application'
        run = subprocess.run([sys.executable, str(ROOT / 'install.py'), '--prefix', str(prefix)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        env = dict(os.environ, PATH=str(prefix / 'bin') + os.pathsep + os.environ['PATH'])
        env.pop('RE_REPO', None)
        output = self.root / 'installed-results'
        installed = subprocess.run(['re-', str(self.binary), '-o', str(output)], env=env,
                                   cwd=self.root, capture_output=True, text=True, timeout=90)
        self.assertEqual(installed.returncode, 2, installed.stdout + installed.stderr)
        report = json.loads((output / 'report.json').read_text())['binaries'][0]
        self.assertGreater(report['pseudocode_emitted'], 0)
        self.assertIn('=== Final summary ===', installed.stdout)
        # All native/spec inputs in provenance must come from the installed bundle.
        import importlib.util
        spec = importlib.util.spec_from_file_location('installed_cli', prefix / 'lib/re-cli/re_cli.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.DEFAULT_REPO, prefix / 'lib/re-cli/backend')

    def test_installer_preserves_unrelated_command(self):
        prefix = self.root / 'conflicting-install'
        (prefix / 'bin').mkdir(parents=True)
        command = prefix / 'bin/re-'
        command.write_text('existing command')
        run = subprocess.run([sys.executable, str(ROOT / 'install.py'), '--prefix', str(prefix)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 1)
        self.assertIn('unrelated command', run.stderr)
        self.assertEqual(command.read_text(), 'existing command')
        self.assertFalse((prefix / 'lib/re-cli').exists())

    def test_analyzer_output_is_visible_before_process_exits(self):
        seen = threading.Event()
        class Capture(io.StringIO):
            def write(self, text):
                result = super().write(text)
                if '[stream-test] first-line' in text:
                    seen.set()
                return result
        release = self.root / 'release-stream-test'
        command = [sys.executable, '-u', '-c',
                   'import pathlib,sys,time; print("first-line",flush=True); '
                   'print("stderr-error",file=sys.stderr,flush=True); '
                   'p=pathlib.Path(sys.argv[1]); '
                   'exec("while not p.exists(): time.sleep(0.01)"); print("last-line")',
                   str(release)]
        output = Capture()
        results = []
        with contextlib.redirect_stdout(output):
            worker = threading.Thread(target=lambda: results.append(re_cli.run(
                command, self.root / 'stream-test', 10, 128)))
            worker.start()
            try:
                self.assertTrue(seen.wait(5), output.getvalue())
                self.assertTrue(worker.is_alive(), 'Output was delayed until process exit')
            finally:
                release.touch()
                worker.join(15)
        self.assertEqual(results[0]['status'], 'ok')
        self.assertIn('[stream-test] stderr-error', output.getvalue())
        self.assertIn('[stream-test] last-line', output.getvalue())
        self.assertIn('stderr-error', (self.root / 'stream-test/analysis.log').read_text())

    def test_summary_distinguishes_failures_timeouts_and_symbolic_partial_results(self):
        rows = [dict(status='ok', decompile=dict(status='ok'), resumed=True),
                dict(status='failed', decompile=dict(status='failed')),
                dict(status='timeout', decompile=dict(status='timeout')),
                dict(status='partial', decompile=dict(status='ok'), symbolic=dict(status='timeout')),
                dict(status='missing_pseudocode', decompile=dict(status='ok'))]
        report = dict(binaries=[dict(path='fixture', status='partial', functions=rows,
                                    pseudocode_emitted=2)], skipped=[dict(path='unsupported')])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            re_cli.print_summary(report, 1.25)
        text = output.getvalue()
        self.assertIn('Functions: 5 total | 1 succeeded | 2 failed | 1 timed out | 1 partial', text)
        self.assertIn('Analysis stages: 3 succeeded | 1 failed | 2 timed out', text)
        self.assertIn('Resumed functions: 1', text)
        self.assertIn('Skipped files/directories: 1 | Elapsed: 1.25s', text)

    def test_terminal_progress_preserves_errors_and_cleans_up_after_completion(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        terminal = Terminal()
        with contextlib.redirect_stdout(terminal), mock.patch.dict(os.environ, TERM='xterm'), \
                mock.patch.object(shutil, 'get_terminal_size', return_value=os.terminal_size((100, 24))):
            progress = re_cli.FunctionProgress(2)
            progress.start()
            try:
                progress.update(dict(status='ok'))
                re_cli.emit('[error] test failure')
                progress.update(dict(status='failed'))
            finally:
                progress.close()
            re_cli.emit('finished')
        text = terminal.getvalue()
        self.assertIn('1/2 functions; 50.0%', text)
        self.assertIn('[error] test failure\n\r\x1b[2K[progress]', text)
        self.assertIn('2/2 functions; 100.0% | ok: 1 | issues: 1', text)
        self.assertTrue(text.endswith('\nfinished\n'))
        self.assertIsNone(re_cli.ACTIVE_PROGRESS)

    def test_narrow_terminal_progress_does_not_wrap(self):
        progress = re_cli.FunctionProgress(100000)
        progress.tty = True
        with mock.patch.object(shutil, 'get_terminal_size', return_value=os.terminal_size((32, 24))):
            self.assertLess(len(progress.line()), 32)


if __name__ == '__main__':
    unittest.main()
