"""Whole-file evidence, global source search, integration and build isolation."""
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import full_recovery as recovery
import re_cli


class FullRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='full-recovery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Both alternatives are complete programs, not independent function tests.
        # Calls cross translation units; the program also has memory, a loop and a branch.
        self.spec = dict(files={
            'state.h': 'extern unsigned state; unsigned step(unsigned);\n',
            'worker.c': '#include "state.h"\nunsigned state=@@INITIAL@@;\n'
                        'unsigned step(unsigned x){if(x&1)state+=x;else state^=x;return state;}\n',
            'main.c': '#include "state.h"\nint main(int argc,char **argv){unsigned y=0;'
                      'for(unsigned i=0;i<(unsigned)argc;++i)y+=step(i);return y&255;}\n'},
            holes={'INITIAL': [{'text':'2', 'cost':0}, {'text':'7', 'cost':1}]},
            profiles=[dict(compiler='gcc', flags=['-O1'], sources=['main.c', 'worker.c'])])
        self.target = self.root / 'app'
        self.build_target(self.spec, 1)

    def build_target(self, spec, index):
        candidate = list(recovery.candidates(spec))[index]
        source = self.root / 'original'
        source.mkdir(exist_ok=True)
        for name, text in candidate['files'].items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        subprocess.run(['/usr/bin/gcc', *candidate['profile']['sources'],
                        *candidate['profile']['flags'], '-o', str(self.target)], cwd=source, check=True)

    def recover(self, spec=None, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()):
            return recovery.recover(self.target, spec or self.spec, self.root / 'recovery',
                                    re_cli.run, re_cli.emit, **kwargs)

    def test_multi_translation_unit_exact_project_and_rebuild(self):
        before = recovery.sha(self.target)
        result = self.recover()
        self.assertEqual(result['status'], 'verified_exact')
        self.assertTrue(result['whole_binary_recovered'])
        self.assertFalse(result['historical_source_recovered'])
        self.assertTrue(result['minimal_declared_cost'])
        self.assertEqual([a['status'] for a in result['attempts']], ['byte_mismatch', 'verified_exact'])
        self.assertIsNotNone(result['attempts'][0]['comparison']['first_difference'])
        project = Path(result['recovered_project'])
        self.assertEqual(recovery.sha(project / 'rebuilt.elf'), before)
        (project / 'rebuilt.elf').unlink()
        subprocess.run([sys.executable, 'rebuild.py'], cwd=project, check=True, capture_output=True)
        self.assertEqual(recovery.sha(project / 'rebuilt.elf'), before)
        self.assertEqual(recovery.sha(self.target), before)

    def test_budget_and_grammar_exhaustion_are_distinct(self):
        budget = self.recover(max_candidates=1)
        self.assertEqual(budget['status'], 'budget_exhausted')
        self.assertFalse(budget['whole_binary_recovered'])
        wrong = copy.deepcopy(self.spec)
        wrong['holes']['INITIAL'] = wrong['holes']['INITIAL'][:1]
        exhausted = self.recover(wrong)
        self.assertEqual(exhausted['status'], 'grammar_exhausted')
        self.assertFalse(exhausted['whole_binary_recovered'])
        # A second run cannot accept leftover exact output from an earlier run.
        self.assertEqual(self.recover()['status'], 'verified_exact')
        self.assertEqual(self.recover(wrong)['status'], 'grammar_exhausted')

    def test_metadata_and_data_mismatches_never_pass(self):
        # Trailing bytes do not change executable code, but must fail exact recovery.
        with self.target.open('ab') as stream:
            stream.write(b'non-code metadata')
        result = self.recover()
        self.assertEqual(result['status'], 'grammar_exhausted')
        self.assertTrue(all(a['status'] == 'byte_mismatch' for a in result['attempts']))
        comparison = result['attempts'][1]['comparison']
        self.assertEqual(comparison['different_bytes'], len(b'non-code metadata'))
        self.assertIsNone(comparison['first_difference']['rebuilt'])

    def test_lazy_global_cost_order_and_shared_holes(self):
        spec = copy.deepcopy(self.spec)
        spec['files']['main.c'] += '\n/* @@INITIAL@@ @@SECOND@@ */\n'
        spec['holes']['SECOND'] = [{'text':'expensive', 'cost':10}, {'text':'cheap', 'cost':0}]
        recovery.validate(spec)
        candidates = list(recovery.candidates(spec))
        self.assertEqual([c['cost'] for c in candidates], [0,1,10,11])
        self.assertIn('/* 7 cheap */', candidates[1]['files']['main.c'])
        self.assertIn('state=7;', candidates[1]['files']['worker.c'])
        self.assertEqual(len({tuple(c['choices'].values()) for c in candidates}), 4)

    def test_invalid_projects_are_rejected_before_build(self):
        mutations = [
            lambda s: s['files'].update({'../escape.c': 'int x;'}),
            lambda s: s['profiles'][0]['flags'].append('-fplugin=/tmp/plugin.so'),
            lambda s: s['profiles'][0]['flags'].append('@/tmp/args'),
            lambda s: s['profiles'][0].update(sources=['main.c']),
            lambda s: s['profiles'][0].update(compiler='/tmp/tool'),
            lambda s: s['holes']['INITIAL'][0].update(cost=-1),
            lambda s: s['files'].update({'object.o': 'bytes'}),
            lambda s: s['files'].update({'main.c/nested.h': 'int x;'}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                spec = copy.deepcopy(self.spec)
                mutation(spec)
                with self.assertRaises(ValueError):
                    recovery.validate(spec)

    def test_compiler_cannot_read_target_or_unrelated_private_file(self):
        secret = self.root / 'private.h'
        secret.write_text('#define PRIVATE 17\n')
        spec = dict(files={'main.c': f'#include "{secret}"\nint main(void){{return PRIVATE;}}'},
                    profiles=[dict(compiler='gcc', sources=['main.c'])])
        result = self.recover(spec)
        row = result['attempts'][0]
        self.assertEqual(row['status'], 'compile_failed')
        self.assertIn('Permission denied', Path(row['build']['log']).read_text())
        marker = json.loads((Path(row['project']) / 'build-isolation.json').read_text())
        self.assertFalse(marker['candidate_execution_allowed'])
        self.assertFalse(marker['target_path_passed_to_compiler'])

    def test_timeout_remains_unresolved(self):
        def timeout(*args, **kwargs):
            return dict(status='timeout', exit_code=-9)
        result = recovery.recover(self.target, self.spec, self.root / 'timeout', timeout,
                                  lambda _: None)
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['unresolved_attempts'], 2)
        self.assertFalse(result['whole_binary_recovered'])

    def test_candidate_execution_is_denied_by_kernel(self):
        project = self.root / 'isolated'
        project.mkdir()
        candidate = project / 'candidate'
        candidate.write_bytes(self.target.read_bytes())
        candidate.chmod(0o755)
        script = ('import sys; sys.path.insert(0,sys.argv[1]); '
                  'from recovery_build import restrict; from pathlib import Path; import os; '
                  'restrict(Path.cwd()); os.execv("./candidate",["./candidate"])')
        process = subprocess.run([sys.executable, '-c', script, str(HERE)], cwd=project,
                                 capture_output=True, text=True, timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('PermissionError', process.stderr)

    def test_cli_integrates_full_project_acceptance(self):
        config = self.root / 'grammar.json'
        config.write_text(json.dumps(dict(version=1, targets={'app': self.spec})))
        out = self.root / 'cli'
        run = subprocess.run([HERE/'bin/re-', self.target, '-o', out, '--recovery-spec', config],
                             capture_output=True, text=True, timeout=90)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        report = json.loads((out / 'report.json').read_text())
        self.assertTrue(report['whole_application_recovered'])
        self.assertTrue(report['whole_binary_set_recovered'])
        self.assertEqual(report['binaries'][0]['full_recovery']['status'], 'verified_exact')
        self.assertFalse(report['target_executed'])
        again = self.root / 'imported'
        run = subprocess.run([HERE/'bin/re-', self.target, '-o', again, '--recovery-spec', config,
                              '--reuse-analysis', out/'report.json'],
                             capture_output=True, text=True, timeout=90)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('hash-matching target', run.stdout)
        self.assertNotIn('[inventory] started', run.stdout)
        imported = json.loads((again/'report.json').read_text())['binaries'][0]
        function_file = next((Path(imported['output'])/'functions').glob('*/decompiled.c'))
        before = recovery.sha(function_file)
        rerun = subprocess.run([HERE/'bin/re-', self.target, '-o', again, '--recovery-spec', config,
                                '--reuse-analysis', again/'report.json'],
                               capture_output=True, text=True, timeout=90)
        self.assertEqual(rerun.returncode, 0, rerun.stdout + rerun.stderr)
        self.assertEqual(recovery.sha(function_file), before)
        with self.target.open('ab') as stream:
            stream.write(b'changed')
        run = subprocess.run([HERE/'bin/re-', self.target, '-o', self.root/'stale',
                              '--reuse-analysis', out/'report.json'],
                             capture_output=True, text=True, timeout=90)
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertIn('No hash-matching analysis', run.stdout)


if __name__ == '__main__':
    unittest.main()
