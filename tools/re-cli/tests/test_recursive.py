import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / 'research/graph_fibers/cpp'

class RecursiveDiscoveryTests(unittest.TestCase):
    def test_stripped_calls_branches_and_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'fixture.s').write_text('''
.global _start
.text
_start:
  call first
  test %eax,%eax
  jz done
  call *%rax
done:
  ret
first:
  call second
  ret
second:
  jmp done
''')
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--build-id=none', '-o', p/'fixture', p/'fixture.s'], check=True)
            nm = subprocess.check_output(['nm', '-n', p/'fixture'], text=True)
            symbols = {line.split()[-1]: int(line.split()[0], 16) for line in nm.splitlines() if len(line.split()) >= 3}
            subprocess.run(['objcopy', '--strip-all', '--remove-section=.eh_frame', '--remove-section=.eh_frame_hdr', p/'fixture'], check=True)
            (p/'seeds.txt').write_text(f'{symbols["_start"]:x}\n')
            command = [BACKEND/'build/native-discover', p/'fixture', BACKEND/'.deps/spec/x86-64.sla', p/'seeds.txt', p, '100']
            subprocess.run(command, check=True)
            rows = (p/'recursive.tsv').read_text().splitlines()[1:]
            targets = {int(row.split('\t')[0], 16) for row in rows}
            self.assertTrue({symbols['first'], symbols['second']} <= targets)
            stats = json.loads((p/'recursive-stats.json').read_text())
            self.assertGreater(stats['unresolved_indirect_calls'], 0)
            self.assertGreater(stats['ambiguous_direct_jumps'], 0)
            self.assertFalse(stats['truncated'])
            cli_out = p / 'cli-output'
            cli = subprocess.run([ROOT/'tools/re-cli/bin/re-', p/'fixture', '-o', cli_out],
                                 text=True, capture_output=True, timeout=60)
            self.assertEqual(cli.returncode, 2, cli.stdout + cli.stderr)
            report = json.loads((cli_out/'report.json').read_text())['binaries'][0]
            self.assertEqual(report['recursive_discovery']['status'], 'ok')
            found = {row['address']: row for row in report['functions']}
            for address in (symbols['first'], symbols['second']):
                self.assertIn('direct_call', found[address]['provenance'])
            self.assertGreater(report['discovery']['recursive']['unresolved_indirect_calls'], 0)
            self.assertTrue((Path(report['output'])/'recursive-discovery/sandbox-active.json').is_file())
            command[-1] = '1'
            subprocess.run(command, check=True)
            self.assertTrue(json.loads((p/'recursive-stats.json').read_text())['truncated'])
            (p/'seeds.txt').write_text('not-hex\n')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

if __name__ == '__main__':
    unittest.main()
