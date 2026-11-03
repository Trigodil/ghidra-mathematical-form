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

    def test_fixed_point_indirect_switch_and_dynamic_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'fixture.s').write_text('''
.global _start
.text
_start:
  lea target(%rip), %rax
  call *%rax
  mov $1, %edi
  call sw
  call dynamic
  ret
target:
  ret
dynamic:
  call *%rdi
  ret
sw:
  mov %edi,%edi
  cmp $2, %edi
  ja default
  lea table(%rip), %rdx
  movslq (%rdx,%rdi,4), %rax
  add %rdx, %rax
  jmp *%rax
case0:
  call leaf0
  ret
case1:
  call leaf1
  ret
case2:
  call leaf2
  ret
default:
  ret
leaf0:
  ret
leaf1:
  ret
leaf2:
  ret
  .space 64,0x90
.section .rodata
table:
  .long case0-table, case1-table, case2-table
  .space 64,0
''')
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--build-id=none', '-o', p/'fixture', p/'fixture.s'], check=True)
            nm = subprocess.check_output(['nm', '-n', p/'fixture'], text=True)
            symbols = {line.split()[-1]: int(line.split()[0], 16) for line in nm.splitlines() if len(line.split()) >= 3}
            subprocess.run(['objcopy', '--strip-all', '--remove-section=.eh_frame', '--remove-section=.eh_frame_hdr', p/'fixture'], check=True)
            (p/'seeds.txt').write_text(f'{symbols["_start"]:x}\n')
            subprocess.run([BACKEND/'build/native-discover', p/'fixture', BACKEND/'.deps/spec/x86-64.sla', p/'seeds.txt', p, '1000'], check=True)
            baseline = {int(line.split('\t')[0], 16) for line in (p/'recursive.tsv').read_text().splitlines()[1:]}
            self.assertNotIn(symbols['target'], baseline)
            self.assertNotIn(symbols['leaf0'], baseline)
            cli_out = p/'output'
            subprocess.run([ROOT/'tools/re-cli/bin/re-', p/'fixture', '-o', cli_out], capture_output=True, text=True, timeout=60)
            report = json.loads((cli_out/'report.json').read_text())['binaries'][0]
            found = {row['address']: row for row in report['functions']}
            self.assertIn('decompiler_indirect_call', found[symbols['target']]['provenance'])
            for name in ('leaf0', 'leaf1', 'leaf2'):
                self.assertIn(symbols[name], found)
            for name in ('case0', 'case1', 'case2'):
                self.assertNotIn(symbols[name], found)
            base = Path(report['output'])
            edges = (base/'functions'/format(symbols['sw'], 'x')/'recovered-edges.tsv').read_text()
            self.assertIn('switch\t', edges)
            sites = (base/'recursive-discovery/sites.tsv').read_text()
            self.assertIn(format(symbols['dynamic'], 'x') + '\tunresolved_indirect_call', sites)
            self.assertIn('unexamined', (base/'recursive-discovery/coverage.tsv').read_text())
            self.assertGreater(report['recovery_rounds'], 1)
            self.assertEqual(report['status'], 'partial')

    def test_pie_relocations_preserve_constant_call_and_external_uncertainty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'fixture.s').write_text('''
.global _start
.weak external
.text
_start:
  call *slot(%rip)
  call *external@GOTPCREL(%rip)
  ret
target:
  ret
  .space 32,0x90
.section .rodata
slot:
  .quad target
  .space 32,0
''')
            subprocess.run(['gcc', '-nostdlib', '-pie', '-Wl,--build-id=none', '-o', p/'fixture', p/'fixture.s'], check=True)
            nm = subprocess.check_output(['nm', '-n', p/'fixture'], text=True)
            target = next(int(line.split()[0], 16) for line in nm.splitlines() if line.split()[-1:] == ['target'])
            subprocess.run(['objcopy', '--strip-all', '--remove-section=.eh_frame', '--remove-section=.eh_frame_hdr', p/'fixture'], check=True)
            subprocess.run([ROOT/'tools/re-cli/bin/re-', p/'fixture', '-o', p/'out'], capture_output=True, text=True, timeout=60)
            report = json.loads((p/'out/report.json').read_text())['binaries'][0]
            self.assertIn(target, {row['address'] for row in report['functions']})
            base = Path(report['output'])
            sites = (base/'recursive-discovery/sites.tsv').read_text()
            self.assertGreaterEqual(sites.count('unresolved_indirect_call'), 2)
            self.assertEqual(report['status'], 'partial')

if __name__ == '__main__':
    unittest.main()
