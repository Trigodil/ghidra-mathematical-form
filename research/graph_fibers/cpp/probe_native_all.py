#!/usr/bin/env python3
"""Bound each named-function lifting attempt; target is always data, never code."""
import collections
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import time


def main():
    root = Path(__file__).resolve().parent
    base = root/'build/claude-full-audit'
    inventory = json.loads((base/'bun-complete/native_symbols.json').read_text())
    target = '/home/ayush/.local/share/claude/versions/2.1.316'
    spec = root/'.deps/spec/x86-64.sla'
    output = base/'native-lifting'
    output.mkdir(exist_ok=True)
    start = time.monotonic()

    def attempt(item):
        directory = output/f'{item["address"]:x}'
        directory.mkdir(exist_ok=True)
        environment = dict(PATH='/usr/bin:/bin', LANG='C',
                           LD_PRELOAD='./build/analysis-lockdown.so',
                           ANALYSIS_INPUT=target, ANALYSIS_SPEC=str(spec), ANALYSIS_OUTPUT=str(directory))
        command = ['/usr/bin/prlimit', '--as=1610612736', '--cpu=6', '--fsize=16777216',
                   '--nofile=64', '--core=0', '--', str(root/'build/native-audit'),
                   'lift', target, str(spec), str(directory), item['name']]
        begin = time.monotonic()
        try:
            # prlimit would be locked down before exec with this environment.
            # env sets LD_PRELOAD only for the analyzer, after prlimit has exec'd.
            launch_env = {'PATH':'/usr/bin:/bin', 'LANG':'C'}
            command = command[:7] + ['/usr/bin/env', '-i'] + [f'{k}={v}' for k,v in environment.items()] + command[7:]
            result = subprocess.run(command, env=launch_env, cwd=root, capture_output=True, text=True, timeout=8)
            status = 'modeled' if result.returncode == 0 else 'unsupported_or_resource_limit'
            detail = (result.stdout+result.stderr).strip()
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            status, detail, returncode = 'wall_time_limit', '8 seconds per function', None
        return dict(**item, status=status, reason=detail, exit_code=returncode,
                    seconds=round(time.monotonic()-begin, 4))

    rows = []
    with (output/'functions.jsonl').open('w') as log, ThreadPoolExecutor(max_workers=2) as pool:
        for result in pool.map(attempt, inventory):
            rows.append(result)
            log.write(json.dumps(result)+'\n')
            log.flush()
            if len(rows)%64 == 0:
                print(f'lifting {len(rows)}/{len(inventory)}', flush=True)
    counts = collections.Counter(row['status'] for row in rows)
    failures = collections.Counter(row['reason'] for row in rows if row['status']!='modeled')
    summary = dict(functions=len(rows), statuses=dict(counts), failure_reasons=dict(failures),
                   total_seconds=round(time.monotonic()-start, 3),
                   source_reconstruction_attempts=0,
                   scope='Generic full initial GPR state; RAX, final RAM, stack and callee-saved GPR observations. '
                         'An accepted model is not a recovered source ABI or an exact source-byte inverse. '
                         '8-second wall and 6-second CPU limits per function; failures remain unresolved.')
    (output/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
