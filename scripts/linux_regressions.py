#!/usr/bin/env python3
"""Real containment checks: run as root ONLY in the disposable reference image.

Uses the production SETUP, RUNNER, authentication and INCORRECT gate without
requiring Inspect in the sandbox image. Logs only stage, returncode and flags.
Docker gives the memory attack a real 512 MiB cgroup; the explicit prlimit
fallback exercises address-space exhaustion, not cgroup OOM behavior.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0'
FLAGS = ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error', 'output_not_decodable')


def load_module(name):
    # Avoid package __init__: the reference image intentionally has no Inspect.
    spec = importlib.util.spec_from_file_location(name, ROOT / 'cobolcodebench' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CASES = {
    'bytes': "import os; os.write(1, b'\\xff'); raise SystemExit(1)",
    'forks': '''import os, time
children = 0
while True:
    try:
        pid = os.fork()
    except OSError:
        assert children > 0
        print('forks-exhausted', flush=True)
        raise SystemExit(1)
    if pid == 0:
        os.setsid()
        while True:
            time.sleep(60)
    children += 1
''',
    'memory': '''print('memory-started', flush=True)
blocks = []
while True:
    blocks.append(bytearray(16 * 1024 * 1024))
''',
}


LIMIT_PROBE = '''import os, resource
assert os.getresuid() == (65532,) * 3
assert resource.getrlimit(resource.RLIMIT_NPROC) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_AS) == (1024**3, 1024**3)
assert resource.getrlimit(resource.RLIMIT_DATA) == (1024**3, 1024**3)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (4096, 4096)
assert open('/proc/self/oom_score_adj').read().strip() == '1000'
'''


def checked_run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError('regression exec failed')
    return result


def run_case(name, *, prlimit=False):
    runner, receipts = load_module('sandbox_runner'), load_module('receipts')
    unused = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
    assert unused.returncode == 1, 'reserved candidate UID must be unused'
    setup = None
    try:
        request = dict(files={}, argv=[sys.executable, '-I', '-c', 'pass'],
                       run_argv=[sys.executable, '-I', '-c', LIMIT_PROBE + CASES[name]],
                       timeout=5, run_timeout=15, output_limit=4096)
        setup_result = checked_run([sys.executable, '-I', '-c', runner.SETUP],
                                   input=json.dumps(request), timeout=5)
        setup = json.loads(setup_result.stdout)
        command = ['timeout', '-s', 'KILL', '30s', sys.executable, '-I', '-c', runner.RUNNER, setup['cwd']]
        if prlimit:
            command = ['prlimit', '--as=1073741824:1073741824',
                       '--data=1073741824:1073741824', '--'] + command
        result = checked_run(command, timeout=35)
        receipt = receipts.verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        assert receipt is not None and receipt['cwd'] == setup['cwd']
        # The production scorer returns INCORRECT for every non-None reason.
        assert receipts.receipt_failure(receipt) is not None
        assert receipt['stage'] == 'run' and receipt['compile_success']
        assert receipt['returncode'] != 0 and not receipt['timeout']
        assert not receipt['cleanup_failed'] and not receipt['supervisor_error']
        if name == 'bytes':
            assert receipt['output_not_decodable']
        else:
            # A probe/launch failure must not masquerade as a successful attack.
            witness = 'forks-exhausted\n' if name == 'forks' else 'memory-started\n'
            assert receipt['output'] == witness
        return {field: receipt[field] for field in ('stage', 'returncode', *FLAGS)}
    finally:
        for command in (runner.CLEANUP_COMMAND, runner.QUIESCENCE_COMMAND):
            result = subprocess.run(command, capture_output=True, timeout=6)
            assert result.returncode in ((0, 1) if command == runner.CLEANUP_COMMAND else (0,))
        if setup:
            shutil.rmtree(setup['cwd'], ignore_errors=True)


def memory_command(image):
    return ['docker', 'run', '--rm', '--memory=512m', '--memory-swap=512m',
            '--pids-limit=128', '--network=none', '--user=0:0',
            '-v', f'{ROOT}:{ROOT}:ro', '-w', str(ROOT), image,
            '/usr/local/bin/python3', str(ROOT / 'scripts/linux_regressions.py'), '--memory-only']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--memory-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('requires root in a disposable Linux reference sandbox image')
    try:
        if args.memory_only:
            reports = [run_case('memory')]
        else:
            reports = [run_case(name) for name in ('bytes', 'forks')]
            if shutil.which('docker'):
                # A present but broken daemon is a failure, never a silent fallback.
                result = checked_run(memory_command(args.image), timeout=90)
                reports.append(json.loads(result.stdout))
            else:
                reports.append(run_case('memory', prlimit=True))
        for report in reports:
            # Whitelist fields even for the nested docker result.
            assert set(report) == {'stage', 'returncode', *FLAGS}
            print(json.dumps(report, sort_keys=True))
        return 0
    except Exception:
        # Do not log exception chains, stdout/stderr, candidates or receipt keys.
        print('Linux regression failed; details withheld.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
