#!/usr/bin/env python3
"""Real containment checks: run as root ONLY in the disposable reference image.

Uses the production SETUP, RUNNER, authentication and INCORRECT gate without
requiring Inspect in the sandbox image. Logs only stage, returncode and flags.
Docker supplies the production-sized memory budget and a writable /tmp volume;
the disk watchdog bounds writes. The prlimit fallback cannot exercise aggregate
memory or disk exhaustion safely.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0'
FLAGS = ('timeout', 'overflow', 'memory_exceeded', 'disk_exceeded', 'cleanup_failed', 'supervisor_error', 'output_not_decodable')


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
        print('forks-exhausted', children, flush=True)
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
    'memory_aggregate': '''import os, time
print('aggregate-started', flush=True)
for _ in range(3):
    if os.fork() == 0:
        os.setsid()
        block = bytearray(600 * 1024 * 1024)
        time.sleep(60)
        os._exit(0)
time.sleep(60)
''',
    'disk': '''import os, tempfile
block = b'x' * (1024 * 1024)
with open('work-file', 'wb') as stream:
    stream.write(block)
# Keep work-directory usage small: only a watcher covering ALL of /tmp can
# stop this unbounded writer. The independent ccb-* cleanup removes both dirs.
other = tempfile.mkdtemp(prefix='ccb-disk-', dir='/tmp')
i = 0
while True:
    with open(os.path.join(other, 'file-' + str(i)), 'wb') as stream:
        stream.write(block)
    i += 1
''',
    'detached': '''import os, time
read_fd, write_fd = os.pipe()
if os.fork() == 0:
    os.close(read_fd)
    os.setsid()
    os.write(write_fd, b'1')
    os.close(write_fd)
    time.sleep(60)
    os._exit(0)
os.close(write_fd)
assert os.read(read_fd, 1) == b'1'
os.close(read_fd)
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


def case_request(name, executable='/usr/local/bin/python3'):
    # Each disk file must fit below FSIZE so this reaches the aggregate disk watchdog.
    limit = 2 * 1024 * 1024 if name == 'disk' else 4096
    probe = LIMIT_PROBE.replace('(4096, 4096)', f'({limit}, {limit})')
    return dict(files={}, argv=[executable, '-I', '-c', 'pass'],
                run_argv=[executable, '-I', '-c', probe + CASES[name]],
                timeout=5, run_timeout=15, output_limit=limit)


def expected_receipt(name, receipt):
    if (receipt['stage'] != 'run' or not receipt['compile_success']
            or any(receipt.get(flag, False) for flag in
                   ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error'))):
        return False
    if name == 'detached':
        return receipt['returncode'] == 0 and not any(receipt.get(f, False) for f in FLAGS)
    if receipt['returncode'] == 0:
        return False
    if name not in {'memory', 'memory_aggregate', 'forks'} and receipt.get('memory_exceeded', False):
        return False
    if name != 'disk' and receipt.get('disk_exceeded', False):
        return False
    if name == 'bytes':
        return receipt['output_not_decodable']
    if receipt['output_not_decodable']:
        return False
    if name == 'memory_aggregate':
        return receipt.get('memory_exceeded', False)
    if name == 'disk':
        return receipt.get('disk_exceeded', False)
    if name == 'forks':
        # gVisor charges shared copy-on-write RSS once per child.
        witness = re.fullmatch(r'forks-exhausted ([1-9][0-9]*)\n', receipt['output'])
        return (receipt.get('memory_exceeded', False) or
                (receipt['returncode'] == 1 and witness is not None
                 and 0 < int(witness[1]) < 64))
    return receipt['output'] == 'memory-started\n'


def run_case(name, *, prlimit=False):
    runner, receipts = load_module('sandbox_runner'), load_module('receipts')
    unused = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
    assert unused.returncode == 1, 'reserved candidate UID must be unused'
    setup = None
    try:
        request = case_request(name, sys.executable)
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
        assert (receipts.receipt_failure(receipt) is None) == (name == 'detached')
        assert expected_receipt(name, receipt)
        return {field: receipt.get(field, False) for field in ('stage', 'returncode', *FLAGS)}
    finally:
        for command in (runner.CLEANUP_COMMAND, runner.QUIESCENCE_COMMAND):
            result = subprocess.run(command, capture_output=True, timeout=6)
            assert result.returncode in ((0, 1) if command == runner.CLEANUP_COMMAND else (0,))
        checked_run([sys.executable, '-I', '-c', 'pass'], timeout=5)


def memory_command(image, docker_cli='docker'):
    return [docker_cli, 'run', '--rm', '--memory=2g', '--memory-swap=2g',
            '--read-only', '--volume', '/tmp', '--shm-size=16m',
            '--pids-limit=128', '--network=none', '--user=0:0',
            '-v', f'{ROOT}:{ROOT}:ro', '-w', str(ROOT), image,
            '/usr/local/bin/python3', str(ROOT / 'scripts/linux_regressions.py'), '--memory-only']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--docker-cli', default='docker')
    parser.add_argument('--memory-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('requires root in a disposable Linux reference sandbox image')
    try:
        if args.memory_only:
            reports = [run_case(name) for name in ('memory', 'memory_aggregate', 'disk')]
        else:
            reports = [run_case(name) for name in ('bytes', 'forks')]
            if shutil.which(args.docker_cli):
                # A present but broken daemon is a failure, never a silent fallback.
                result = checked_run(memory_command(args.image, args.docker_cli), timeout=90)
                reports.extend(json.loads(line) for line in result.stdout.splitlines())
            else:
                if args.docker_cli != 'docker':
                    raise RuntimeError('requested Docker CLI unavailable')
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
