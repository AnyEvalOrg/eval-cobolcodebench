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
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

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
    'sysv_shm': '''import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
libc.shmget.restype = ctypes.c_int
libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
libc.shmat.restype = ctypes.c_void_p
libc.shmdt.argtypes = [ctypes.c_void_p]
libc.shmdt.restype = ctypes.c_int
size = 64 * 1024 * 1024
segments = 0
def check_refusal():
    if segments == 0 and ctypes.get_errno() in (errno.ENOSYS, errno.EPERM, errno.EACCES, errno.EOPNOTSUPP):
        print('sysv-shm-unavailable', flush=True)
        raise SystemExit(1)
    raise SystemExit(2)
while True:
    ident = libc.shmget(0, size, 0o1000 | 0o600)
    if ident == -1:
        check_refusal()
    address = libc.shmat(ident, None, 0)
    if address == ctypes.c_void_p(-1).value:
        check_refusal()
    ctypes.memset(address, 1, size)
    assert libc.shmdt(address) == 0
    # Intentionally no IPC_RMID: no path, fd or RSS retains these bytes.
    segments += 1
''',
    'memfd_mapped_closed': '''import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
block = b'x' * (1024 * 1024)
while True:
    fd = os.memfd_create('candidate')
    remaining = block
    while remaining:
        remaining = remaining[os.write(fd, remaining):]
    # PROT_NONE, MAP_SHARED; libc avoids Python mmap's retained duplicate fd.
    address = libc.mmap(None, 4096, 0, 1, fd, 0)
    assert address != ctypes.c_void_p(-1).value
    os.close(fd)
    # No munmap: each tiny mapping retains the entire populated 1 MiB file.
''',
    'socketpair_queues': '''import os, socket, time
# Stay below per-process NOFILE/AS and aggregate NPROC/RSS while filling
# kernel socket queues. Neither peer consumes the queued bytes.
for _ in range(40):
    if os.fork() == 0:
        os.setsid()
        retained = []
        block = b'x' * (64 * 1024)
        for _ in range(120):
            pair = socket.socketpair()
            retained.extend(pair)
            for peer in pair:
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
                peer.setblocking(False)
                while True:
                    try:
                        peer.send(block)
                    except BlockingIOError:
                        break
        time.sleep(60)
        os._exit(0)
time.sleep(60)
''',
    'ptrace_denied': '''import os
try:
    os.stat('/proc/1/fd/0')
except PermissionError:
    print('ptrace-denied', flush=True)
    raise SystemExit(1)
raise SystemExit(0)
''',
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
    'disk_unlinked': '''import os, tempfile, time
for _ in range(4):
    if os.fork() == 0:
        os.setsid()
        retained = []
        block = b'x' * (1024 * 1024)
        for _ in range(75):
            fd, path = tempfile.mkstemp(prefix='ccb-unlinked-', dir='/tmp')
            os.unlink(path)
            retained.append(fd)
            remaining = block
            while remaining:
                remaining = remaining[os.write(fd, remaining):]
        time.sleep(60)
        os._exit(0)
time.sleep(60)
''',
    'disk_memfd': '''import os, time
# Split across four workers to respect native NOFILE=256 and FSIZE=1 MiB.
for _ in range(4):
    if os.fork() == 0:
        os.setsid()
        retained = []
        block = b'x' * (1024 * 1024)
        for _ in range(75):
            fd = os.memfd_create('candidate')
            retained.append(fd)
            remaining = block
            while remaining:
                remaining = remaining[os.write(fd, remaining):]
        time.sleep(60)
        os._exit(0)
time.sleep(60)
''',
    'disk_entries': '''import os, tempfile, time
other = tempfile.mkdtemp(prefix='ccb-entries-', dir='/tmp')
for i in range(50000):
    open(os.path.join(other, str(i)), 'wb').close()
time.sleep(60)
''',
    'shm_readonly': '''import errno, os
try:
    fd = os.open('/dev/shm/candidate-write', os.O_CREAT | os.O_WRONLY, 0o600)
except OSError as exc:
    if exc.errno == errno.EROFS:
        raise SystemExit(1)
    raise SystemExit(2)
os.close(fd)
raise SystemExit(0)
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


DISK_CASES = ('disk', 'disk_unlinked', 'disk_memfd', 'disk_entries')
KERNEL_CASES = ('sysv_shm', 'memfd_mapped_closed', 'socketpair_queues')
BOUNDED_CASES = ('memory', 'memory_aggregate', *DISK_CASES, 'shm_readonly', 'ptrace_denied', 'detached')
STEPS = frozenset(('startup', 'docker', *CASES))
LABELS = frozenset((
    'unexpected-error', 'exec-completed', 'reserved-uid-unused', 'setup-completed',
    'runner-completed', 'authenticated-receipt', 'incorrect-verdict',
    'expected-receipt', 'cleanup-completed', 'quiescence-completed',
    'smoke-completed', 'docker-completed', 'docker-output', 'docker-inspect',
    'docker-cleanup', 'docker-cli-unavailable',
))
ERROR_CLASSES = frozenset((
    'AssertionError', 'TimeoutExpired', 'TimeoutError', 'JSONDecodeError',
    'UnicodeDecodeError', 'OSError', 'FileNotFoundError', 'PermissionError',
    'ProcessLookupError', 'ValueError', 'TypeError', 'KeyError', 'IndexError',
    'AttributeError', 'MemoryError', 'OverflowError', 'RecursionError',
    'RuntimeError', 'Exception',
))


@contextmanager
def step(name, label='unexpected-error'):
    try:
        yield
    except Exception as error:
        if not hasattr(error, 'regression_step'):
            error.regression_step = name
        if not hasattr(error, 'regression_label'):
            error.regression_label = label
        raise


def require(condition, label):
    if not condition:
        error = AssertionError()
        error.regression_label = label
        raise error


def failure_report(error):
    name = getattr(error, 'regression_step', 'startup')
    label = getattr(error, 'regression_label', 'unexpected-error')
    kind = type(error).__name__
    return dict(stage='regression', step=name if name in STEPS else 'startup',
                error=kind if kind in ERROR_CLASSES else 'Exception',
                label=label if label in LABELS else 'unexpected-error')


def relay_failure(data):
    # Never relay arbitrary nested stdout/stderr or exception messages.
    for line in data.splitlines():
        try:
            report = json.loads(line)
        except (ValueError, TypeError):
            continue
        if (type(report) is dict and set(report) == {'stage', 'step', 'error', 'label'}
                and all(type(value) is str for value in report.values())
                and report['stage'] == 'regression' and report['step'] in STEPS
                and report['error'] in ERROR_CLASSES and report['label'] in LABELS):
            print(json.dumps(report, sort_keys=True), file=sys.stderr, flush=True)


def emit(report):
    print(json.dumps(report, sort_keys=True), flush=True)


LIMIT_PROBE = '''import os, resource
assert os.getresuid() == (65532,) * 3
assert resource.getrlimit(resource.RLIMIT_NPROC) == (64, 64)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (256, 256)
assert resource.getrlimit(resource.RLIMIT_AS) == (1024**3, 1024**3)
assert resource.getrlimit(resource.RLIMIT_DATA) == (1024**3, 1024**3)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (4096, 4096)
assert open('/proc/self/oom_score_adj').read().strip() == '1000'
'''


def checked_run(command, *, label='exec-completed', **kwargs):
    try:
        result = subprocess.run(command, capture_output=True, text=True, **kwargs)
        require(result.returncode == 0, label)
    except Exception as error:
        error.regression_label = label
        raise
    return result


def case_request(name, executable='/usr/local/bin/python3'):
    # Each disk file must fit below FSIZE so this reaches the aggregate disk watchdog.
    limit = 1024 * 1024 if name in (*DISK_CASES, *KERNEL_CASES) else 4096
    probe = LIMIT_PROBE.replace('(4096, 4096)', f'({limit}, {limit})')
    return dict(files={}, argv=[executable, '-I', '-c', 'pass'],
                run_argv=[executable, '-I', '-c', probe + CASES[name]],
                timeout=5, run_timeout=15, output_limit=limit)


def expected_receipt(name, receipt):
    if (receipt['stage'] != 'run' or not receipt['compile_success']
            or any(receipt.get(flag, False) for flag in
                   ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error'))):
        return False
    if name in KERNEL_CASES:
        # Also shared by Kubernetes regressions, where SysV may be unavailable.
        return (receipt.get('memory_exceeded', False) or receipt.get('disk_exceeded', False)
                or sysv_unavailable(name, receipt))
    if name == 'detached':
        return receipt['returncode'] == 0 and not any(receipt.get(f, False) for f in FLAGS)
    if receipt['returncode'] == 0:
        return False
    if name not in {'memory', 'memory_aggregate', 'forks'} and receipt.get('memory_exceeded', False):
        return False
    if name not in DISK_CASES and receipt.get('disk_exceeded', False):
        return False
    if name == 'ptrace_denied':
        return (receipt['returncode'] == 1 and receipt['output'] == 'ptrace-denied\n'
                and not any(receipt.get(f, False) for f in FLAGS))
    if name == 'shm_readonly':
        return receipt['returncode'] == 1 and not any(receipt.get(f, False) for f in FLAGS)
    if name == 'bytes':
        return receipt['output_not_decodable']
    if receipt['output_not_decodable']:
        return False
    if name == 'memory_aggregate':
        return receipt.get('memory_exceeded', False)
    if name in DISK_CASES:
        return receipt.get('disk_exceeded', False)
    if name == 'forks':
        # gVisor charges shared copy-on-write RSS once per child.
        witness = re.fullmatch(r'forks-exhausted ([1-9][0-9]*)\n', receipt['output'])
        return (receipt.get('memory_exceeded', False) or
                (receipt['returncode'] == 1 and witness is not None
                 and 0 < int(witness[1]) < 64))
    return receipt['output'] == 'memory-started\n'


def sysv_unavailable(name, receipt):
    return (name == 'sysv_shm' and receipt['returncode'] == 1
            and receipt['output'] == 'sysv-shm-unavailable\n'
            and not any(receipt.get(flag, False) for flag in FLAGS))


def run_case(name, *, prlimit=False):
    with step(name):
        return _run_case(name, prlimit=prlimit)


def _run_case(name, *, prlimit=False):
    runner, receipts = load_module('sandbox_runner'), load_module('receipts')
    unused = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
    require(unused.returncode == 1, 'reserved-uid-unused')
    setup = None
    try:
        request = case_request(name, sys.executable)
        setup_result = checked_run([sys.executable, '-I', '-c', runner.SETUP],
                                   input=json.dumps(request), timeout=5, label='setup-completed')
        setup = json.loads(setup_result.stdout)
        command = ['timeout', '-s', 'KILL', '30s', sys.executable, '-I', '-c', runner.RUNNER, setup['cwd']]
        if prlimit:
            command = ['prlimit', '--as=1073741824:1073741824',
                       '--data=1073741824:1073741824', '--'] + command
        result = checked_run(command, timeout=35, label='runner-completed')
        receipt = receipts.verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        require(receipt is not None and receipt['cwd'] == setup['cwd'], 'authenticated-receipt')
        # The production scorer returns INCORRECT for every non-None reason.
        require((receipts.receipt_failure(receipt) is None) == (name == 'detached'), 'incorrect-verdict')
        require(expected_receipt(name, receipt), 'expected-receipt')
        if name in KERNEL_CASES:
            # Docker kernel sinks must exercise a resource limit.
            require(receipt.get('memory_exceeded', False) or receipt.get('disk_exceeded', False),
                    'expected-receipt')
            return dict(signed_receipt=True, oom_exit_137=False,
                        sysv_unavailable=sysv_unavailable(name, receipt),
                        **{flag: receipt.get(flag, False) for flag in FLAGS})
        return {field: receipt.get(field, False) for field in ('stage', 'returncode', *FLAGS)}
    finally:
        for command in (runner.CLEANUP_COMMAND, runner.QUIESCENCE_COMMAND):
            result = subprocess.run(command, capture_output=True, timeout=6)
            require(result.returncode in ((0, 1) if command == runner.CLEANUP_COMMAND else (0,)),
                    'cleanup-completed' if command == runner.CLEANUP_COMMAND else 'quiescence-completed')
        checked_run([sys.executable, '-I', '-c', 'pass'], timeout=5, label='smoke-completed')


def memory_command(image, docker_cli='docker'):
    return [docker_cli, 'run', '--rm', '--memory=2g', '--memory-swap=2g',
            '--read-only', '--volume', '/tmp', '--tmpfs', '/dev/shm:ro,size=16m',
            '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID',
            '--cap-add=KILL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE',
            '--cap-add=SYS_PTRACE', '--security-opt=no-new-privileges:true', '--pids-limit=128', '--network=none', '--user=0:0',
            '-v', f'{ROOT}:{ROOT}:ro', '-w', str(ROOT), image,
            '/usr/local/bin/python3', str(ROOT / 'scripts/linux_regressions.py'), '--memory-only']


def kernel_command(image, name, docker_cli='docker', *, container_name):
    command = memory_command(image, docker_cli)[:-1] + ['--kernel-case', name]
    command[command.index('--rm'):command.index('--rm') + 1] = ['--name', container_name]
    return command


def run_kernel_container(image, name, docker_cli):
    # Retain each isolated container until OOM inspection, then remove its /tmp
    # volume too. Exit 137 is an allowed regression outcome, not production proof.
    container_name = 'ccb-kernel-' + uuid.uuid4().hex
    report = dict(case=name, nested_returncode=None, signed_receipt=False,
                  oom_exit_137=False, oom_killed=False, sysv_unavailable=False,
                  **dict.fromkeys(FLAGS, False))
    with step(name):
        try:
            try:
                with step(name, 'docker-completed'):
                    result = subprocess.run(kernel_command(image, name, docker_cli, container_name=container_name),
                                            capture_output=True, text=True, timeout=60)
                report.update(nested_returncode=result.returncode, oom_exit_137=result.returncode == 137)
                with step(name, 'docker-inspect'):
                    inspected = subprocess.run([docker_cli, 'inspect', '--format', '{{.State.OOMKilled}}', container_name],
                                               capture_output=True, text=True, timeout=10)
                    require(inspected.returncode == 0 and inspected.stdout.strip() in ('true', 'false'), 'docker-inspect')
                    report['oom_killed'] = inspected.stdout.strip() == 'true'
                if report['oom_exit_137'] or report['oom_killed']:
                    return report
                relay_failure(getattr(result, 'stderr', ''))
                require(result.returncode == 0, 'docker-completed')
                with step(name, 'docker-output'):
                    child = json.loads(result.stdout)
                    require(type(child) is dict and set(child) == {*FLAGS, 'signed_receipt', 'oom_exit_137', 'sysv_unavailable'}
                            and all(type(value) is bool for value in child.values()), 'docker-output')
                report.update(child)
                require(child['signed_receipt'] and not child['oom_exit_137']
                        and not child['sysv_unavailable']
                        and (child['memory_exceeded'] or child['disk_exceeded'])
                        and not any(child[flag] for flag in ('timeout', 'overflow', 'cleanup_failed', 'supervisor_error')),
                        'expected-receipt')
                return report
            finally:
                original_error = sys.exc_info()[1]
                try:
                    with step(name, 'docker-cleanup'):
                        cleaned = subprocess.run([docker_cli, 'rm', '--force', '--volumes', container_name],
                                                 capture_output=True, timeout=10)
                        require(cleaned.returncode == 0, 'docker-cleanup')
                except Exception:
                    # Preserve the primary diagnostic if cleanup also fails.
                    if original_error is None:
                        raise
        except Exception:
            emit(report)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--docker-cli', default='docker')
    parser.add_argument('--memory-only', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--kernel-case', choices=KERNEL_CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('requires root in a disposable Linux reference sandbox image')

    def report_case(name, **kwargs):
        with step(name):
            emit(run_case(name, **kwargs))

    try:
        if args.kernel_case:
            report_case(args.kernel_case)
        elif args.memory_only:
            for name in BOUNDED_CASES:
                report_case(name)
        else:
            for name in ('bytes', 'forks'):
                report_case(name)
            if shutil.which(args.docker_cli):
                # A present but broken daemon is a failure, never a silent fallback.
                with step('docker', 'docker-completed'):
                    result = subprocess.run(memory_command(args.image, args.docker_cli),
                                            capture_output=True, text=True, timeout=300)
                    relay_failure(result.stderr)
                    require(result.returncode == 0, 'docker-completed')
                    with step('docker', 'docker-output'):
                        reports = [json.loads(line) for line in result.stdout.splitlines()]
                        require(len(reports) == len(BOUNDED_CASES), 'docker-output')
                        for report in reports:
                            # Validate values too: a permitted field can contain private text.
                            require(type(report) is dict and set(report) == {'stage', 'returncode', *FLAGS}
                                    and report['stage'] in ('compile', 'run')
                                    and type(report['returncode']) is int
                                    and all(type(report[flag]) is bool for flag in FLAGS), 'docker-output')
                            emit(report)
                for name in KERNEL_CASES:
                    with step(name):
                        emit(run_kernel_container(args.image, name, args.docker_cli))
            else:
                require(args.docker_cli == 'docker', 'docker-cli-unavailable')
                report_case('memory', prlimit=True)
        return 0
    except Exception as error:
        # No exception chains, stdout/stderr, candidates or receipt keys.
        print(json.dumps(failure_report(error), sort_keys=True), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
