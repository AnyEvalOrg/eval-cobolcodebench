"""Opt-in real Linux regressions; run only in a disposable reserved-UID sandbox."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import pytest
from cobolcodebench.sandbox_runner import SETUP, RUNNER, CLEANUP_COMMAND, QUIESCENCE_COMMAND
from cobolcodebench.scoring import cleanup_candidate, verify_receipt

pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or os.geteuid() != 0 or os.environ.get('CCB_LINUX_CONTAINMENT') != '1',
    reason='requires root in a disposable Linux sandbox, unused UID 65532, and CCB_LINUX_CONTAINMENT=1',
)


def require_unused_uid():
    result = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
    assert result.returncode == 1, 'candidate UID must be unused before containment tests'


def prepare(code):
    require_unused_uid()
    request = dict(files={}, argv=[sys.executable, '-I', '-c', 'pass'],
                   run_argv=[sys.executable, '-I', '-c', code], timeout=5, run_timeout=5, output_limit=4096)
    result = subprocess.run([sys.executable, '-I', '-c', SETUP], input=json.dumps(request),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    return json.loads(result.stdout)


def independent_cleanup():
    for command in (CLEANUP_COMMAND, QUIESCENCE_COMMAND):
        result = subprocess.run(command, capture_output=True, timeout=6)
        assert result.returncode in ((0, 1) if command == CLEANUP_COMMAND else (0,))


def process_running(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in {'Z', 'X'}
    except FileNotFoundError:
        return False


def test_real_credentials_protected_supervisor_and_detached_descendant_cleanup():
    code = '''import json, os, signal, time
assert os.getresuid() == (65532,)*3 and os.getresgid() == (65532,)*3
assert os.getgroups() == []
status = dict(line.split(':',1) for line in open('/proc/self/status'))
assert all(int(status[k],16) == 0 for k in ('CapEff','CapPrm','CapAmb'))
assert int(status['NoNewPrivs']) == 1
try:
    os.kill(os.getppid(), signal.SIGKILL)
except PermissionError:
    pass
else:
    raise SystemExit(2)
try:
    open(f'/proc/{os.getppid()}/mem','rb')
except PermissionError:
    pass
else:
    raise SystemExit(3)
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open('detached-ready','w').close()
    while True: time.sleep(0.1)
while not os.path.exists('detached-ready'): time.sleep(0.01)
print(pid, flush=True)
'''
    setup = prepare(code)
    try:
        result = subprocess.run([sys.executable, '-I', '-c', RUNNER, setup['cwd']],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0
        receipt = verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        assert receipt and receipt['returncode'] == 0 and receipt['stage'] == 'run'
        assert not process_running(int(receipt['output']))
        assert Path(setup['cwd']).exists()
        independent_cleanup()
        assert not Path(setup['cwd']).exists()
    finally:
        independent_cleanup()
        shutil.rmtree(setup['cwd'], ignore_errors=True)


def test_independent_cleanup_after_supervisor_death():
    code = '''import ctypes, json, os, signal, time
ctypes.CDLL(None).prctl(1, 0, 0, 0, 0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open('ready.tmp','w') as f: json.dump({'pid':os.getpid(), 'parent':os.getppid()}, f)
os.rename('ready.tmp','ready')
while True: time.sleep(0.1)
'''
    setup = prepare(code)
    supervisor = subprocess.Popen([sys.executable, '-I', '-c', RUNNER, setup['cwd']],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready = Path(setup['cwd'])/'candidate/ready'
        until = time.monotonic()+4
        while not ready.exists() and time.monotonic() < until:
            time.sleep(0.01)
        assert ready.exists()
        info = json.loads(ready.read_text())
        assert info['parent'] == supervisor.pid
        os.kill(supervisor.pid, signal.SIGKILL)
        supervisor.communicate(timeout=3)
        assert process_running(info['pid'])

        class DirectSandbox:
            async def exec(self, command, **kwargs):
                from inspect_ai.util import ExecResult
                result = subprocess.run(command, capture_output=True, text=True, timeout=6)
                return ExecResult(success=result.returncode == 0, returncode=result.returncode,
                                  stdout=result.stdout, stderr=result.stderr)

        asyncio.run(cleanup_candidate(DirectSandbox()))
        assert not process_running(info['pid'])
    finally:
        independent_cleanup()
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=3)
        shutil.rmtree(setup['cwd'], ignore_errors=True)
