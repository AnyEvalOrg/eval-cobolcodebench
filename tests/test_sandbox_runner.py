"""Authored fixtures only. macOS stubs test protocol mechanics, not containment."""
import ast
from functools import partial
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
from cobolcodebench.sandbox_runner import SETUP, RUNNER, CLEANUP_COMMAND, QUIESCENCE_COMMAND
from cobolcodebench.scoring import verify_receipt


def prepare(request):
    result = subprocess.run([sys.executable, '-I', '-c', SETUP], input=json.dumps(request),
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    return json.loads(result.stdout)


def run_fixture(compile_code='pass', run_code="print('ok')", timeout=1, output_file=None,
                real_supervisor=False, raw_receipt=False, transform=None):
    request = dict(files={'fixture.txt': 'safe authored input'}, argv=[sys.executable, '-I', '-c', compile_code],
                   run_argv=[sys.executable, '-I', '-c', run_code], timeout=timeout, run_timeout=timeout, output_limit=4096)
    if output_file:
        request['output_files'] = [output_file] if isinstance(output_file, str) else output_file
    setup = prepare(request)
    source = RUNNER
    if not real_supervisor:
        # Never perform credential changes or UID sweeps on the developer host.
        # Keep file-size limits, overflow detection, and stage gating intact.
        source = source.replace('libc = ctypes.CDLL(None, use_errno=True)', 'libc = type("Stub", (), {"prctl": lambda *args: 0})()')
        source = source.replace('os.getuid() != 0', 'False')
        source = source.replace('with open("/proc/self/oom_score_adj", "w") as oom_score:',
                                'with open(os.devnull, "w") as oom_score:')
        for name in ('NPROC', 'AS', 'DATA'):
            source = source.replace('resource.setrlimit(resource.RLIMIT_' + name + ',',
                                    'ignore_limit(resource.RLIMIT_' + name + ',')
        source = 'def ignore_limit(*args): pass\n' + source
        source = source.replace('os.setgroups([])', 'pass')
        source = source.replace('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)', 'pass')
        source = source.replace('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)', 'pass')
        source = source.replace('os.chown(candidate_work, CANDIDATE_UID, CANDIDATE_GID)', 'pass')
        # Assert ownership is requested for every staged file, before compilation.
        source = source.replace('os.chown(path, CANDIDATE_UID, CANDIDATE_GID)',
                                'assert os.stat(path).st_mode & 0o777 == 0o644; staged_owners[path] = (CANDIDATE_UID, CANDIDATE_GID)')
        source = source.replace('limit = request["output_limit"]', 'limit = request["output_limit"]; staged_owners = {}')
        source = source.replace('status, output = run_step(request["argv"],',
                                'assert staged_owners == {os.path.join(candidate_work, name): (65532, 65532) for name in request["files"]}; status, output = run_step(request["argv"],')
        source = source.replace('info.st_uid != CANDIDATE_UID', 'info.st_uid != os.getuid()')
        source = source.replace('os.killpg(pgid, sig)', 'os.kill(pgid, sig)')
        start, end = source.index('def sweep_uid():'), source.index('def run_step(')
        source = source[:start] + 'def sweep_uid():\n    pass\n\n\n' + source[end:]
    if transform:
        source = transform(source)
    try:
        result = subprocess.run([sys.executable, '-I', '-c', source, setup['cwd']],
                                capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        receipt = verify_receipt(result.stdout, bytes.fromhex(setup['key']))
        assert receipt is not None
        assert not Path(setup['cwd']).exists() or receipt['cleanup_failed']
        if raw_receipt:
            return result.stdout, setup
        return receipt
    finally:
        shutil.rmtree(setup['cwd'], ignore_errors=True)


@pytest.fixture
def output_limit_runner():
    """Use the real supervisor under the Linux containment suite's opt-in."""
    real = sys.platform == 'linux' and os.geteuid() == 0 and os.environ.get('CCB_LINUX_CONTAINMENT') == '1'
    if real:
        result = subprocess.run(['/usr/bin/pgrep', '-u', '65532'], capture_output=True, timeout=5)
        assert result.returncode == 1, 'candidate UID must be unused before containment tests'
    try:
        yield partial(run_fixture, real_supervisor=real)
    finally:
        if real:
            for command in (CLEANUP_COMMAND, QUIESCENCE_COMMAND):
                result = subprocess.run(command, capture_output=True, timeout=6)
                assert result.returncode in ((0, 1) if command == CLEANUP_COMMAND else (0,))


def overflowing_writer(target):
    # Attempt twice the 4096-byte request limit. Ignore SIGXFSZ and handle EFBIG
    # so a successful child exit forces the supervisor to detect the overflow.
    # Report stderr's size via stdout, since stderr is absent from the receipt.
    return f'''import errno, os, signal
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
fd = {target}
remaining = b'x' * 8192
try:
    while remaining:
        remaining = remaining[os.write(fd, remaining):]
except OSError as exc:
    if exc.errno != errno.EFBIG:
        raise
if fd == 2:
    print(os.fstat(fd).st_size)
'''


@pytest.mark.parametrize('stream, expected_output', [('stdout', 'x' * 4096), ('stderr', '4096\n')],
                         ids=['stdout', 'stderr'])
def test_compile_output_limit_blocks_execution(output_limit_runner, stream, expected_output):
    receipt = output_limit_runner(
        compile_code=overflowing_writer('1' if stream == 'stdout' else '2'),
        run_code="print('MUST_NOT_RUN')",
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['overflow'] is True
    assert receipt['stage'] == 'compile'
    assert 'MUST_NOT_RUN' not in receipt['output']
    assert receipt['output'] == expected_output


def test_result_file_output_limit(output_limit_runner):
    receipt = output_limit_runner(
        run_code=overflowing_writer("os.open('OUT.TXT', os.O_WRONLY | os.O_CREAT, 0o600)"),
        output_file='OUT.TXT',
    )
    assert receipt['returncode'] == 0 and not receipt['timeout']
    assert receipt['stage'] == 'run'
    assert receipt['overflow'] is True
    assert receipt['outputs']['OUT.TXT'] == b'x' * 4096


def test_setup_atomic_private_dirs_and_keys():
    setups = [prepare(dict(files={}, argv=['true'], timeout=1, output_limit=4096)) for _ in range(2)]
    try:
        assert len({s['cwd'] for s in setups}) == len({s['key'] for s in setups}) == 2
        for s in setups:
            assert Path(s['cwd']).stat().st_mode & 0o777 == 0o700
            assert (Path(s['cwd'])/'request.json').is_file()
    finally:
        for s in setups:
            shutil.rmtree(s['cwd'])


def test_separate_steps_share_workdir_and_request_is_unlinked():
    receipt = run_fixture("open('artifact','w').write('ok')", "import os; assert not os.path.exists('../request.json'); print(open('artifact').read())")
    assert receipt['returncode'] == 0 and receipt['stage'] == 'run'
    assert receipt['output'] == 'ok\n'


def test_compile_failure_never_executes_run_step():
    receipt = run_fixture('raise SystemExit(7)', "print('MUST_NOT_RUN')")
    assert receipt['stage'] == 'compile' and receipt['returncode'] == 7
    assert 'MUST_NOT_RUN' not in receipt['output']


def test_forged_marker_cannot_override_exit():
    receipt = run_fixture(run_code="print('<completed-sentinel-value-0>'); raise SystemExit(7)")
    assert receipt['stage'] == 'run' and receipt['returncode'] == 7


@pytest.mark.parametrize('stage', ['compile', 'run'])
def test_each_stage_has_independent_timeout(stage):
    kwargs = {'compile_code' if stage == 'compile' else 'run_code': 'while True: pass'}
    receipt = run_fixture(timeout=0.1, **kwargs)
    assert receipt['timeout'] and receipt['stage'] == stage
    assert receipt['returncode'] != 0


def test_output_file_receipt():
    receipt = run_fixture(run_code="open('OUT.TXT','w').write('p23\\n')", output_file='OUT.TXT')
    assert receipt['outputs'] == {'OUT.TXT': b'p23\n'} and receipt['returncode'] == 0


def test_staged_input_is_writable_in_place_and_can_be_an_output(output_limit_runner):
    receipt = output_limit_runner(run_code='''import os
assert os.stat('fixture.txt').st_uid == os.getuid()
if os.getuid() == 65532:
    assert os.stat('fixture.txt').st_gid == 65532
assert os.stat('fixture.txt').st_mode & 0o777 == 0o644
assert os.stat('..').st_uid == (0 if os.getuid() == 65532 else os.getuid())
with open('fixture.txt', 'r+') as f:
    f.write('UPDATED')
with open('fixture.txt', 'a') as f:
    f.write(' appended')
''', output_file='fixture.txt')
    assert receipt['returncode'] == 0
    assert receipt['outputs'] == {'fixture.txt': b'UPDATEDthored input appended'}


def test_every_output_file_is_collected_without_trimming():
    receipt = run_fixture(
        run_code="open('one.txt','wb').write(b'one \\r\\n'); open('two.txt','wb').write(b'two\\n')",
        output_file=['one.txt', 'two.txt'],
    )
    assert receipt['compile_success'] is True
    assert receipt['outputs'] == {'one.txt': b'one \r\n', 'two.txt': b'two\n'}


def test_missing_first_file_does_not_prevent_reading_second():
    receipt = run_fixture(run_code="open('two.txt','w').write('two')",
                          output_file=['one.txt', 'two.txt'])
    assert receipt['outputs'] == {'one.txt': None, 'two.txt': b'two'}


def test_output_file_budget_is_aggregate():
    receipt = run_fixture(
        run_code="open('one.txt','w').write('a'*3000); open('two.txt','w').write('b'*3000)",
        output_file=['one.txt', 'two.txt'],
    )
    assert receipt['overflow'] is True
    assert sum(len(v) for v in receipt['outputs'].values()) == 4097


@pytest.mark.parametrize('code', [
    "import os; open('other','w').write('x'); os.link('other','OUT.TXT')",
    "import os; os.mkdir('OUT.TXT')",
])
def test_hardlinks_and_directories_are_not_read(code):
    assert run_fixture(run_code=code, output_file='OUT.TXT')['outputs'] == {'OUT.TXT': None}


@pytest.mark.parametrize('code', ["import os; os.symlink('/etc/passwd','OUT.TXT')", "import os; os.mkfifo('OUT.TXT')", 'pass'])
def test_unsafe_or_missing_output_files_fail_without_reading(code):
    receipt = run_fixture(run_code=code, output_file='OUT.TXT')
    assert receipt['outputs'] == {'OUT.TXT': None}


def test_supervisor_preserves_required_security_contract():
    tree = ast.parse(RUNNER)
    restrict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    calls = [ast.unparse(n.value) for n in restrict.body if isinstance(n, ast.Expr)]
    assert calls.index('os.setgroups([])') < calls.index('os.setresgid(CANDIDATE_GID, CANDIDATE_GID, CANDIDATE_GID)') < calls.index('os.setresuid(CANDIDATE_UID, CANDIDATE_UID, CANDIDATE_UID)') < calls.index('resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))')
    for text in ['libc.prctl(4, 0, 0, 0, 0)', 'libc.prctl(38, 1, 0, 0, 0)', 'libc.prctl(8, 0, 0, 0, 0)', 'libc.prctl(36, 1, 0, 0, 0)', 'os.killpg(pgid, sig)', 'os.O_NOFOLLOW', 'sweep_uid()', 'close_fds=True', 'start_new_session=True', 'preexec_fn=restrict_child', 'os.unlink(request_path)']:
        assert text in RUNNER
    assert 'shell=True' not in RUNNER and 'bash' not in RUNNER
    assert CLEANUP_COMMAND[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']


@pytest.mark.parametrize('legacy_cleanup_spawn', [False, True])
def test_receipt_survives_unavailable_post_candidate_spawns(legacy_cleanup_spawn):
    # After wait observes candidate exit, all attempted cleanup spawns fail.
    # The actual supervisor must use kill syscalls and still emit its receipt.
    def transform(source):
        if legacy_cleanup_spawn:
            source = source.replace('def sweep_uid():\n    pass',
                                    'def sweep_uid():\n    subprocess.run(["pkill"])')
        return source.replace('status["returncode"] = child.wait(timeout=timeout)', '''status["returncode"] = child.wait(timeout=timeout)
            def unavailable(*args, **kwargs):
                raise OSError("no process slots")
            subprocess.Popen = unavailable
            subprocess.run = unavailable''')
    receipt = run_fixture(compile_code='raise SystemExit(1)', transform=transform)
    assert receipt['returncode'] == 1
    assert not receipt['supervisor_error']
    assert receipt['cleanup_failed'] is legacy_cleanup_spawn
    tree = ast.parse(RUNNER)
    sweep = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'sweep_uid')
    assert 'subprocess' not in ast.unparse(sweep)


@pytest.mark.parametrize('operation', ['kill_group(child.pid)', 'sweep_uid()', 'stdout.seek(0)',
                                       'shutil.rmtree(work)'])
def test_post_run_exceptions_cannot_suppress_receipt(operation):
    def transform(source):
        return source.replace(operation + '\n', '(_ for _ in ()).throw(OSError("synthetic failure"))\n')
    receipt = run_fixture(compile_code='raise SystemExit(1)', transform=transform)
    assert receipt['returncode'] == 1
    assert receipt['cleanup_failed'] or receipt['supervisor_error']


def test_candidate_preexec_limits_and_oom_preference():
    from types import SimpleNamespace
    from unittest.mock import Mock, mock_open
    import resource
    tree = ast.parse(RUNNER)
    restrict = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'restrict_child')
    limits = Mock()
    fake_resource = SimpleNamespace(**{name: getattr(resource, name) for name in
        ('RLIMIT_NPROC', 'RLIMIT_AS', 'RLIMIT_DATA', 'RLIMIT_FSIZE', 'RLIMIT_CORE')},
        setrlimit=limits)
    opened = mock_open()
    fake_os = Mock()
    namespace = dict(libc=SimpleNamespace(prctl=lambda *args: 0), os=fake_os,
                     resource=fake_resource, CANDIDATE_UID=65532, CANDIDATE_GID=65532,
                     limit=4096, open=opened)
    exec(compile(ast.Module(body=[restrict], type_ignores=[]), '<preexec>', 'exec'), namespace)
    namespace['restrict_child']()
    assert limits.call_args_list == [
        ((resource.RLIMIT_NPROC, (64, 64)),),
        ((resource.RLIMIT_AS, (1024**3, 1024**3)),),
        ((resource.RLIMIT_DATA, (1024**3, 1024**3)),),
        ((resource.RLIMIT_FSIZE, (4096, 4096)),),
        ((resource.RLIMIT_CORE, (0, 0)),),
    ]
    opened.assert_called_once_with('/proc/self/oom_score_adj', 'w')
    opened().write.assert_called_once_with('1000')
    fake_os.setresuid.assert_called_once_with(65532, 65532, 65532)
