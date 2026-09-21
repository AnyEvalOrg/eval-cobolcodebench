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
        source = source.replace('def candidate_rss():',
                                'def candidate_rss(): return 0\n\ndef unused_candidate_rss():')
        source = source.replace('def candidate_disk_bytes(roots=("/tmp", "/dev/shm")):',
                                'def candidate_disk_bytes(): return 0\n\ndef unused_candidate_disk_bytes(roots=("/tmp", "/dev/shm")):')
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
        # Directory deletion belongs only to the independent exec.
        assert Path(setup['cwd']).exists()
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


@pytest.mark.parametrize('operation', ['kill_group(child.pid)', 'sweep_uid()', 'stdout.seek(0)'])
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


@pytest.mark.parametrize('rss_kib, exceeded', [(768 * 1024, False), (768 * 1024 + 1, True)])
def test_watchdog_sums_only_candidate_rss_and_kills_detached_sessions(rss_kib, exceeded):
    from io import StringIO
    from types import SimpleNamespace
    from unittest.mock import Mock
    import signal
    tree = ast.parse(RUNNER)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                 n.name in {'candidate_rss', 'kill_candidate', 'watch_memory'}]
    proc = {
        '11': f'Uid:\t65532 65532 65532 65532\nVmRSS:\t{rss_kib // 2} kB\n',
        '12': f'Uid:\t65532 65532 65532 65532\nVmRSS:\t{rss_kib - rss_kib // 2} kB\n',
        '13': 'Uid:\t0 0 0 0\nVmRSS:\t9999999 kB\n',
        '14': 'Uid:\t65532 65532 65532 65532\nState:\tZ (zombie)\n',
    }
    def opened(path):
        pid = path.split('/')[2]
        if pid == '15':
            raise FileNotFoundError(path)
        return StringIO(proc[pid])
    fake_os = SimpleNamespace(listdir=lambda _: [*proc, '15', 'self'], kill=Mock(), killpg=Mock())
    stopped = Mock()
    stopped.is_set.side_effect = [False, True]
    namespace = dict(os=fake_os, open=opened, signal=signal, CANDIDATE_UID=65532)
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<watchdog>', 'exec'), namespace)
    assert namespace['candidate_rss']() == rss_kib * 1024
    status = dict(memory_exceeded=False)
    namespace['watch_memory'](11, stopped, status)
    assert status == dict(memory_exceeded=exceeded)
    if exceeded:
        fake_os.killpg.assert_called_once_with(11, signal.SIGKILL)
        assert [call.args for call in fake_os.kill.call_args_list] == [
            (11, signal.SIGKILL), (12, signal.SIGKILL), (14, signal.SIGKILL)]
        stopped.wait.assert_not_called()
    else:
        fake_os.kill.assert_not_called()
        stopped.wait.assert_called_once_with(0.05)


@pytest.mark.parametrize('stage', ['compile', 'run'])
@pytest.mark.parametrize('resource_name', ['memory', 'disk'])
def test_watchdog_flag_is_signed_and_blocks_success(stage, resource_name):
    # The watcher marks the flag even if the candidate happened to exit 0.
    def transform(source):
        condition = ('if candidate_rss() > 768 * 1024**2:' if resource_name == 'memory'
                     else 'if candidate_disk_bytes() > 256 * 1024**2:')
        return source.replace(condition,
                              f'if stage == {stage!r}:').replace(
            'kill_candidate(pgid)\n', 'pass\n')
    receipt = run_fixture(run_code="print('run')", transform=transform)
    from cobolcodebench.receipts import receipt_failure
    assert receipt[resource_name + '_exceeded']
    assert receipt['stage'] == stage
    assert receipt['compile_success'] is (stage == 'run')
    assert receipt_failure(receipt) == resource_name + ' limit exceeded'


@pytest.mark.parametrize('hang', [False, True])
def test_receipt_complete_before_any_deletion_and_hanging_deletion_cannot_delay_it(tmp_path, hang):
    marker = tmp_path / 'deletion-attempted'
    def transform(source):
        return f'''import shutil
def forbidden_deletion(*args, **kwargs):
    open({str(marker)!r}, 'w').close()
    {'__import__("time").sleep(60)' if hang else 'raise AssertionError("deletion before receipt")'}
shutil.rmtree = forbidden_deletion
''' + source
    receipt = run_fixture(transform=transform)
    assert receipt['returncode'] == 0 and not receipt['cleanup_failed']
    assert not marker.exists()
    final = ast.parse(RUNNER).body[-1].finalbody
    assert [ast.unparse(n) for n in final[-3:]] == [
        "sys.stdout.write(json.dumps({'body': body, 'tag': tag}))",
        'sys.stdout.flush()', 'os._exit(0)',
    ]
    assert 'exec rm -rf -- /tmp/ccb-*' in QUIESCENCE_COMMAND[-1]
    assert QUIESCENCE_COMMAND[:4] == ['timeout', '-s', 'KILL', '5s']


@pytest.mark.parametrize('exceeded', [False, True])
def test_disk_watchdog_counts_allocated_blocks_across_both_roots(tmp_path, exceeded):
    import errno
    import stat
    from unittest.mock import Mock
    tmp, shm, outside = [tmp_path / name for name in ('tmp', 'shm', 'outside')]
    for directory in (tmp / 'work', tmp / 'sibling', shm, outside):
        directory.mkdir(parents=True)
    files = [tmp / 'work' / 'file', tmp / 'sibling' / 'file', shm / 'file']
    for path in files:
        path.write_bytes(b'x' * 8192)
    (outside / 'ignored').write_bytes(b'x' * 8192)
    (tmp / 'linked-directory').symlink_to(outside, target_is_directory=True)
    (shm / 'linked-file').symlink_to(files[0])
    os.mkfifo(tmp / 'fifo')
    sparse = tmp / 'sparse'
    with sparse.open('wb') as stream:
        stream.truncate(1024**3)
    files.append(sparse)
    expected = sum(path.stat().st_blocks * 512 for path in files)
    assert expected < sparse.stat().st_size
    tree = ast.parse(RUNNER)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and
                 n.name in {'candidate_disk_bytes', 'watch_disk'}]
    namespace = dict(os=os, errno=errno, stat=stat, kill_candidate=Mock())
    # Use a small threshold with real allocated files, preserving the strict
    # production comparison. Avoid allocating 256 MiB on the developer host.
    source = ast.unparse(ast.Module(body=functions, type_ignores=[]))
    source = source.replace('256 * 1024 ** 2', str(expected - int(exceeded)))
    exec(compile(source, '<disk-watchdog>', 'exec'), namespace)
    scan = namespace['candidate_disk_bytes']
    roots = (str(tmp), str(shm))
    assert scan(roots) == expected
    namespace['candidate_disk_bytes'] = lambda: scan(roots)
    stopped = Mock()
    stopped.is_set.side_effect = [False, True]
    status = dict(disk_exceeded=False)
    namespace['watch_disk'](123, stopped, status)
    assert status == dict(disk_exceeded=exceeded)
    if exceeded:
        namespace['kill_candidate'].assert_called_once_with(123)
        stopped.wait.assert_not_called()
    else:
        namespace['kill_candidate'].assert_not_called()
        stopped.wait.assert_called_once_with(0.1)


@pytest.mark.parametrize('race', ['deleted', 'symlink'])
def test_disk_walk_tolerates_directory_races_without_following_symlinks(tmp_path, monkeypatch, race):
    import errno
    import stat
    root, outside = tmp_path / 'root', tmp_path / 'outside'
    root.mkdir()
    outside.mkdir()
    (outside / 'ignored').write_bytes(b'x' * 8192)
    changing = root / 'changing'
    changing.mkdir()
    original_open = os.open

    def raced_open(path, flags, **kwargs):
        if path == 'changing':
            changing.rmdir()
            if race == 'symlink':
                changing.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, **kwargs)

    monkeypatch.setattr(os, 'open', raced_open)
    function = next(n for n in ast.parse(RUNNER).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'candidate_disk_bytes')
    namespace = dict(os=os, errno=errno, stat=stat)
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<disk-walk>', 'exec'), namespace)
    assert namespace['candidate_disk_bytes']((str(root), str(tmp_path / 'missing'))) == 0


@pytest.mark.parametrize('failure', ['raise OSError("scan failed")', '__import__("time").sleep(60)'])
def test_disk_scan_failure_or_hang_cannot_suppress_signed_receipt(failure):
    def transform(source):
        return source.replace('def candidate_disk_bytes(): return 0',
                              'def candidate_disk_bytes(): ' + failure).replace(
            'def kill_candidate(pgid):',
            'def kill_candidate(pgid): pass\n\ndef unused_kill_candidate(pgid):')
    receipt = run_fixture(compile_code='raise SystemExit(1)', transform=transform)
    assert receipt['supervisor_error']
    assert receipt['returncode'] == 1
