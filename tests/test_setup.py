"""Prerequisite checks without credential changes or Linux /proc on the host."""
import ast
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, mock_open

import pytest

from cobolcodebench.sandbox_runner import RUNNER, SETUP


def source_nodes(source, kind):
    return [node for node in ast.parse(source).body if isinstance(node, kind)]


@pytest.mark.parametrize('source', [SETUP, RUNNER], ids=['setup', 'runner'])
def test_restrict_child_irreversibly_clears_capabilities_in_order(source):
    restrict = next(n for n in source_nodes(source, ast.FunctionDef) if n.name == 'restrict_child')
    events = Mock()
    events.prctl.return_value = 0
    namespace = dict(libc=SimpleNamespace(prctl=events.prctl), os=events,
                     resource=Mock(), CANDIDATE_UID=65532,
                     CANDIDATE_GID=65532, limit=4096, open=mock_open())
    exec(compile(ast.Module(body=[restrict], type_ignores=[]), '<restrict>', 'exec'), namespace)
    namespace['restrict_child']()
    assert events.mock_calls == [
        call.prctl(38, 1, 0, 0, 0),  # NO_NEW_PRIVS before any UID change
        call.prctl(8, 0, 0, 0, 0),   # KEEPCAPS=0 before setresuid
        call.setgroups([]),
        call.setresgid(65532, 65532, 65532),
        call.setresuid(65532, 65532, 65532),
    ]


@pytest.fixture
def setup_probe(tmp_path):
    fault = dict(at=None)
    seen = []
    child = Mock(pid=314)
    child.wait.return_value = -9

    def step(name):
        seen.append(name)
        if fault['at'] == name:
            raise PermissionError('private diagnostic must never escape')

    def mkdtemp(*, prefix, dir):
        import tempfile
        step('work_directory' if dir == '/tmp' else 'probe_directory')
        return tempfile.mkdtemp(prefix=prefix, dir=tmp_path if dir == '/tmp' else dir)

    def opened(path, mode='r', **kwargs):
        if path == '/proc/self/oom_score_adj':
            step('oom_open')
            stream = Mock(wraps=io.StringIO('0\n'))
            stream.write.side_effect = lambda value: step('oom_write')
            context = mock_open()
            context.return_value.__enter__.return_value = stream
            return context()
        if path == '/proc/314/status':
            step('status_read')
            status = 'Uid:\t65532 65532 65532 65532\nVmRSS:\t16 kB\n'
            if fault['at'] == 'wrong_uid':
                status = status.replace('65532', '0', 1)
            if fault['at'] == 'missing_rss':
                status = status.split('VmRSS:')[0]
            return io.StringIO(status)
        if Path(path).name == 'executable':
            step('script_write')
        return open(path, mode, **kwargs)

    def stat(path):
        if path == '/proc/314/fd/0':
            step('descriptor_stat')
            return SimpleNamespace()
        if Path(path).name == 'writable':
            step('child_write')
            assert Path(path).is_file()
            return SimpleNamespace(st_uid=65532)
        return os.stat(path)

    def chmod(path, mode):
        if Path(path).name == 'executable':
            step('script_chmod')
        os.chmod(path, mode)

    def popen(argv, **kwargs):
        step('child_spawn')
        assert argv[-1] == 'import time; time.sleep(2)'
        assert kwargs['preexec_fn'] is namespace['restrict_child']
        assert kwargs['close_fds']
        return child

    def run(argv, **kwargs):
        step('script_exec')
        script = Path(argv[0])
        assert script.read_text() == '#!/bin/sh\n: > writable\n'
        assert script.stat().st_mode & 0o777 == 0o755
        assert kwargs['preexec_fn'] is namespace['restrict_child']
        assert kwargs['check'] and kwargs['timeout'] == 1
        Path(kwargs['cwd'], 'writable').touch()

    namespace = dict(
        os=SimpleNamespace(path=os.path, getuid=lambda: 0, listdir=lambda p: step('proc_list'),
                           chown=lambda *a: step('probe_owner'), chmod=chmod, stat=stat),
        libc=SimpleNamespace(prctl=lambda *a: 0), CANDIDATE_UID=65532, CANDIDATE_GID=65532,
        tempfile=SimpleNamespace(mkdtemp=mkdtemp), open=opened,
        subprocess=SimpleNamespace(Popen=Mock(side_effect=popen), run=Mock(side_effect=run), DEVNULL=-3),
        shutil=__import__('shutil'), json=json, secrets=SimpleNamespace(token_hex=Mock(return_value='ab' * 32)),
        sys=SimpleNamespace(stdin=io.StringIO(json.dumps(dict(files={'candidate': 'NEVER RUN'}))),
                            stdout=io.StringIO(), executable='/usr/local/bin/python3'),
    )
    exec(compile(ast.Module(body=source_nodes(SETUP, ast.FunctionDef), type_ignores=[]),
                 '<setup-functions>', 'exec'), namespace)
    return namespace, fault, seen, child


def execute_setup(namespace):
    exec(compile(ast.Module(body=source_nodes(SETUP, ast.Try), type_ignores=[]),
                 '<setup>', 'exec'), namespace)


def test_setup_prerequisites_happy_path(setup_probe):
    namespace, _, seen, child = setup_probe
    execute_setup(namespace)
    result = json.loads(namespace['sys'].stdout.getvalue())
    work = Path(result['cwd'])
    assert result['key'] == 'ab' * 32
    assert work.stat().st_mode & 0o777 == 0o700
    assert list(work.iterdir()) == [work / 'request.json']
    assert json.loads((work / 'request.json').read_text())['key'] == result['key']
    assert {'proc_list', 'oom_open', 'oom_write', 'descriptor_stat', 'status_read',
            'script_write', 'script_chmod', 'script_exec', 'child_write'} <= set(seen)
    child.kill.assert_called_once_with()
    child.wait.assert_called_once_with(timeout=1)


@pytest.mark.parametrize('failure', [
    'work_directory', 'probe_directory', 'probe_owner', 'proc_list', 'oom_open', 'oom_write',
    'descriptor_stat', 'status_read', 'wrong_uid', 'missing_rss', 'script_write',
    'script_chmod', 'script_exec', 'child_write', 'child_spawn',
])
def test_each_prerequisite_failure_exits_without_key_or_details(setup_probe, monkeypatch, failure):
    namespace, fault, _, child = setup_probe
    monkeypatch.setitem(fault, 'at', failure)
    with pytest.raises(SystemExit) as error:
        execute_setup(namespace)
    assert error.value.code == 'Sandbox setup failed; details withheld.'
    assert namespace['sys'].stdout.getvalue() == ''
    namespace['secrets'].token_hex.assert_not_called()
    if 'work' in namespace:
        work = Path(namespace['work'])
        assert not (work / 'request.json').exists()
        assert not list(work.iterdir())
        assert work.stat().st_mode & 0o777 == 0o700
    if failure in {'descriptor_stat', 'status_read', 'wrong_uid', 'missing_rss', 'script_exec', 'child_write'}:
        child.kill.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=1)
