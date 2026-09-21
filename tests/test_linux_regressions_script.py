"""Orchestration checks only; real attacks run in the operator's Linux image."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from scripts import linux_regressions as regression


def test_cloudbuild_provides_reference_image_and_docker_socket():
    config = yaml.safe_load(Path('scripts/cloudbuild-linux-regressions.yaml').read_text())
    step = config['steps'][0]
    assert step['name'] == 'gcr.io/cloud-builders/docker'
    assert config['substitutions']['_SANDBOX_IMAGE'] == regression.IMAGE
    command = step['args'][-1]
    assert '/var/run/docker.sock:/var/run/docker.sock' in command
    assert 'scripts/linux_regressions.py' in command
    assert '--docker-cli /workspace/.build/docker' in command
    assert "--image '${_SANDBOX_IMAGE}'" in command


def test_nested_memory_container_budget():
    command = regression.memory_command('reference@sha256:fixture')
    for argument in ('--memory=2g', '--memory-swap=2g', '--pids-limit=128',
                     '--read-only', '--volume', '/tmp', '--shm-size=16m',
                     '--user=0:0', '--memory-only', 'reference@sha256:fixture'):
        assert argument in command
    assert '/var/run/docker.sock:/var/run/docker.sock' not in command


@pytest.mark.parametrize('docker', [False, True])
def test_real_regression_orchestration_and_private_logging(monkeypatch, capsys, docker):
    calls = []
    report = dict(stage='run', returncode=1, **{flag: False for flag in regression.FLAGS})

    def run_case(name, *, prlimit=False):
        calls.append((name, prlimit))
        return report

    def checked_run(command, **kwargs):
        assert command == regression.memory_command(regression.IMAGE)
        return SimpleNamespace(stdout='\n'.join([json.dumps(report)] * 3))

    monkeypatch.setattr(regression, 'run_case', run_case)
    monkeypatch.setattr(regression, 'checked_run', checked_run)
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regression.shutil, 'which', lambda name: '/bin/docker' if docker else None)
    monkeypatch.setattr(regression.sys, 'argv', ['linux_regressions.py'])
    assert regression.main() == 0
    assert calls == [('bytes', False), ('forks', False)] + ([] if docker else [('memory', True)])
    output = capsys.readouterr()
    assert not output.err
    assert [json.loads(line) for line in output.out.splitlines()] == [report] * (5 if docker else 3)


def test_script_imports_exact_production_sources_without_inspect():
    from cobolcodebench.sandbox_runner import SETUP, RUNNER
    from cobolcodebench.scoring import verify_receipt, receipt_failure
    runner = regression.load_module('sandbox_runner')
    receipts = regression.load_module('receipts')
    assert (runner.SETUP, runner.RUNNER) == (SETUP, RUNNER)
    assert receipts.verify_receipt.__code__.co_code == verify_receipt.__code__.co_code
    assert receipts.receipt_failure.__code__.co_code == receipt_failure.__code__.co_code


@pytest.mark.parametrize('prlimit', [False, True])
def test_memory_case_executes_production_supervisor_and_checks_receipt(monkeypatch, prlimit):
    import base64
    import hashlib
    import hmac
    runner = regression.load_module('sandbox_runner')
    key = bytes(range(32))
    setup = dict(cwd='/tmp/ccb-regression', key=key.hex())
    calls = []
    body = json.dumps(dict(cwd=setup['cwd'], stage='run', compile_success=True,
                           returncode=1, timeout=False, overflow=False, cleanup_failed=False,
                           supervisor_error=False, outputs={},
                           output=base64.b64encode(b'memory-started\n').decode()))
    envelope = json.dumps(dict(body=body, tag=hmac.new(key, body.encode(), hashlib.sha256).hexdigest()))

    def checked_run(command, **kwargs):
        calls.append(command)
        if command[-1] == 'pass':
            return SimpleNamespace(stdout='')
        if command[-1] == runner.SETUP:
            request = json.loads(kwargs['input'])
            assert request['run_argv'][-1] == regression.LIMIT_PROBE + regression.CASES['memory']
            return SimpleNamespace(stdout=json.dumps(setup))
        assert runner.RUNNER in command and command[-1] == setup['cwd']
        if prlimit:
            assert command[:4] == ['prlimit', '--as=1073741824:1073741824',
                                   '--data=1073741824:1073741824', '--']
        else:
            assert command[0] == 'timeout'
        return SimpleNamespace(stdout=envelope)

    monkeypatch.setattr(regression, 'checked_run', checked_run)
    monkeypatch.setattr(regression.subprocess, 'run', lambda command, **kwargs:
                        SimpleNamespace(returncode=0 if command == runner.QUIESCENCE_COMMAND else 1))
    report = regression.run_case('memory', prlimit=prlimit)
    assert len(calls) == 3
    assert report == dict(stage='run', returncode=1, **{flag: False for flag in regression.FLAGS})


def test_bounded_docker_cases_include_aggregate_memory_and_disk(monkeypatch, capsys):
    calls = []
    report = dict(stage='run', returncode=1, **{flag: False for flag in regression.FLAGS})
    monkeypatch.setattr(regression, 'run_case', lambda name: calls.append(name) or report)
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regression.sys, 'argv', ['linux_regressions.py', '--memory-only'])
    assert regression.main() == 0
    assert calls == ['memory', 'memory_aggregate', 'disk']
    assert len(capsys.readouterr().out.splitlines()) == 3


def test_disk_case_exceeds_aggregate_disk_not_single_file_limit():
    request = regression.case_request('disk')
    assert request['output_limit'] == 2 * 1024**2
    assert '1024 * 1024' in request['run_argv'][-1]
    assert 'while True:' in request['run_argv'][-1]
    assert "dir='/tmp'" in request['run_argv'][-1]
    assert "open('work-file', 'wb')" in request['run_argv'][-1]
    assert 'range(3)' in regression.CASES['memory_aggregate']
    assert '600 * 1024 * 1024' in regression.CASES['memory_aggregate']


def test_explicit_docker_cli_is_used():
    command = regression.memory_command('reference', '/workspace/.build/docker')
    assert command[0] == '/workspace/.build/docker'
    assert '--tmpfs' not in command
    assert command[command.index('--volume') + 1] == '/tmp'
