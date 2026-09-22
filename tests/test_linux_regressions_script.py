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
    assert '--cap-drop=ALL' in command
    for capability in ('SETUID', 'SETGID', 'KILL', 'CHOWN', 'DAC_OVERRIDE', 'SYS_PTRACE'):
        assert '--cap-add=' + capability in command
    assert 'scripts/linux_regressions.py' in command
    assert '--docker-cli /workspace/.build/docker' in command
    assert "--image '${_SANDBOX_IMAGE}'" in command


def test_nested_memory_container_budget():
    command = regression.memory_command('reference@sha256:fixture')
    for argument in ('--memory=2g', '--memory-swap=2g', '--pids-limit=128',
                     '--read-only', '--volume', '/tmp', '--tmpfs', '/dev/shm:ro,size=16m',
                     '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=KILL',
                     '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE', '--cap-add=SYS_PTRACE',
                     '--security-opt=no-new-privileges:true', '--user=0:0', '--memory-only', 'reference@sha256:fixture'):
        assert argument in command
    assert '/var/run/docker.sock:/var/run/docker.sock' not in command


@pytest.mark.parametrize('docker', [False, True])
def test_real_regression_orchestration_and_private_logging(monkeypatch, capsys, docker):
    calls = []
    report = dict(stage='run', returncode=1, **{flag: False for flag in regression.FLAGS})

    def run_case(name, *, prlimit=False):
        calls.append((name, prlimit))
        return report

    def docker_run(command, **kwargs):
        assert command == regression.memory_command(regression.IMAGE)
        return SimpleNamespace(returncode=0, stderr='', stdout='\n'.join([json.dumps(report)] * len(regression.BOUNDED_CASES)))

    monkeypatch.setattr(regression, 'run_case', run_case)
    monkeypatch.setattr(regression.subprocess, 'run', docker_run)
    kernel_report = dict.fromkeys((*regression.FLAGS, 'signed_receipt', 'oom_exit_137', 'sysv_unavailable'), False)
    kernel_report['oom_exit_137'] = True
    kernel_calls = []
    monkeypatch.setattr(regression, 'run_kernel_container',
                        lambda image, name, cli: kernel_calls.append(name) or kernel_report)
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regression.shutil, 'which', lambda name: '/bin/docker' if docker else None)
    monkeypatch.setattr(regression.sys, 'argv', ['linux_regressions.py'])
    assert regression.main() == 0
    assert calls == [('bytes', False), ('forks', False)] + ([] if docker else [('memory', True)])
    output = capsys.readouterr()
    assert not output.err
    assert [json.loads(line) for line in output.out.splitlines()] == (
        [report] * (2 + len(regression.BOUNDED_CASES) if docker else 3)
        + ([kernel_report] * len(regression.KERNEL_CASES) if docker else []))
    assert kernel_calls == (list(regression.KERNEL_CASES) if docker else [])


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
    assert calls == list(regression.BOUNDED_CASES)
    assert len(capsys.readouterr().out.splitlines()) == len(regression.BOUNDED_CASES)


def test_disk_case_exceeds_aggregate_disk_not_single_file_limit():
    request = regression.case_request('disk')
    assert request['output_limit'] == 1024**2
    assert '1024 * 1024' in request['run_argv'][-1]
    assert 'while True:' in request['run_argv'][-1]
    assert "dir='/tmp'" in request['run_argv'][-1]
    assert "open('work-file', 'wb')" in request['run_argv'][-1]
    assert 'range(3)' in regression.CASES['memory_aggregate']
    assert '600 * 1024 * 1024' in regression.CASES['memory_aggregate']


def test_explicit_docker_cli_is_used():
    command = regression.memory_command('reference', '/workspace/.build/docker')
    assert command[0] == '/workspace/.build/docker'
    assert command[command.index('--tmpfs') + 1] == '/dev/shm:ro,size=16m'
    assert command[command.index('--volume') + 1] == '/tmp'


@pytest.mark.parametrize('name', ['disk_unlinked', 'disk_memfd', 'disk_entries', 'shm_readonly'])
def test_new_cases_are_required_in_docker_and_production(name):
    from scripts.k8s_regressions import CASES
    assert name in regression.BOUNDED_CASES and name in CASES
    receipt = dict(stage='run', compile_success=True, returncode=1, output='',
                   **{flag: False for flag in regression.FLAGS})
    if name in regression.DISK_CASES:
        receipt['disk_exceeded'] = True
    assert regression.expected_receipt(name, receipt)
    for changes in ({'returncode': 0}, {'timeout': True}, {'supervisor_error': True},
                    {'disk_exceeded': not receipt['disk_exceeded']}):
        assert not regression.expected_receipt(name, {**receipt, **changes})
    compile(regression.case_request(name)['run_argv'][-1], '<candidate>', 'exec')


def test_ptrace_denial_requires_signed_nonzero_permission_witness():
    from scripts.k8s_regressions import CASES
    assert 'ptrace_denied' in regression.BOUNDED_CASES and 'ptrace_denied' in CASES
    code = regression.CASES['ptrace_denied']
    assert "os.stat('/proc/1/fd/0')" in code
    assert 'except PermissionError:' in code
    receipt = dict(stage='run', compile_success=True, returncode=1, output='ptrace-denied\n',
                   **{flag: False for flag in regression.FLAGS})
    assert regression.expected_receipt('ptrace_denied', receipt)
    for changes in ({'returncode': 0}, {'returncode': 2}, {'output': ''},
                    {'supervisor_error': True}, {'timeout': True}):
        assert not regression.expected_receipt('ptrace_denied', {**receipt, **changes})
    compile(regression.case_request('ptrace_denied')['run_argv'][-1], '<candidate>', 'exec')


@pytest.mark.parametrize('name', regression.KERNEL_CASES)
@pytest.mark.parametrize('outcome', [
    'signed_memory', 'signed_disk', 'oom', 'oom_inspected', 'oom_zero',
    'unsigned', 'error', 'timeout', 'private_output', 'malformed', 'forged',
    'refusal', 'bad_flags', 'inspect_error', 'cleanup_error',
])
def test_kernel_container_checks_receipt_or_container_death(monkeypatch, capsys, name, outcome):
    report = dict.fromkeys((*regression.FLAGS, 'signed_receipt', 'oom_exit_137', 'sysv_unavailable'), False)
    report.update(signed_receipt=True, memory_exceeded=True)
    if outcome == 'signed_disk':
        report.update(memory_exceeded=False, disk_exceeded=True)
    if outcome == 'forged':
        report['signed_receipt'] = False
    if outcome == 'refusal':
        report.update(memory_exceeded=False, sysv_unavailable=True)
    if outcome == 'bad_flags':
        report['memory_exceeded'] = 'PRIVATE'
    calls = []
    container_names = []
    exit_code = {'oom': 137, 'oom_inspected': 1, 'error': 1, 'private_output': 137}.get(outcome, 0)

    def run(command, **kwargs):
        calls.append(command)
        if command[1] == 'run':
            container_name = command[command.index('--name') + 1]
            container_names.append(container_name)
            assert command == regression.kernel_command('reference', name, 'docker-fixture', container_name=container_name)
            assert '--rm' not in command
            assert command[-2:] == ['--kernel-case', name]
            assert '--memory-only' not in command and '--memory=2g' in command
            if outcome == 'timeout':
                raise TimeoutError('PRIVATE')
            return SimpleNamespace(returncode=exit_code, stderr='PRIVATE',
                                   stdout='' if outcome == 'unsigned' else 'PRIVATE' if outcome in ('private_output', 'malformed') else json.dumps(report))
        if command[1] == 'inspect':
            assert command == ['docker-fixture', 'inspect', '--format', '{{.State.OOMKilled}}', container_names[0]]
            return SimpleNamespace(returncode=1 if outcome == 'inspect_error' else 0,
                                   stdout='true\n' if outcome in ('oom_inspected', 'oom_zero') else 'false\n')
        assert command == ['docker-fixture', 'rm', '--force', '--volumes', container_names[0]]
        return SimpleNamespace(returncode=1 if outcome == 'cleanup_error' else 0)

    monkeypatch.setattr(regression.subprocess, 'run', run)
    if outcome in ('signed_memory', 'signed_disk', 'oom', 'oom_inspected', 'oom_zero', 'private_output'):
        value = regression.run_kernel_container('reference', name, 'docker-fixture')
        assert value['case'] == name and value['nested_returncode'] == exit_code
        assert value['signed_receipt'] == outcome.startswith('signed_')
        assert value['oom_exit_137'] == (exit_code == 137)
        assert value['oom_killed'] == (outcome in ('oom_inspected', 'oom_zero'))
        assert all(type(v) is bool for k, v in value.items() if k not in ('case', 'nested_returncode'))
    else:
        with pytest.raises(Exception) as caught:
            regression.run_kernel_container('reference', name, 'docker-fixture')
        attribution = regression.failure_report(caught.value)
        assert attribution['step'] == name
        assert attribution['label'] in regression.LABELS - {'unexpected-error'}
    assert calls[-1][1] == 'rm'
    output = capsys.readouterr()
    assert 'PRIVATE' not in output.out + output.err
    if outcome not in ('signed_memory', 'signed_disk', 'oom', 'oom_inspected', 'oom_zero', 'private_output'):
        diagnostic = json.loads(output.out)
        assert diagnostic['case'] == name
        assert diagnostic['nested_returncode'] == (None if outcome == 'timeout' else exit_code)


@pytest.mark.parametrize('name', regression.KERNEL_CASES)
def test_kernel_fixture_only_accepts_limit_flags_or_sysv_refusal(name):
    compile(regression.case_request(name)['run_argv'][-1], '<candidate>', 'exec')
    assert regression.case_request(name)['output_limit'] == 1024**2
    receipt = dict(stage='run', compile_success=True, returncode=1, output='',
                   **dict.fromkeys(regression.FLAGS, False))
    assert not regression.expected_receipt(name, receipt)
    for flag in ('memory_exceeded', 'disk_exceeded'):
        assert regression.expected_receipt(name, {**receipt, flag: True})
    refusal = {**receipt, 'output': 'sysv-shm-unavailable\n'}
    assert regression.expected_receipt(name, refusal) == (name == 'sysv_shm')
    assert not regression.expected_receipt(name, {**refusal, 'returncode': 2})


@pytest.mark.parametrize('name', ['bytes', *regression.BOUNDED_CASES, *regression.KERNEL_CASES])
def test_main_attributes_failed_case_without_exception_text(monkeypatch, capsys, name):
    def run_case(current, **kwargs):
        if current == name:
            regression.require(False, 'expected-receipt')
        return {}

    args = ['linux_regressions.py']
    if name in regression.KERNEL_CASES:
        args += ['--kernel-case', name]
    elif name in regression.BOUNDED_CASES:
        args += ['--memory-only']
    monkeypatch.setattr(regression, 'run_case', run_case)
    monkeypatch.setattr(regression.sys, 'argv', args)
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    assert regression.main() == 1
    assert json.loads(capsys.readouterr().err) == dict(
        stage='regression', step=name, error='AssertionError', label='expected-receipt')


def test_failure_attribution_allowlists_all_text(capsys):
    error = type('PRIVATE', (Exception,), {})('PRIVATE')
    error.regression_step = 'PRIVATE'
    error.regression_label = 'PRIVATE'
    assert regression.failure_report(error) == dict(
        stage='regression', step='startup', error='Exception', label='unexpected-error')
    valid = dict(stage='regression', step='sysv_shm', error='AssertionError', label='expected-receipt')
    records = [valid, {'output': 'PRIVATE'}]
    records += [{**valid, key: 'PRIVATE'} for key in valid]
    regression.relay_failure('PRIVATE\n' + '\n'.join(json.dumps(record) for record in records))
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err) == valid


def test_checked_run_failure_preserves_case_and_operation(monkeypatch):
    monkeypatch.setattr(regression.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stdout='PRIVATE', stderr='PRIVATE'))
    with pytest.raises(AssertionError) as caught:
        with regression.step('sysv_shm'):
            regression.checked_run(['fixture'], label='runner-completed')
    assert regression.failure_report(caught.value) == dict(
        stage='regression', step='sysv_shm', error='AssertionError', label='runner-completed')


@pytest.mark.parametrize('private_field', ['stage', 'returncode', 'timeout'])
def test_main_does_not_relay_private_nested_values(monkeypatch, capsys, private_field):
    report = dict(stage='run', returncode=1, **dict.fromkeys(regression.FLAGS, False))
    report[private_field] = 'PRIVATE'
    monkeypatch.setattr(regression, 'run_case', lambda *args: {})
    monkeypatch.setattr(regression.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stderr='PRIVATE',
                                        stdout='\n'.join([json.dumps(report)] * len(regression.BOUNDED_CASES))))
    monkeypatch.setattr(regression.sys, 'argv', ['linux_regressions.py'])
    monkeypatch.setattr(regression.sys, 'platform', 'linux')
    monkeypatch.setattr(regression.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(regression.shutil, 'which', lambda name: '/bin/docker')
    assert regression.main() == 1
    output = capsys.readouterr()
    assert 'PRIVATE' not in output.out + output.err
    assert json.loads(output.err) == dict(
        stage='regression', step='docker', error='AssertionError', label='docker-output')
