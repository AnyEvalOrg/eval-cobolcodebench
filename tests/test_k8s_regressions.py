"""Offline checks of the operator task; these never claim gVisor containment."""
import asyncio
import base64
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.model import ModelName

from cobolcodebench.sandbox_runner import CLEANUP_COMMAND, QUIESCENCE_COMMAND, RUNNER, SETUP
from cobolcodebench.task import task_sandbox
from scripts import k8s_regressions as regression


def test_operator_task_uses_exact_production_sandbox_and_mock_model():
    task = regression.k8s_regressions()
    kind, config = task_sandbox()
    assert task.sandbox.type == kind == 'k8s'
    assert task.sandbox.config == config
    assert str(ModelName(task.model)) == 'mockllm/model'
    assert len(task.dataset) == 1
    import cobolcodebench
    assert 'k8s_regressions' not in cobolcodebench.__all__


def test_inspect_can_load_operator_file_without_repository_on_python_path(tmp_path):
    # The CLI changes its Python working directory to scripts/. A normal test
    # import would hide broken sibling imports because conftest adds repo root.
    script = str(Path(regression.__file__).resolve())
    code = f'''from pathlib import Path
from inspect_ai._util.module import load_module
module = load_module(Path({script!r}))
assert module.k8s_regressions().sandbox.type == 'k8s'
'''
    result = subprocess.run([sys.executable, '-I', '-c', code], cwd=tmp_path,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


class RegressionSandbox:
    def __init__(self, name, changes=None, *, unsigned=False, cleanup_failure=False, lost_pod=False):
        self.calls = []
        self.name, self.changes = name, changes or {}
        self.unsigned, self.cleanup_failure, self.lost_pod = unsigned, cleanup_failure, lost_pod
        self.key = bytes(range(32))
        self.work = '/tmp/ccb-regression'

    async def exec(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        assert kwargs['timeout_retry'] is False
        if SETUP in cmd:
            request = json.loads(kwargs['input'])
            assert request == regression.case_request(self.name)
            return SimpleNamespace(returncode=0, stdout=json.dumps(dict(cwd=self.work, key=self.key.hex())))
        if RUNNER in cmd:
            assert cmd[-1] == self.work and kwargs['timeout'] == 30
            body = dict(stage='run', cwd=self.work, compile_success=True, outputs={},
                        returncode=0 if self.name == 'detached' else -9 if self.name in regression.DISK_CASES else 1,
                        **{flag: False for flag in regression.FLAGS if flag != 'output_not_decodable'})
            body['memory_exceeded'] = self.name in ('memory_aggregate', *regression.KERNEL_CASES)
            body['disk_exceeded'] = self.name in regression.DISK_CASES
            output = b'\xff' if self.name == 'bytes' else b'forks-exhausted 63\n' if self.name == 'forks' else b''
            if self.name == 'ptrace_denied':
                output = b'ptrace-denied\n'
            body['output'] = base64.b64encode(output).decode()
            body.update(self.changes)
            body = json.dumps(body)
            tag = hmac.new(self.key, body.encode(), hashlib.sha256).hexdigest()
            return SimpleNamespace(returncode=0, stdout=json.dumps(dict(body=body, tag='bad' if self.unsigned else tag)))
        if cmd == CLEANUP_COMMAND:
            return SimpleNamespace(returncode=1, stdout='')
        if cmd == QUIESCENCE_COMMAND:
            return SimpleNamespace(returncode=2 if self.cleanup_failure else 0, stdout='')
        assert cmd[-1] == 'pass'
        return SimpleNamespace(returncode=1 if self.lost_pod else 0, stdout='')


@pytest.mark.parametrize('name', regression.CASES)
def test_real_protocol_authenticates_expected_cases_and_probes_same_pod(name):
    fake = RegressionSandbox(name)
    summary = asyncio.run(regression.run_case(fake, name))
    assert all(summary[field] for field in ('signed_receipt', 'expected', 'cleanup_succeeded', 'pod_usable'))
    assert all(type(value) is bool for value in summary.values())
    assert len(fake.calls) == 5
    assert [cmd for cmd, _ in fake.calls[2:4]] == [CLEANUP_COMMAND, QUIESCENCE_COMMAND]
    assert fake.calls[-1][0][-1] == 'pass'


@pytest.mark.parametrize('name,changes', [
    ('memory_aggregate', {'memory_exceeded': False}),
    ('disk', {'disk_exceeded': False}), ('disk', {'returncode': 0}),
    ('detached', {'cleanup_failed': True}), ('bytes', {'output': ''}),
    ('ptrace_denied', {'returncode': 0}), ('ptrace_denied', {'returncode': 2}),
    ('ptrace_denied', {'output': ''}),
    ('forks', {'timeout': True}), ('forks', {'output': ''}),
    ('forks', {'output': base64.b64encode(b'forks-exhausted 0\n').decode()}),
    ('forks', {'output': base64.b64encode(b'forks-exhausted 64\n').decode()}),
])
def test_unexpected_candidate_outcome_fails_regression(name, changes):
    summary = asyncio.run(regression.run_case(RegressionSandbox(name, changes), name))
    assert summary['signed_receipt'] and not summary['expected']
    assert summary['pod_usable']


@pytest.mark.parametrize('problem,field', [
    ('unsigned', 'signed_receipt'), ('cleanup_failure', 'cleanup_succeeded'), ('lost_pod', 'pod_usable'),
])
def test_missing_receipt_failed_cleanup_or_dead_pod_cannot_pass(monkeypatch, problem, field):
    async def no_sleep(delay):
        assert 34 <= delay <= 35
    monkeypatch.setattr(regression.asyncio, 'sleep', no_sleep)
    fake = RegressionSandbox('detached', **{problem: True})
    summary = asyncio.run(regression.run_case(fake, 'detached'))
    assert not summary[field]
    assert fake.calls[-1][0][-1] == 'pass'


@pytest.mark.parametrize('failed_field', [None, 'signed_receipt', 'expected', 'cleanup_succeeded', 'pod_usable'])
def test_scorer_requires_every_case_and_only_logs_flags(failed_field):
    summary = {name: dict(signed_receipt=True, expected=True, cleanup_succeeded=True, pod_usable=True)
               for name in regression.CASES}
    if failed_field:
        summary['disk'][failed_field] = False
    state = SimpleNamespace(sample_id='containment', metadata={'regressions': summary})
    score = asyncio.run(regression.regression_scorer()(state, Target('')))
    assert score.value == (INCORRECT if failed_field else CORRECT)
    assert json.loads(score.explanation) == summary


@pytest.mark.parametrize('changes', [
    {'memory_exceeded': True, 'returncode': -9, 'output': ''},
    {'memory_exceeded': True, 'returncode': 1, 'output': ''},
])
def test_fork_exhaustion_accepts_gvisor_aggregate_rss_limit(changes):
    summary = asyncio.run(regression.run_case(RegressionSandbox('forks', changes), 'forks'))
    assert summary['signed_receipt'] and summary['expected'] and summary['pod_usable']


def test_fork_witness_requires_exit_one():
    summary = asyncio.run(regression.run_case(RegressionSandbox('forks', {'returncode': 2}), 'forks'))
    assert summary['signed_receipt'] and not summary['expected']


def test_lethal_samples_are_generated_last_one_per_pod():
    source = regression.RegressionSamples()
    assert [s.id for s in source.initial_samples()] == ['containment']
    # Inspect calls next_samples only when no earlier samples remain in flight.
    for name in regression.KERNEL_CASES:
        samples = asyncio.run(source.next_samples())
        assert len(samples) == 1 and samples[0].id == name
    assert asyncio.run(source.next_samples()) is None


@pytest.mark.parametrize('name', regression.KERNEL_CASES)
@pytest.mark.parametrize('outcome', ['signed', 'oom', 'exit137', 'signal9', 'running', 'lookup_failure', 'setup_failure', 'storage'])
def test_kernel_cases_require_signed_limit_or_attributed_oom(monkeypatch, name, outcome):
    from cobolcodebench import sandbox_state
    from test_sandbox_state import pod
    class Environment(RegressionSandbox):
        async def exec(self, cmd, **kwargs):
            if outcome == 'setup_failure' and SETUP in cmd:
                raise ConnectionError('PRIVATE')
            if outcome != 'signed' and RUNNER in cmd:
                raise ConnectionError('PRIVATE')
            if outcome in ('oom', 'exit137', 'signal9', 'storage') and (cmd in (CLEANUP_COMMAND, QUIESCENCE_COMMAND) or cmd[-1] == 'pass'):
                raise ConnectionError('PRIVATE')
            return await super().exec(cmd, **kwargs)
    def lookup(env):
        if outcome in ('signed', 'setup_failure'):
            pytest.fail('unexpected lookup')
        if outcome == 'lookup_failure':
            raise ConnectionError('PRIVATE')
        return (pod(terminated='OOMKilled') if outcome == 'oom' else
                pod(terminated='Error', exit_code=137) if outcome == 'exit137' else
                pod(last='Error', signal=9) if outcome == 'signal9' else
                pod(phase='Failed', reason='Evicted', message='ephemeral-storage') if outcome == 'storage' else pod())
    async def no_sleep(delay):
        pass
    monkeypatch.setattr(regression.asyncio, 'sleep', no_sleep)
    monkeypatch.setattr(sandbox_state, '_read_pod', lookup)
    summary = asyncio.run(regression.run_case(Environment(name), name))
    assert ('classification_evidence' in summary) == (outcome not in ('signed', 'setup_failure'))
    assert summary['kernel_oom'] == (outcome in ('oom', 'exit137', 'signal9'))
    state = SimpleNamespace(sample_id=name, metadata={'regressions': {name: summary}})
    score = asyncio.run(regression.regression_scorer()(state, Target('')))
    assert score.value == (CORRECT if outcome in ('signed', 'oom', 'exit137', 'signal9') else INCORRECT)


def test_sysv_refusal_is_reported_as_a_flag():
    fake = RegressionSandbox('sysv_shm', dict(
        memory_exceeded=False, output=base64.b64encode(b'sysv-shm-unavailable\n').decode()))
    summary = asyncio.run(regression.run_case(fake, 'sysv_shm'))
    assert summary['expected'] and summary['signed_receipt'] and summary['sysv_unavailable']


@pytest.mark.parametrize('name', ['detached', *regression.KERNEL_CASES])
@pytest.mark.parametrize('outcome', ['terminated', 'gone', 'failure', 'missing'])
def test_missing_receipt_records_exact_classifier_lookups(monkeypatch, name, outcome):
    import time
    from kubernetes.client.exceptions import ApiException
    from cobolcodebench import sandbox_state
    from test_sandbox_state import pod

    value = pod(phase='Failed', reason='KUBELET_REASON', message='P' * 201,
                terminated='Error', last='Completed', exit_code=137, signal=9)
    value.status.container_statuses[0].state.terminated.message = 'S' * 201
    value.status.container_statuses[0].last_state.terminated.message = 'L' * 201
    value.status.container_statuses += pod().status.container_statuses
    calls = []
    failed_at = None

    class Environment(RegressionSandbox):
        async def exec(self, cmd, **kwargs):
            nonlocal failed_at
            if RUNNER in cmd:
                failed_at = time.monotonic()
                raise ConnectionError('PRIVATE_EXEC')
            return await super().exec(cmd, **kwargs)

    def lookup(environment):
        calls.append(time.monotonic())
        # Record a propagation retry as well as the decisive result.
        if len(calls) == 1:
            return pod()
        if outcome == 'gone':
            error = ApiException(status=404, reason='PRIVATE_API')
            error.body = 'PRIVATE_BODY'
            raise error
        if outcome == 'failure':
            raise ConnectionError('PRIVATE_EXCEPTION')
        return None if outcome == 'missing' else value

    async def no_sleep(delay):
        pass

    monkeypatch.setattr(sandbox_state, '_read_pod', lookup)
    monkeypatch.setattr(regression.asyncio, 'sleep', no_sleep)
    summary = asyncio.run(regression.run_case(Environment(name), name))
    evidence = summary['classification_evidence']
    assert len(evidence) == len(calls) == 2
    assert evidence[0]['phase'] == 'Running'
    assert evidence[0]['containerStatuses'][0]['state'] == {'terminated': None}
    elapsed = [entry['exec_failure_to_lookup_seconds'] for entry in evidence]
    assert elapsed == sorted(elapsed)
    assert all(0 <= delay <= called - failed_at for delay, called in zip(elapsed, calls))
    final = evidence[-1]
    assert final['lookup_failed'] == (outcome in ('gone', 'failure'))
    assert final['lookup_exception'] == {'gone': 'ApiException', 'failure': 'ConnectionError'}.get(outcome)
    assert final['pod_gone'] == (outcome == 'gone')
    if outcome == 'terminated':
        assert (final['phase'], final['reason'], final['message']) == ('Failed', 'KUBELET_REASON', 'P' * 200)
        assert final['containerStatuses'] == [
            {'name': 'default',
             'state': {'terminated': dict(reason='Error', exitCode=137, signal=9, message='S' * 200)},
             'lastState': {'terminated': dict(reason='Completed', exitCode=137, signal=9, message='L' * 200)}},
            {'name': 'default', 'state': {'terminated': None}, 'lastState': {'terminated': None}},
        ]
    else:
        assert final['phase'] is None and final['containerStatuses'] == []
    assert 'PRIVATE' not in json.dumps(summary)
    state = SimpleNamespace(sample_id=name, metadata={'regressions': {name: summary}})
    score = asyncio.run(regression.regression_scorer()(state, Target('')))
    assert json.loads(score.explanation)[name]['classification_evidence'] == evidence
