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
                        returncode=0 if self.name == 'detached' else -9 if self.name == 'disk' else 1,
                        **{flag: False for flag in regression.FLAGS if flag != 'output_not_decodable'})
            body['memory_exceeded'] = self.name == 'memory_aggregate'
            body['disk_exceeded'] = self.name == 'disk'
            output = b'\xff' if self.name == 'bytes' else b'forks-exhausted 63\n' if self.name == 'forks' else b''
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
    state = SimpleNamespace(metadata={'regressions': summary})
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
