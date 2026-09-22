import asyncio
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.util import ExecResult, OutputLimitExceededError
import cobolcodebench.scoring as scoring


WITHHELD = "Private sandbox operation failed; details withheld."


def assert_sample_error(kind="complete"):
    with pytest.raises(RuntimeError) as raised:
        asyncio.run(scoring.file_scorer(kind)(state(kind), Target("")))
    assert str(raised.value) == WITHHELD
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert raised.value.__suppress_context__ is True


def record(expected='2', test_input='PRIVATE_INPUT'):
    return dict(program_name='task_func_01', input_file_names='input.txt',
                output_file_names='one.txt, two.txt', inputs=json.dumps({'input.txt': test_input}),
                outputs=json.dumps({'one.txt': expected, 'two.txt': expected}),
                complete_prompt='       IDENTIFICATION DIVISION.\n       WORKING-STORAGE SECTION.',
                instruct_prompt='SYNTHETIC_SPEC', canonical_solution='PRIVATE_CANONICAL')


def state(kind='instruct', completion=None):
    return SimpleNamespace(sample_id='task_func_01', metadata={}, output=SimpleNamespace(
        completion=completion if completion is not None else '```cobol\n       synthetic candidate\n```'))


def result(stdout='2', returncode=0):
    return ExecResult(success=returncode == 0, returncode=returncode, stdout=stdout, stderr='')


def signed_receipt(key, cwd, output='2', outputs=None, **kwargs):
    if outputs is None:
        outputs = {'one.txt': output, 'two.txt': output}
    stage = kwargs.get('stage', 'run')
    body = json.dumps(dict(returncode=kwargs.get('returncode', 0),
        timeout=kwargs.get('timeout', False), overflow=kwargs.get('overflow', False),
        stage=stage, compile_success=kwargs.get('compile_success', stage == 'run'), cwd=cwd,
        output=base64.b64encode(output.encode()).decode(),
        outputs={k: None if v is None else base64.b64encode(v.encode()).decode() for k,v in outputs.items()}))
    return json.dumps({'body': body, 'tag': hmac.new(key, body.encode(), hashlib.sha256).hexdigest()})


class FakeSandbox:
    def __init__(self, results):
        self.results = iter(results)
        self.calls, self.requests, self.paths = [], [], []
        self.key = bytes(range(32))

    async def exec(self, cmd, input=None, **kwargs):
        self.calls.append((cmd, dict(kwargs, input=input)))
        if cmd[-1] == scoring.SETUP:
            self.requests.append(json.loads(input))
            self.paths.append(f'/tmp/ccb-fresh_{len(self.paths)+1}')
            return result(json.dumps({'cwd': self.paths[-1], 'key': self.key.hex()}))
        if cmd == scoring.CLEANUP_COMMAND:
            return result('', returncode=1)
        if cmd == scoring.QUIESCENCE_COMMAND:
            return result('', returncode=0)
        response = next(self.results)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, str):
            return result(response)
        return result(signed_receipt(self.key, self.paths[-1], response.stdout, returncode=response.returncode))


def install_sandbox(monkeypatch, fake):
    from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy
    monkeypatch.setattr(scoring, 'sandbox', lambda: SandboxEnvironmentProxy(fake))


@pytest.fixture(autouse=True)
def synthetic_records(monkeypatch):
    monkeypatch.setattr(scoring, 'load_records', lambda: [record()])
    async def no_sleep(delay):
        pass
    monkeypatch.setattr(scoring.asyncio, 'sleep', no_sleep)


@pytest.mark.parametrize('kind', ['instruct', 'complete'])
@pytest.mark.parametrize('outcome', ['correct', 'runtime', 'compile', 'compile_timeout', 'timeout', 'overflow', 'incomplete', 'missing_file', 'wrong_second'])
def test_scorer_results_with_fake_sandbox(monkeypatch, kind, outcome):
    fields = dict(stage='compile' if outcome in {'compile','compile_timeout','incomplete'} else 'run',
                  returncode=1 if outcome in {'runtime','compile'} else 0,
                  timeout=outcome in {'timeout','compile_timeout'}, overflow=outcome == 'overflow')
    outputs = {'one.txt':'2', 'two.txt': '9' if outcome == 'wrong_second' else None if outcome == 'missing_file' else '2'}
    response = signed_receipt(bytes(range(32)), '/tmp/ccb-fresh_1', outputs=outputs, **fields)
    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer(kind)(state(kind), Target('')))
    assert score.value == (CORRECT if outcome == 'correct' else INCORRECT)
    explanation = json.loads(score.explanation)
    assert isinstance(explanation['upstream_score'], (float,int))
    assert explanation['compile_success'] == (outcome not in {'compile','compile_timeout','incomplete'})
    assert len(fake.calls) == 4
    assert fake.calls[1][0][:4] == ['timeout','-s','KILL','100s']
    assert fake.calls[1][1]['timeout_retry'] is False
    request = fake.requests[0]
    assert request['argv'] == ['cobc','-x','-o','task_func_01','task_func_01.cbl']
    assert request['output_files'] == ['one.txt','two.txt']
    if kind == 'complete':
        assert request['files']['task_func_01.cbl'].startswith(record()['complete_prompt']+'\n')


def test_fuzzy_score_never_decides_verdict(monkeypatch):
    fake = FakeSandbox([result('2\r\n')])
    monkeypatch.setattr(scoring, 'load_records', lambda: [record(expected='2\n')])
    install_sandbox(monkeypatch,fake)
    score = asyncio.run(scoring.file_scorer('instruct')(state(),Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)['upstream_score'] == 1.0


def test_answers_and_canonical_solution_never_sent_to_sandbox(monkeypatch):
    fake = FakeSandbox([result('wrong')])
    monkeypatch.setattr(scoring, 'load_records', lambda: [record(expected='EXPECTED_SECRET')])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer('instruct')(state(),Target('')))
    rendered = json.dumps(fake.calls) + score.explanation
    assert 'EXPECTED_SECRET' not in rendered and 'PRIVATE_CANONICAL' not in rendered


@pytest.mark.parametrize('completion', ['unfenced', '```cobol\nfirst\n```\n```\nsecond\n```'])
def test_upstream_extraction_accepts_unfenced_and_first_of_multiple(monkeypatch, completion):
    fake = FakeSandbox([result()]); install_sandbox(monkeypatch,fake)
    assert asyncio.run(scoring.file_scorer('instruct')(state(completion=completion),Target(''))).value == CORRECT


@pytest.mark.parametrize('mode', ['instruct','complete'])
def test_bad_mode_rejected(mode):
    with pytest.raises(ValueError):
        scoring.file_scorer(mode+'-bad')


@pytest.mark.parametrize("failure", [ConnectionError("private provider exception"),
                                     TimeoutError("private timeout output")])
def test_lost_supervisor_response_is_sample_error(monkeypatch, failure):
    fake = FakeSandbox([failure])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize("kind", ["complete", "instruct"])
def test_output_limit_is_sample_error(monkeypatch, kind):
    fake = FakeSandbox([OutputLimitExceededError("fixture limit", None)])
    install_sandbox(monkeypatch, fake)
    assert_sample_error(kind)
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize("forgery", [
    "",
    "2<completed-sentinel-value-0>",
    signed_receipt(b"wrong key", "/tmp/ccb-fresh_1"),
    '{"returncode":0,"output":"2"}',
])
def test_missing_or_forged_receipt_is_sample_error(monkeypatch, forgery):
    fake = FakeSandbox([forgery])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_marker_inside_captured_candidate_output_cannot_hide_failure(monkeypatch):
    fake = FakeSandbox([result("2<completed-sentinel-value-0>", returncode=1)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target("")))
    assert score.value == INCORRECT
    assert "run error (exit 1)" in score.explanation


def test_provider_really_strips_the_forged_marker():
    execute = pytest.importorskip("k8s_sandbox._pod.execute")
    output, status = execute.ExecuteOperation._filter_sentinel_and_returncode(
        None, b"2<completed-sentinel-value-0>"
    )
    assert output == b"2" and status == 0


@pytest.mark.parametrize("field,value", [("timeout", True), ("overflow", True), ("returncode", 137)])
def test_authenticated_failure_channels(monkeypatch, field, value):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), "/tmp/ccb-fresh_1", **{field: value})])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target("")))
    assert score.value == INCORRECT


def test_setup_timeout_is_bounded_and_sample_error(monkeypatch):
    class HungSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd in (scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND):
                return await super().exec(cmd, **kwargs)
            assert cmd[:4] == ["timeout", "-s", "KILL", "5s"]
            assert kwargs["timeout"] == 5
            raise TimeoutError("private material")
    fake = HungSetup([])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('response', [result(), result('3'), result(returncode=7), '',
                                      TimeoutError(), ConnectionError(),
                                      OutputLimitExceededError('synthetic', None)])
def test_uid_cleanup_is_a_separate_exec_on_every_run_outcome(monkeypatch, response):
    fake = FakeSandbox([response, response])
    install_sandbox(monkeypatch, fake)
    if isinstance(response, Exception) or response == '':
        assert_sample_error()
    else:
        asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
    runs = [i for i, (cmd, _) in enumerate(fake.calls) if scoring.RUNNER in cmd]
    assert runs
    for index in runs:
        cmd, kwargs = fake.calls[index + 1]
        assert cmd == scoring.CLEANUP_COMMAND
        assert cmd[-4:] == ['/usr/bin/pkill', '-KILL', '-u', '65532']
        assert kwargs['input'] is None and kwargs['cwd'] == '/'
        assert kwargs['timeout'] == 5 and kwargs['timeout_retry'] is False


def test_missing_receipt_waits_through_host_deadline_before_uid_sweep(monkeypatch):
    events = []

    async def wait(delay):
        assert 104 <= delay <= 105  # compile + run + supervisor overhead + host grace
        events.append('deadline')

    class MissingSupervisor(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                assert events == ['deadline']
                events.append('sweep')
            return await super().exec(cmd, **kwargs)

    monkeypatch.setattr(scoring.asyncio, 'sleep', wait)
    fake = MissingSupervisor([''])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert events == ['deadline', 'sweep']


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(), result('', returncode=2)])
def test_cleanup_failure_aborts_before_next_test(monkeypatch, failure):
    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.CLEANUP_COMMAND:
                self.calls.append((cmd, kwargs))
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return await super().exec(cmd, **kwargs)

    fake = FailedCleanup([result()])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)['reason'] == 'candidate left processes that could not be cleaned up'
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.CLEANUP_COMMAND


def test_scorer_cancellation_still_awaits_independent_uid_sweep(monkeypatch):
    class CancelledRun(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.RUNNER in cmd:
                raise asyncio.CancelledError()
            return await super().exec(cmd, **kwargs)

    fake = CancelledRun([])
    install_sandbox(monkeypatch, fake)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(),
                                     OutputLimitExceededError('private output', None)])
def test_setup_failure_also_issues_uid_cleanup(monkeypatch, failure):
    class FailedSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                raise failure
            return await super().exec(cmd, **kwargs)

    fake = FailedSetup([])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_cleanup_requires_quiescence_before_reusing_sandbox(monkeypatch):
    class StillRunning(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == scoring.QUIESCENCE_COMMAND:
                self.calls.append((cmd, kwargs))
                return result('', returncode=2)
            return await super().exec(cmd, **kwargs)
    fake = StillRunning([result()])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)['reason'] == 'candidate left processes that could not be cleaned up'
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_receipt_for_another_directory_is_sample_error(monkeypatch):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/ccb-other')])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('phase', ['setup', 'runner'])
def test_exec_never_returns_is_bounded_and_sample_error(monkeypatch, phase):
    class HungExec(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if (scoring.SETUP if phase == 'setup' else scoring.RUNNER) in cmd:
                self.calls.append((cmd, kwargs))
                await asyncio.Event().wait()
            return await super().exec(cmd, **kwargs)

    real_timeout = asyncio.timeout
    monkeypatch.setattr(scoring.asyncio, 'timeout', lambda delay: real_timeout(0.01))
    fake = HungExec([])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert [cmd for cmd, _ in fake.calls[-2:]] == [
        scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND,
    ]


@pytest.mark.parametrize('response', [
    '',
    '{"returncode":0,"output":"PRIVATE_STDOUT"}',
    signed_receipt(b'wrong key', '/tmp/ccb-fresh_1'),
    signed_receipt(bytes(range(32)), '/tmp/ccb-fresh_1').replace('run', 'compile'),
    signed_receipt(bytes(range(32)), '/tmp/ccb-other'),
    TimeoutError('PRIVATE_EXCEPTION PRIVATE_STDIN PRIVATE_STDERR PRIVATE_CODE'),
    OutputLimitExceededError('PRIVATE_STDOUT PRIVATE_STDERR', None),
    ConnectionError('PRIVATE_EXCEPTION PRIVATE_STDIN PRIVATE_CODE'),
], ids=['missing', 'unsigned', 'bad-signature', 'tampered', 'wrong-cwd',
        'exec-timeout', 'output-limit', 'provider-error'])
def test_rejected_receipt_records_inspect_sample_error(monkeypatch, tmp_path, response):
    from inspect_ai import Task, eval
    from inspect_ai.dataset import Sample
    from inspect_ai._util import appdirs

    monkeypatch.setattr(appdirs, 'user_data_path', lambda package: tmp_path / 'data')
    monkeypatch.setattr(appdirs, 'user_cache_path', lambda package: tmp_path / 'cache')
    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    task = Task(dataset=[Sample(id='task_func_01', input='Synthetic task')],
                solver=[], scorer=scoring.file_scorer('complete'))
    [log] = eval(task, model='mockllm/model', log_dir=str(tmp_path),
                 display='none', fail_on_error=False, retry_on_error=0,
                 log_realtime=False, ctl_server=False)
    [sample] = log.samples
    assert sample.error is not None
    assert sample.error.message == repr(RuntimeError(WITHHELD))
    assert not sample.scores
    rendered = sample.error.model_dump_json()
    for secret in ('PRIVATE_EXCEPTION', 'PRIVATE_STDIN', 'PRIVATE_STDOUT',
                   'PRIVATE_STDERR', 'PRIVATE_CODE', 'PRIVATE_INPUT', 'PRIVATE_CANONICAL'):
        assert secret not in rendered
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('sample_id', ['task_func_02', 'task_func_05'])
@pytest.mark.parametrize('mode', ['instruct', 'complete'])
def test_actual_runner_base64_receipt_scores_correct(monkeypatch, sample_id, mode):
    from cobolcodebench.dataset import load_records
    from test_sandbox_runner import run_fixture
    selected = next(r for r in load_records() if r['program_name'] == sample_id)
    expected = json.loads(selected['outputs'])
    # Authored Python fixture writes the exact expected bytes. No canonical
    # program runs locally. RUNNER itself reads/b64encodes/signs the receipt.
    writer = '\n'.join(f'open({name!r}, "wb").write({value.encode("utf-8")!r})'
                       for name, value in expected.items())
    envelope, setup = run_fixture(run_code=writer, output_file=list(expected), raw_receipt=True)

    class RunnerReceiptSandbox(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd[-1] == scoring.SETUP:
                return result(json.dumps(setup))
            return await super().exec(cmd, **kwargs)

    monkeypatch.setattr(scoring, 'load_records', lambda: [selected])
    install_sandbox(monkeypatch, RunnerReceiptSandbox([envelope]))
    candidate = state(mode)
    candidate.sample_id = sample_id
    score = asyncio.run(scoring.file_scorer(mode)(candidate, Target('')))
    assert score.value == CORRECT
    assert json.loads(score.explanation) == dict(compile_success=True, upstream_score=1.0,
                                                reason=f'{len(expected)}/{len(expected)} output files match exactly')


def resign_receipt(**changes):
    key = bytes(range(32))
    body = json.loads(json.loads(signed_receipt(key, '/tmp/ccb-fresh_1'))['body'])
    body.update(changes)
    body = json.dumps(body)
    return json.dumps({'body': body, 'tag': hmac.new(key, body.encode(), hashlib.sha256).hexdigest()})


@pytest.mark.parametrize('fields', [
    {'output': '/w=='}, {'outputs': {'one.txt': '/w=='}},
    {'output': 'not base64'}, {'outputs': []}, {'outputs': {'one.txt': 42}},
    {'outputs': {'one.txt': 'not base64'}}, {'output': None},
])
def test_authenticated_invalid_output_is_incorrect(monkeypatch, fields):
    envelope = resign_receipt(**fields)
    receipt = scoring.verify_receipt(envelope, bytes(range(32)))
    assert receipt is not None and receipt['output_not_decodable']
    fake = FakeSandbox([envelope])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)['reason'] == 'output not decodable'
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('fields', [
    {'returncode': True}, {'timeout': 1}, {'overflow': None}, {'stage': []},
    {'cwd': '../candidate'}, {'compile_success': 1}, {'cleanup_failed': 'yes'},
    {'supervisor_error': 1}, {'stage': 'run', 'compile_success': False},
    {'memory_exceeded': 1}, {'disk_exceeded': 1}, {'disk_exceeded': None},
    {'disk_exceeded': 'true'},
])
def test_invalid_supervisor_fields_reject_envelope(fields):
    assert scoring.verify_receipt(resign_receipt(**fields), bytes(range(32))) is None


def test_bad_signature_rejected_before_output_decode():
    envelope = json.loads(resign_receipt(output='/w==', outputs=[]))
    envelope['tag'] = '0' * 64
    assert scoring.verify_receipt(json.dumps(envelope), bytes(range(32))) is None


@pytest.mark.parametrize('flag', ['cleanup_failed', 'supervisor_error', 'memory_exceeded', 'disk_exceeded'])
def test_signed_supervision_failure_is_incorrect_with_independent_cleanup(monkeypatch, flag):
    fake = FakeSandbox([resign_receipt(**{flag: True})])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert score.value == INCORRECT
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('command', [scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND],
                         ids=['uid-kill', 'quiescence-or-deletion'])
@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError(), result('', returncode=2)])
@pytest.mark.parametrize('receipt_kind', ['timeout', 'runtime', 'memory', 'success', 'missing'])
def test_signed_verdict_precedes_failed_independent_cleanup(monkeypatch, command, failure, receipt_kind):
    events = []
    original_failure = scoring.receipt_failure
    def decide(receipt):
        events.append('verdict')
        return original_failure(receipt)
    class FailedCleanup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd == command:
                events.append('cleanup')
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return await super().exec(cmd, **kwargs)
    fields = {'timeout': {'timeout': True}, 'runtime': {'returncode': 7},
              'memory': {'memory_exceeded': True}, 'success': {}, 'missing': {}}[receipt_kind]
    response = '' if receipt_kind == 'missing' else resign_receipt(**fields)
    fake = FailedCleanup([response])
    install_sandbox(monkeypatch, fake)
    monkeypatch.setattr(scoring, 'receipt_failure', decide)
    if receipt_kind == 'missing':
        assert_sample_error()
        assert events == ['cleanup']
    else:
        score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
        assert score.value == INCORRECT
        assert json.loads(score.explanation)['reason'] == {
            'timeout': 'run timeout', 'runtime': 'run error (exit 7)',
            'memory': 'memory limit exceeded',
            'success': 'candidate left processes that could not be cleaned up',
        }[receipt_kind]
        assert events == ['verdict', 'cleanup']
    assert len(fake.paths) == 1


@pytest.mark.parametrize('code', ["import os; os.write(1, b'\\xff'); raise SystemExit(1)",
                                  "open('one.txt', 'wb').write(b'\\xff')"])
def test_actual_runner_invalid_utf8_scores_incorrect(monkeypatch, code):
    from test_sandbox_runner import run_fixture
    envelope, setup = run_fixture(run_code=code, output_file='one.txt', raw_receipt=True)

    class RealReceiptSandbox(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd[-1] == scoring.SETUP:
                return result(json.dumps(setup))
            return await super().exec(cmd, **kwargs)

    install_sandbox(monkeypatch, RealReceiptSandbox([envelope]))
    score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert score.value == INCORRECT
    assert 'output not decodable' in score.explanation


@pytest.mark.parametrize('stdout', ['', json.dumps({'cwd': '/tmp/ccb-probe', 'key': 'ab' * 32})])
def test_nonzero_prerequisite_setup_is_withheld_harness_error(monkeypatch, stdout):
    class FailedPrerequisite(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                self.calls.append((cmd, kwargs))
                return result(stdout, returncode=1)
            return await super().exec(cmd, **kwargs)

    fake = FailedPrerequisite([])
    install_sandbox(monkeypatch, fake)
    assert_sample_error()
    assert not any(scoring.RUNNER in cmd for cmd, _ in fake.calls)
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize('response', ['', TimeoutError('PRIVATE'), ConnectionError('PRIVATE')])
@pytest.mark.parametrize('cleanup_fails', [False, True])
@pytest.mark.parametrize('fields,reason', [
    ({'terminated': 'OOMKilled'}, 'sandbox memory exhausted during candidate execution'),
    ({'last': 'OOMKilled'}, 'sandbox memory exhausted during candidate execution'),
    ({'terminated': 'Error', 'exit_code': 137}, 'sandbox memory exhausted during candidate execution'),
    ({'last': 'Error', 'signal': 9}, 'sandbox memory exhausted during candidate execution'),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'ephemeral-storage exceeded'},
     'sandbox storage exhausted during candidate execution'),
])
def test_missing_receipt_kernel_evidence_survives_cleanup(monkeypatch, response, cleanup_fails, fields, reason):
    from cobolcodebench import sandbox_state
    from test_sandbox_state import pod
    class DeadSandbox(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cleanup_fails and cmd == scoring.CLEANUP_COMMAND:
                raise ConnectionError('PRIVATE')
            return await super().exec(cmd, **kwargs)
    fake = DeadSandbox([response])
    install_sandbox(monkeypatch, fake)
    def lookup(env):
        assert env._sandbox is fake
        assert any(scoring.RUNNER in cmd for cmd, _ in fake.calls)
        return pod(**fields)
    monkeypatch.setattr(sandbox_state, '_read_pod', lookup)
    score = asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation) == dict(compile_success=None, upstream_score=0.0, reason=reason)


@pytest.mark.parametrize('phase', ['setup', 'signed'])
def test_setup_failure_and_signed_receipt_never_consult_kernel(monkeypatch, phase):
    async def forbidden(env):
        pytest.fail('classification outside missing RUNNER receipt')
    class Environment(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if phase == 'setup' and scoring.SETUP in cmd:
                raise TimeoutError('PRIVATE')
            return await super().exec(cmd, **kwargs)
    install_sandbox(monkeypatch, Environment([result()]))
    monkeypatch.setattr(scoring, 'sandbox_failure', forbidden)
    if phase == 'setup':
        assert_sample_error()
    else:
        assert asyncio.run(scoring.file_scorer('complete')(state(), Target(''))).value == CORRECT


@pytest.mark.parametrize('outcome', ['running', 'node', 'node_running', 'preemption', 'lookup_failure', 'gone', 'evicted'])
def test_outer_kill_is_never_itself_a_candidate_verdict(monkeypatch, outcome):
    from cobolcodebench import sandbox_state
    from test_sandbox_state import pod
    class KilledRunner(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.RUNNER in cmd:
                return result('', returncode=137)
            return await super().exec(cmd, **kwargs)
    def lookup(env):
        if outcome == 'lookup_failure':
            raise ConnectionError('PRIVATE')
        if outcome == 'gone':
            from kubernetes.client.exceptions import ApiException
            raise ApiException(status=404, reason='Spot preemption')
        return {'running': pod(), 'node': pod(phase='Unknown', reason='NodeNotReady'),
                'node_running': pod(reason='NodeNotReady'),
                'evicted': pod(phase='Failed', reason='Evicted', terminated='Error', exit_code=137),
                'preemption': pod(phase='Failed', reason='Shutdown')}.get(outcome)
    install_sandbox(monkeypatch, KilledRunner([]))
    monkeypatch.setattr(sandbox_state, '_read_pod', lookup)
    assert_sample_error()
