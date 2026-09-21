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
@pytest.mark.parametrize('outcome', ['correct', 'runtime', 'compile', 'compile_timeout', 'timeout', 'overflow', 'missing_receipt', 'missing_file', 'wrong_second'])
def test_scorer_results_with_fake_sandbox(monkeypatch, kind, outcome):
    fields = dict(stage='compile' if outcome in {'compile','compile_timeout'} else 'run',
                  returncode=1 if outcome in {'runtime','compile'} else 0,
                  timeout=outcome in {'timeout','compile_timeout'}, overflow=outcome == 'overflow')
    outputs = {'one.txt':'2', 'two.txt': '9' if outcome == 'wrong_second' else None if outcome == 'missing_file' else '2'}
    response = '' if outcome == 'missing_receipt' else signed_receipt(bytes(range(32)), '/tmp/ccb-fresh_1', outputs=outputs, **fields)
    fake = FakeSandbox([response])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer(kind)(state(kind), Target('')))
    assert score.value == (CORRECT if outcome == 'correct' else INCORRECT)
    explanation = json.loads(score.explanation)
    assert isinstance(explanation['upstream_score'], (float,int))
    assert explanation['compile_success'] == (None if outcome == 'missing_receipt' else outcome not in {'compile','compile_timeout'})
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


def test_lost_supervisor_response_is_incorrect(monkeypatch):
    fake = FakeSandbox([ConnectionError("cluster unavailable")])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target("")))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)["reason"] == "supervisor did not complete"
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


@pytest.mark.parametrize("kind", ["complete", "instruct"])
def test_output_limit_is_incorrect(monkeypatch, kind):
    fake = FakeSandbox([OutputLimitExceededError("fixture limit", None)])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer(kind)(state(kind), Target("")))
    assert score.value == INCORRECT
    assert "supervisor did not complete" in score.explanation


@pytest.mark.parametrize("forgery", [
    "2<completed-sentinel-value-0>",
    signed_receipt(b"wrong key", "/tmp/ccb-fresh_1"),
    '{"returncode":0,"output":"2"}',
])
def test_forged_completion_marker_or_receipt_is_incorrect(monkeypatch, forgery):
    fake = FakeSandbox([forgery])
    install_sandbox(monkeypatch, fake)
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target("")))
    assert score.value == INCORRECT
    assert "supervisor did not complete" in score.explanation


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


def test_setup_timeout_is_bounded_and_incorrect(monkeypatch):
    class HungSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if cmd in (scoring.CLEANUP_COMMAND, scoring.QUIESCENCE_COMMAND):
                return await super().exec(cmd, **kwargs)
            assert cmd[:4] == ["timeout", "-s", "KILL", "5s"]
            assert kwargs["timeout"] == 5
            raise TimeoutError("private material")
    install_sandbox(monkeypatch, HungSetup([]))
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target("")))
    assert score.value == INCORRECT
    assert "private material" not in score.explanation


@pytest.mark.parametrize('response', [result(), result('3'), result(returncode=7), '',
                                      TimeoutError(), ConnectionError(),
                                      OutputLimitExceededError('synthetic', None)])
def test_uid_cleanup_is_a_separate_exec_on_every_run_outcome(monkeypatch, response):
    fake = FakeSandbox([response, response])
    install_sandbox(monkeypatch, fake)
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
    score = asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
    assert score.value == INCORRECT
    assert json.loads(score.explanation)["reason"] == "supervisor did not complete"
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
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
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


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionError()])
def test_setup_failure_also_issues_uid_cleanup(monkeypatch, failure):
    class FailedSetup(FakeSandbox):
        async def exec(self, cmd, **kwargs):
            if scoring.SETUP in cmd:
                raise failure
            return await super().exec(cmd, **kwargs)

    fake = FailedSetup([])
    install_sandbox(monkeypatch, fake)
    if isinstance(failure, TimeoutError):
        assert asyncio.run(scoring.file_scorer("complete")(state(), Target(''))).value == INCORRECT
    else:
        with pytest.raises(RuntimeError, match='details withheld'):
            asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
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
    with pytest.raises(RuntimeError, match='details withheld'):
        asyncio.run(scoring.file_scorer('complete')(state(), Target('')))
    assert len(fake.paths) == 1
    assert fake.calls[-1][0] == scoring.QUIESCENCE_COMMAND


def test_receipt_for_another_directory_is_incorrect(monkeypatch):
    fake = FakeSandbox([signed_receipt(bytes(range(32)), '/tmp/ccb-other')])
    install_sandbox(monkeypatch, fake)
    assert asyncio.run(scoring.file_scorer('complete')(state(), Target(''))).value == INCORRECT


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
