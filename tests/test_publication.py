"""Exercise the real Inspect event proxy and AnyEval publication redactor."""
import asyncio
import json
import logging
from pathlib import Path

import pytest
import yaml
from inspect_ai.log._transcript import Transcript, _transcript
from inspect_ai.scorer import Target
from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

import cobolcodebench.scoring as scoring
from cobolcodebench.publication import private_grading
from cobolcodebench.task import record_to_sample
from test_scoring import FakeSandbox, install_sandbox, record, result, state


@pytest.fixture
def redact_export(monkeypatch):
    app_root = Path('/Users/jperla/josh/repos/anyeval-app')
    if app_root.is_dir():
        monkeypatch.syspath_prepend(str(app_root))
        # This is importable in the requested venv: exercise production code.
        from app.runner import redact_export
        return redact_export
    # Portable package contract: sensitive material must be absent even before
    # a publisher does anything. No synthetic redactor that could mask a leak.
    return lambda export: export


@pytest.mark.parametrize('outcome', ['correct', 'timeout', 'infrastructure'])
def test_rendered_sample_and_events_contain_no_structured_tests(monkeypatch, redact_export, caplog, outcome):
    input_secret = 'PRIVATE_INPUT_SENTINEL'
    output_secret = 'EXPECTED_OUTPUT_SENTINEL'
    fixture = record(expected=output_secret, test_input=input_secret)
    
    monkeypatch.setattr(scoring, 'load_records', lambda: [fixture])

    class LoggingSandbox(FakeSandbox):
        async def exec(self, cmd, input=None, **kwargs):
            # These are precisely the provider logger and fields that normally
            # expose exec input/output, including enriched infrastructure errors.
            for logger_name in ('k8s_sandbox._logger', 'inspect_ai.util._subprocess',
                                'inspect_ai.util._sandbox.docker.compose',
                                'inspect_ai.util._sandbox.docker.util'):
                logging.getLogger(logger_name).error('%s %s', input_secret, output_secret)
            if outcome == 'timeout':
                raise TimeoutError(input_secret + output_secret)
            if outcome == 'infrastructure':
                raise ConnectionError(input_secret + output_secret)
            return await super().exec(cmd, input=input, **kwargs)

    fake = LoggingSandbox([result(output_secret), result(output_secret)])
    install_sandbox(monkeypatch, fake)
    sample = record_to_sample(fixture, "complete")
    transcript = Transcript()
    token = _transcript.set(transcript)
    try:
        try:
            score = asyncio.run(scoring.file_scorer("complete")(state(), Target('')))
            details = {'scores': {'cobolcodebench_scorer': score.model_dump(mode='json')}}
        except RuntimeError as error:
            from inspect_ai._util.rich import format_traceback
            monkeypatch.setenv('INSPECT_TRACEBACK_LOCALS', '1')
            # Exclude this test caller, whose locals deliberately contain the
            # synthetic secrets; inspect the scorer frames the package owns.
            plain, ansi = format_traceback(type(error), error, error.__traceback__.tb_next)
            details = {'error': {'message': str(error), 'traceback': plain, 'traceback_ansi': ansi}}
        exported = {'samples': [{**sample.model_dump(mode='json'), **details,
                                 'events': [event.model_dump(mode='json') for event in transcript.events]}]}
        # Include Inspect's embedded sample event copy as well as the top level.
        exported['samples'][0]['events'].append({'event': 'sample_init', 'sample': sample.model_dump(mode='json')})
        for document in (exported, redact_export(exported)):
            rendered = json.dumps(document)
            assert input_secret not in rendered
            assert output_secret not in rendered
            assert 'public_test_cases' not in rendered
            assert 'private_test_cases' not in rendered
        assert input_secret not in caplog.text and output_secret not in caplog.text
        assert not any(event.event == 'sandbox' for event in transcript.events)
    finally:
        _transcript.reset(token)


def test_policy_covers_private_fields():
    policy = yaml.safe_load(Path('redaction.yaml').read_text())
    assert policy['version'] == 1
    assert {'inputs', 'outputs', 'canonical_solution'} <= set(policy['redact'])
    assert set(policy['sandbox_exec']) == {'input', 'stdout', 'stderr'}


def test_private_proxy_does_not_disable_public_provenance_or_other_contexts(caplog):
    fake = FakeSandbox([])
    public = SandboxEnvironmentProxy(fake)
    with private_grading(public):
        assert public._events is True
        logging.getLogger('k8s_sandbox._logger').error('PRIVATE_DIAGNOSTIC')
        import contextvars
        contextvars.Context().run(logging.getLogger('k8s_sandbox._logger').error, 'PUBLIC_CONCURRENT_DIAGNOSTIC')
    logging.getLogger('k8s_sandbox._logger').error('PUBLIC_PROVENANCE_DIAGNOSTIC')
    assert 'PRIVATE_DIAGNOSTIC' not in caplog.text
    assert 'PUBLIC_CONCURRENT_DIAGNOSTIC' in caplog.text
    assert 'PUBLIC_PROVENANCE_DIAGNOSTIC' in caplog.text


def test_unknown_proxy_contract_fails_closed():
    with pytest.raises(TypeError, match='pinned sandbox event proxy'):
        with private_grading(object()):
            pytest.fail('must not execute with unknown logging behavior')
