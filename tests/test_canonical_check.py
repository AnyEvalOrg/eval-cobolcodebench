"""Canonical-check orchestration tests use authored data and a mocked compiler."""
import json
from pathlib import Path

import pytest
import yaml
from scripts import canonical_check as checker


def record():
    return dict(program_name='task_func_01', canonical_solution='AUTHORED_FIXTURE',
                inputs=json.dumps({'shared.txt': 'before'}),
                outputs=json.dumps({'shared.txt': 'after\n'}))


@pytest.mark.parametrize('outcome', ['pass', 'compile', 'run', 'timeout', 'missing', 'newline'])
def test_reference_check_staging_failures_and_in_place_output(monkeypatch, outcome):
    calls = []

    def step(argv, cwd, timeout):
        calls.append(argv)
        assert (cwd / 'task_func_01.cbl').read_bytes() == b'       AUTHORED_FIXTURE'
        if argv[0] == 'cobc':
            assert argv == ['cobc', '-x', '-o', 'task_func_01', 'task_func_01.cbl']
            assert (cwd / 'shared.txt').read_bytes() == b'before'
            return (1, False) if outcome == 'compile' else (0, False)
        assert argv == ['./task_func_01']
        if outcome == 'run':
            return 1, False
        if outcome == 'timeout':
            return -9, True
        if outcome == 'missing':
            (cwd / 'shared.txt').unlink()
        else:
            (cwd / 'shared.txt').write_bytes(b'after\r\n' if outcome == 'newline' else b'after\n')
        return 0, False

    monkeypatch.setattr(checker, 'step', step)
    failure = checker.check_record(record())
    assert len(calls) == (1 if outcome == 'compile' else 2)
    if outcome == 'pass':
        assert failure is None
    elif outcome in ('compile', 'run'):
        assert failure['reason'] == f'{outcome} error (exit 1)'
    elif outcome == 'timeout':
        assert failure['reason'] == 'run timeout'
    else:
        assert failure['reason'] == 'output mismatch (output file is also an input file)'


def test_checker_loads_all_records_and_emits_partition_without_private_fields():
    records, manifest = checker.load_source(Path('cobolcodebench/data'))
    assert len(records) == 46
    report = checker.make_eligibility(records, manifest['source_sha256'], checker.IMAGE,
                                      '2026-09-20', 'authored test',
                                      check=lambda r: {'reason': 'synthetic failure'} if r['program_name'] == 'task_func_17' else None)
    assert len(report['eligible_task_ids']) == 45
    assert set(report['excluded_tasks']) == {'task_func_17'}
    assert not {'canonical_solution', 'inputs', 'outputs'} & set(report)


def test_cloudbuild_runs_checker_in_reference_image():
    config = yaml.safe_load(Path('scripts/cloudbuild-canonical.yaml').read_text())
    step = config['steps'][0]
    assert config['substitutions']['_SANDBOX_IMAGE'] == checker.IMAGE
    assert step['name'] == '${_SANDBOX_IMAGE}'
    assert step['entrypoint'] == '/usr/local/bin/python3'
    assert step['args'][0] == 'scripts/canonical_check.py'
