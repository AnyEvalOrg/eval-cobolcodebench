import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import pytest
from cobolcodebench.dataset import load_records, manifest, file_names
from cobolcodebench.task import record_to_sample
from cobolcodebench.prompts import SYSTEM_MESSAGE


def test_all_original_records_ids_and_hashes():
    records = load_records()
    raw = Path('CobolCodeBench_Dataset.jsonl').read_bytes()
    assert records == [json.loads(line) for line in raw.splitlines()]
    expected = [f'task_func_{n:02}' for n in [*range(1, 6), *range(7, 41), 43, 44, 45, 47, 48, 49, 55]]
    assert [r['program_name'] for r in records] == expected == manifest()['task_ids']
    assert len(expected) == len(set(expected)) == 46
    assert hashlib.sha256(raw).hexdigest() == manifest()['source_sha256']
    assert sum(len(json.loads(r['outputs'])) for r in records) == 49
    assert sum(len(json.loads(r['inputs'])) for r in records) == 55


@pytest.mark.parametrize('mode', ['instruct', 'complete'])
def test_prompts_are_exact_and_private_fields_are_not_published(mode):
    for record in load_records():
        sample = record_to_sample(record, mode)
        assert [m.role for m in sample.input] == ['system', 'user']
        assert [m.content for m in sample.input] == [SYSTEM_MESSAGE, record[mode + '_prompt']]
        assert not sample.target
        assert sample.metadata == {'program_name': record['program_name'], 'mode': mode}
        assert record['canonical_solution'] not in '\n'.join(m.content for m in sample.input)
        # Raw prompts may contain worked examples; the separate answer map is
        # never interpolated, even if snippets happen to occur in upstream prose.
        sentinel = {**record, 'outputs': 'EXPECTED_OUTPUT_SENTINEL', 'canonical_solution': 'CANONICAL_SENTINEL', 'inputs': 'PRIVATE_INPUT_SENTINEL'}
        rendered = record_to_sample(sentinel, mode).model_dump_json()
        assert not any(value in rendered for value in ('EXPECTED_OUTPUT_SENTINEL', 'CANONICAL_SENTINEL', 'PRIVATE_INPUT_SENTINEL'))


def test_build_is_deterministic():
    paths = [Path('cobolcodebench/data') / name for name in ('problems.jsonl.gz', 'manifest.json')]
    before = [p.read_bytes() for p in paths]
    subprocess.run([sys.executable, 'scripts/build_dataset.py'], check=True, capture_output=True)
    assert before == [p.read_bytes() for p in paths]


@pytest.mark.parametrize('value', ['../evil', '/tmp/evil', 'a,a', 'a/b', '.', '..', 'bad\x00name', '-flag'])
def test_reject_unsafe_file_names(value):
    with pytest.raises(ValueError):
        file_names(value)


def test_checksum_failure_is_private(monkeypatch):
    import cobolcodebench.dataset as dataset
    monkeypatch.setattr(dataset, 'manifest', lambda: {'artifact_sha256': 'wrong'})
    with pytest.raises(RuntimeError, match='details withheld'):
        load_records()


def assert_reference_eligibility(info):
    assert set(info) == {'schema_version', 'checked_at', 'reference_image',
                         'source_sha256', 'method', 'evidence',
                         'eligible_task_ids', 'excluded_tasks'}
    checked_at = datetime.fromisoformat(info['checked_at'])
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=timezone.utc)
    assert checked_at <= datetime.now(timezone.utc)
    assert info['schema_version'] == 1
    assert info['source_sha256'] == manifest()['source_sha256']
    assert info['excluded_tasks'] == {
        'task_func_17': {'reason': 'compile error (exit 1)', 'stage': 'compile', 'returncode': 1},
        **{f'task_func_{n}': {'reason': 'run error (exit 1)', 'stage': 'run', 'returncode': 1}
           for n in (20, 55)},
        **{f'task_func_{n}': {'reason': 'output mismatch', 'stage': 'compare'}
           for n in (21, 23, 47, 48, 49)},
    }
    assert info['eligible_task_ids'] == [
        name for name in manifest()['task_ids'] if name not in info['excluded_tasks']
    ]
    assert len(info['eligible_task_ids']) == 38


def test_reference_eligibility_partition_and_reasons():
    from cobolcodebench.dataset import eligibility, load_eligible_records
    from cobolcodebench.task import load_dataset
    info = eligibility()
    assert_reference_eligibility(info)
    assert len(info['eligible_task_ids']) == len(load_eligible_records()) == 38
    for mode in ('instruct', 'complete'):
        assert [sample.id for sample in load_dataset(mode)] == info['eligible_task_ids']


@pytest.mark.parametrize('checked_at', ['2000-01-01', datetime.now(timezone.utc).isoformat()])
def test_generated_reference_eligibility_passes_same_validation(checked_at):
    from cobolcodebench.dataset import eligibility
    from scripts import canonical_check as checker

    outcomes = {
        name: ({'reason': f'{stage} error (exit 1)', 'stage': stage, 'returncode': 1}
               if stage in ('compile', 'run') else {'reason': 'output mismatch', 'stage': stage})
        for name, stage in {
            'task_func_17': 'compile', 'task_func_20': 'run',
            'task_func_21': 'compare', 'task_func_23': 'compare',
            'task_func_47': 'compare', 'task_func_48': 'compare',
            'task_func_49': 'compare', 'task_func_55': 'run',
        }.items()
    }
    report = checker.make_eligibility(
        load_records(), manifest()['source_sha256'], checker.IMAGE,
        checked_at, 'authored test', check=lambda record: outcomes.get(record['program_name']))
    assert_reference_eligibility(report)
    expected = {**eligibility(), 'checked_at': checked_at, 'evidence': 'authored test'}
    assert json.dumps(report, indent=2) == json.dumps(expected, indent=2)


@pytest.mark.parametrize('checked_at', ['invalid', '9999-12-31', '9999-12-31T00:00:00+00:00'])
def test_reference_eligibility_validation_rejects_invalid_or_future_dates(checked_at):
    from cobolcodebench.dataset import eligibility
    with pytest.raises((ValueError, AssertionError)):
        assert_reference_eligibility({**eligibility(), 'checked_at': checked_at})


def test_eligibility_rejects_an_incomplete_partition(monkeypatch):
    import cobolcodebench.dataset as dataset
    original = dataset.manifest()
    monkeypatch.setattr(dataset, 'manifest', lambda: {**original, 'task_ids': original['task_ids'][:-1]})
    with pytest.raises(ValueError, match='eligibility'):
        dataset.eligibility()
