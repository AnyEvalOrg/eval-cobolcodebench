import gzip
import hashlib
import json
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
