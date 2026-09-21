import json
from types import SimpleNamespace

import pytest

import run
from cobolcodebench.dataset import manifest


@pytest.mark.parametrize("sample_id", ["*", "?", "[abc]", "missing-synthetic-id"])
def test_runner_rejects_globs_and_unknown_ids(sample_id):
    with pytest.raises(ValueError):
        run.validate_sample_id(sample_id)


def test_runner_accepts_exact_dataset_id():
    sample_id = manifest()["task_ids"][0]
    assert run.validate_sample_id(sample_id) == sample_id


def test_bundle_omits_test_metadata_and_unverified_provenance(tmp_path):
    sample_id = manifest()["task_ids"][0]
    args = SimpleNamespace(task="cobolcodebench_instruct", sample_id=sample_id, model="mockllm/model", token_limit=100, sandbox_type="docker")
    score = SimpleNamespace(value="C", explanation="All 2 tests passed.")
    sample = SimpleNamespace(id=sample_id, scores={"file_scorer": score}, metadata={"tests": "SECRET_SENTINEL"})
    log = SimpleNamespace(status="success", samples=[sample])
    path = tmp_path / "bundle.json"
    bundle = run.emit_bundle(log, args, path)
    assert bundle["outputs"]["score"] == "C"
    assert bundle["sandbox"]["provenance"] is None
    assert bundle["model"]["served"] == []
    assert "SECRET_SENTINEL" not in path.read_text()
    assert json.loads(path.read_text())["eval"]["sample_id"] == sample_id


@pytest.mark.parametrize('sample_id', ['task_func_17', 'task_func_49'])
def test_runner_rejects_excluded_ids(sample_id):
    with pytest.raises(ValueError, match='eligible dataset'):
        run.validate_sample_id(sample_id)
