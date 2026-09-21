"""One generation, one epoch (pass@1), reference-eligible tasks in each mode."""
import os
from importlib.resources import files
from pathlib import Path
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ChatMessageSystem, ChatMessageUser, GenerateConfig
from inspect_ai.solver import generate
from .dataset import load_eligible_records, manifest, eligibility
from .prompts import SYSTEM_MESSAGE, user_prompt
from .scoring import file_scorer


def record_to_sample(record: dict, mode: str) -> Sample:
    return Sample(id=record['program_name'], input=[
        ChatMessageSystem(content=SYSTEM_MESSAGE),
        ChatMessageUser(content=user_prompt(record, mode)),
    ], metadata={'program_name': record['program_name'], 'mode': mode})


def load_dataset(mode: str) -> MemoryDataset:
    return MemoryDataset(name='CobolCodeBench-' + mode,
                         samples=[record_to_sample(r, mode) for r in load_eligible_records()])


def _task(mode: str, sandbox_type: str, anyeval_chart: bool) -> Task:
    if sandbox_type not in {'k8s', 'docker'}:
        raise ValueError('sandbox_type must be k8s or docker')
    resources = files('cobolcodebench')
    config = str(resources.joinpath('values.yaml' if sandbox_type == 'k8s' else 'compose.yaml'))
    if sandbox_type == 'k8s' and anyeval_chart:
        from k8s_sandbox import K8sSandboxEnvironmentConfig
        os.environ.setdefault('INSPECT_K8S_DEFAULT_NAMESPACE', 'anyeval-sandbox')
        config = K8sSandboxEnvironmentConfig(chart=str(resources.joinpath('chart')), values=Path(config))
    return Task(dataset=load_dataset(mode), solver=generate(), scorer=file_scorer(mode),
                sandbox=(sandbox_type, config), epochs=1, version='1.0.0',
                config=GenerateConfig(temperature=0.3, max_tokens=4096),
                metadata={'metric': 'pass@1', 'eligibility': eligibility(), 'dataset_provenance': {
                    k: v for k, v in manifest().items() if k != 'task_ids'}})


@task
def cobolcodebench_instruct(sandbox_type: str = 'k8s', anyeval_chart: bool = True) -> Task:
    """Generate a complete COBOL program from the upstream instruction."""
    return _task('instruct', sandbox_type, anyeval_chart)


@task
def cobolcodebench_complete(sandbox_type: str = 'k8s', anyeval_chart: bool = True) -> Task:
    """Complete the upstream partial COBOL program."""
    return _task('complete', sandbox_type, anyeval_chart)
