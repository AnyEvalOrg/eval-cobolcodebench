"""Offline, integrity-checked records; private fields never enter Sample objects."""
import gzip
import hashlib
import json
import re
from importlib.resources import files


def manifest() -> dict:
    return json.loads(files('cobolcodebench').joinpath('data/manifest.json').read_text(encoding='utf-8'))


def file_names(value: str) -> list[str]:
    names = [name.strip() for name in value.split(',') if name.strip()]
    if len(set(names)) != len(names) or any(
        not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', name) for name in names
    ):
        raise ValueError('Invalid file names')
    return names


def validate_record(record: dict) -> None:
    if not re.fullmatch(r'task_func_\d{2}', record['program_name']):
        raise ValueError('Invalid program name')
    for kind in ('input', 'output'):
        names = file_names(record[kind + '_file_names'])
        content = json.loads(record[kind + 's'])
        if not isinstance(content, dict) or set(content) != set(names):
            raise ValueError('File declarations do not match content keys')
        if any(not isinstance(value, str) for value in content.values()):
            raise ValueError('File contents must be strings')
        if kind == 'output' and not names:
            raise ValueError('Every task requires an output file')
    for key in ('instruct_prompt', 'complete_prompt', 'canonical_solution'):
        if not isinstance(record[key], str) or not record[key].strip():
            raise ValueError('Missing prompt or solution')


def load_records() -> list[dict]:
    try:
        info = manifest()
        raw = files('cobolcodebench').joinpath('data/problems.jsonl.gz').read_bytes()
        if hashlib.sha256(raw).hexdigest() != info['artifact_sha256']:
            raise ValueError('Checksum mismatch')
        records = [json.loads(line) for line in gzip.decompress(raw).splitlines()]
        ids = [r['program_name'] for r in records]
        if len(records) != 46 or len(set(ids)) != 46 or ids != info['task_ids']:
            raise ValueError('Invalid ids')
        for record in records:
            validate_record(record)
        return records
    except Exception:
        pass
    raise RuntimeError('Packaged dataset invalid; details withheld.') from None
