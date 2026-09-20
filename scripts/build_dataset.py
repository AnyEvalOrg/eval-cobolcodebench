"""Deterministically package the supplied HF snapshot; no network or git needed."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parents[1]


def main():
    raw = (ROOT / 'CobolCodeBench_Dataset.jsonl').read_bytes()
    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    validate = runpy.run_path(str(ROOT / 'cobolcodebench/dataset.py'))['validate_record']
    for record in records:
        validate(record)
    ids = [r['program_name'] for r in records]
    if len(records) != 46 or len(set(ids)) != 46:
        raise ValueError('Expected 46 distinct upstream program_name values')
    data = b''.join((json.dumps(r, ensure_ascii=False, separators=(',', ':')) + '\n').encode() for r in records)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode='wb', filename='', mtime=0, compresslevel=9) as stream:
        stream.write(data)
    artifact = out.getvalue()
    manifest = dict(dataset='harshini-kumar/CobolCodeBench',
                    upstream_revision=(ROOT / 'UPSTREAM-REVISION').read_text().strip(),
                    source_path='CobolCodeBench_Dataset.jsonl', license='Apache-2.0',
                    selection='All 46 default split records; original order and program_name values',
                    count=len(records),
                    input_file_count=sum(len(json.loads(r['inputs'])) for r in records),
                    output_file_count=sum(len(json.loads(r['outputs'])) for r in records),
                    source_sha256=hashlib.sha256(raw).hexdigest(),
                    card_sha256=hashlib.sha256((ROOT / 'UPSTREAM-DATASET-CARD.md').read_bytes()).hexdigest(),
                    artifact_sha256=hashlib.sha256(artifact).hexdigest(), artifact_bytes=len(artifact),
                    ids_sha256=hashlib.sha256(('\n'.join(ids)+'\n').encode()).hexdigest(), task_ids=ids)
    target = ROOT / 'cobolcodebench/data'
    target.mkdir(parents=True, exist_ok=True)
    (target / 'problems.jsonl.gz').write_bytes(artifact)
    (target / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f"Packaged {len(records)} records, {manifest['output_file_count']} output files, {len(artifact)} bytes")


if __name__ == '__main__':
    main()
