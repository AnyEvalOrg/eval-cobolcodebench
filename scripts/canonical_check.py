#!/usr/bin/env python3
"""Check all canonical solutions as root in the disposable reference image.

Standard library only; never prints program text, file contents, or diagnostics.
Known dataset failures are results, not a checker failure. Infrastructure errors
abort without replacing the eligibility file. Never run this on the host.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0'
METHOD = 'root compile and run; cobc -x; inputs in cwd; exact UTF-8 byte comparison'


def load_source(data_dir: Path) -> tuple[list[dict], dict]:
    manifest = json.loads((data_dir / 'manifest.json').read_text())
    raw = (data_dir / 'problems.jsonl.gz').read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['artifact_sha256']:
        raise ValueError('Dataset artifact checksum mismatch')
    unpacked = gzip.decompress(raw)
    # The packager reserializes JSON; source_sha256 identifies the original JSONL,
    # while artifact_sha256 above authenticates the packaged bytes we execute.
    records = [json.loads(line) for line in unpacked.splitlines()]
    if [r['program_name'] for r in records] != manifest['task_ids']:
        raise ValueError('Dataset IDs do not match manifest')
    return records, manifest


def step(argv: list[str], cwd: Path, timeout: int) -> tuple[int, bool]:
    child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    timed_out = False
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
    return child.returncode, timed_out


def check_record(record: dict, compile_timeout: int = 60, run_timeout: int = 60) -> dict | None:
    name = record['program_name']
    inputs, expected = json.loads(record['inputs']), json.loads(record['outputs'])
    with tempfile.TemporaryDirectory(prefix='ccb-canonical-') as temporary:
        work = Path(temporary)
        program = record['canonical_solution']
        # Same initial fixed-format indentation rule as the operator's check A.
        if not program.startswith('       '):
            program = '       ' + program.lstrip()
        (work / (name + '.cbl')).write_bytes(program.encode('utf-8'))
        for filename, content in inputs.items():
            (work / filename).write_bytes(content.encode('utf-8'))
        for stage, argv, timeout in (
            ('compile', ['cobc', '-x', '-o', name, name + '.cbl'], compile_timeout),
            ('run', ['./' + name], run_timeout),
        ):
            returncode, timed_out = step(argv, work, timeout)
            if timed_out:
                return {'reason': stage + ' timeout', 'stage': stage, 'timeout': True}
            if returncode:
                return {'reason': f'{stage} error (exit {returncode})',
                        'stage': stage, 'returncode': returncode}
        mismatches = []
        for filename, content in expected.items():
            path = work / filename
            if not path.is_file() or path.read_bytes() != content.encode('utf-8'):
                mismatches.append(filename)
        if mismatches:
            reason = 'output mismatch'
            if set(expected) & set(inputs):
                reason += ' (output file is also an input file)'
            return {'reason': reason, 'stage': 'compare'}
    return None


def make_eligibility(records: list[dict], source_sha256: str, image: str,
                     checked_at: str, evidence: str, check=check_record) -> dict:
    eligible, excluded = [], {}
    for record in records:
        name = record['program_name']
        failure = check(record)
        if failure is None:
            eligible.append(name)
        else:
            excluded[name] = failure
    return dict(schema_version=1, checked_at=checked_at, reference_image=image,
                source_sha256=source_sha256, method=METHOD, evidence=evidence,
                eligible_task_ids=eligible, excluded_tasks=excluded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.build/canonical-eligibility.json')
    parser.add_argument('--image', default=IMAGE, help='Reference image tag or resolved digest (provenance)')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not shutil.which('cobc'):
        parser.error('requires root Linux with cobc in a disposable eval-cobol-sandbox container')
    try:
        records, manifest = load_source(ROOT / 'cobolcodebench/data')
        report = make_eligibility(records, manifest['source_sha256'], args.image,
                                  datetime.now(timezone.utc).isoformat(), 'canonical_check.py')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        temporary.replace(args.output)
    except Exception:
        print('Canonical check failed; private details withheld.', file=sys.stderr)
        return 1
    # This is safe to retain in Cloud Build logs: IDs, reasons and provenance only.
    print(json.dumps(report, indent=2))
    print(f"{len(report['eligible_task_ids'])}/{len(records)} eligible; "
          f"{len(report['excluded_tasks'])} excluded")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
