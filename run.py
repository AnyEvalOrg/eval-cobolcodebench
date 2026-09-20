#!/usr/bin/env python3
"""Run exactly one literal problem and emit a test-free local AnyEval bundle.

Actual serving receipts and live sandbox provenance are collected by AnyEval's
application hooks; this standalone runner leaves absent evidence explicitly null.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
TASK_PREFIX = "cobolcodebench/"


def validate_sample_id(sample_id: str) -> str:
    if any(char in sample_id for char in "*?[]"):
        raise ValueError("refusing glob-like sample id: pass one literal id")
    from cobolcodebench.dataset import manifest

    if sample_id not in manifest()["task_ids"]:
        raise ValueError("sample id is not in the packaged dataset")
    return sample_id


def emit_bundle(log, args, out: Path) -> dict:
    bundle = json.loads((HERE / "bundle.template.json").read_text())
    bundle["generated_at"] = datetime.now(timezone.utc).isoformat()
    bundle["eval"]["sample_id"] = args.sample_id
    bundle["eval"]["task"] = TASK_PREFIX + args.task
    bundle["model"]["name"] = args.model
    bundle["model"]["provider"] = args.model.partition("/")[0]
    bundle["scaffold"]["token_limit"] = args.token_limit
    bundle["sandbox"]["class"] = "sandbox-k8s" if args.sandbox_type == "k8s" else "sandbox-local"
    bundle["outputs"]["status"] = log.status
    samples = log.samples or []
    if len(samples) != 1 or str(samples[0].id) != args.sample_id:
        raise ValueError("Runner did not produce exactly the requested sample")
    scores = samples[0].scores or {}
    if len(scores) == 1:
        score = next(iter(scores.values()))
        bundle["outputs"].update(score=score.value, explanation=score.explanation)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    return bundle


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--task", choices=["cobolcodebench_instruct", "cobolcodebench_complete"], required=True)
    ap.add_argument("--sample-id", required=True)
    ap.add_argument("--model", required=True, help="Inspect provider/model reference")
    ap.add_argument("--scaffold", choices=["baseline"], default="baseline")
    ap.add_argument("--token-limit", type=int, default=32768)
    ap.add_argument("--sandbox-type", choices=["k8s", "docker"], default="k8s")
    ap.add_argument("--log-dir", default=str(HERE / ".build/logs"))
    ap.add_argument("--bundle", default=str(HERE / "bundle.json"))
    args = ap.parse_args()
    try:
        validate_sample_id(args.sample_id)
    except ValueError as exc:
        ap.error(str(exc))
    if args.token_limit <= 0:
        ap.error("--token-limit must be positive")
    from inspect_ai import eval as inspect_eval
    from cobolcodebench import cobolcodebench_instruct, cobolcodebench_complete

    task_fn = cobolcodebench_instruct if args.task == "cobolcodebench_instruct" else cobolcodebench_complete

    logs = inspect_eval(
        task_fn(sandbox_type=args.sandbox_type),
        model=args.model,
        sample_id=args.sample_id,
        epochs=1,
        token_limit=args.token_limit,
        log_dir=args.log_dir,
    )
    if len(logs) != 1:
        raise ValueError("Runner expected one task log")
    bundle = emit_bundle(logs[0], args, Path(args.bundle))
    print(f"status={bundle['outputs']['status']} score={bundle['outputs']['score']}")
    return 0 if logs[0].status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
