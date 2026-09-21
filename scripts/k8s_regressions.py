"""Operator-only Inspect task: exercise the actual production gVisor pod.

Run with the operator's KUBECONFIG:
inspect eval scripts/k8s_regressions.py --model mockllm/model
This module is intentionally absent from the package task registry.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import re
import sys

# Inspect loads task files with scripts/ as its Python working directory. Use
# this checkout's package and sibling fixtures even when launched via the CLI.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import solver
from inspect_ai.util import sandbox

from cobolcodebench.publication import private_grading
from cobolcodebench.receipts import verify_receipt
from cobolcodebench.sandbox_runner import RUNNER, SETUP
from cobolcodebench.scoring import cleanup_candidate
from cobolcodebench.task import task_sandbox
from scripts.linux_regressions import DISK_CASES, FLAGS, case_request, expected_receipt

CASES = ('bytes', 'forks', 'memory_aggregate', *DISK_CASES, 'shm_readonly', 'ptrace_denied', 'detached')


async def run_case(environment, name):
    summary = dict.fromkeys((*FLAGS, 'signed_receipt', 'expected',
                             'cleanup_succeeded', 'pod_usable'), False)
    cleanup_after = 0
    try:
        async with asyncio.timeout(10):
            setup_result = await environment.exec(
                ['timeout', '-s', 'KILL', '5s', '/usr/local/bin/python3', '-I', '-c', SETUP],
                cwd='/', input=json.dumps(case_request(name)), timeout=5, timeout_retry=False,
            )
        if setup_result.returncode != 0:
            raise RuntimeError("Sandbox setup failed")
        setup = json.loads(setup_result.stdout)
        work, key = setup['cwd'], bytes.fromhex(setup['key'])
        if len(key) != 32 or not re.fullmatch(r'/tmp/ccb-[a-zA-Z0-9_-]+', work):
            raise ValueError('Invalid setup')
        cleanup_after = asyncio.get_running_loop().time() + 35
        async with asyncio.timeout(35):
            result = await environment.exec(
                ['timeout', '-s', 'KILL', '30s', '/usr/local/bin/python3', '-I', '-c', RUNNER, work],
                cwd='/', timeout=30, timeout_retry=False,
            )
        receipt = verify_receipt(result.stdout, key)
        if receipt is not None and receipt['cwd'] == work:
            cleanup_after = 0
            summary.update({flag: receipt.get(flag, False) for flag in FLAGS})
            summary['signed_receipt'] = True
            summary['expected'] = expected_receipt(name, receipt)
    except Exception:
        # Publish flags only, never provider output, keys or exception chains.
        pass
    finally:
        cleanup = asyncio.create_task(cleanup_candidate(environment, cleanup_after))
        try:
            await asyncio.shield(cleanup)
            summary['cleanup_succeeded'] = True
        except asyncio.CancelledError:
            await cleanup
            raise
        except Exception:
            pass
        try:
            async with asyncio.timeout(10):
                probe = await environment.exec(
                    ['timeout', '-s', 'KILL', '5s', '/usr/local/bin/python3', '-I', '-c', 'pass'],
                    cwd='/', timeout=5, timeout_retry=False,
                )
            summary['pod_usable'] = probe.returncode == 0
        except Exception:
            pass
    return summary


@solver
def regressions():
    async def solve(state, generate):
        with private_grading(sandbox()) as environment:
            summary = {name: await run_case(environment, name) for name in CASES}
        state.metadata['regressions'] = summary
        print(json.dumps(summary, sort_keys=True))
        return state
    return solve


@scorer(metrics=[accuracy()])
def regression_scorer():
    async def score(state, target):
        summary = state.metadata.get('regressions', {})
        passed = set(summary) == set(CASES) and all(
            all(summary[name].get(flag) is True for flag in
                ('signed_receipt', 'expected', 'cleanup_succeeded', 'pod_usable'))
            for name in CASES
        )
        return Score(value=CORRECT if passed else INCORRECT,
                     explanation=json.dumps(summary, sort_keys=True))
    return score


@task
def k8s_regressions():
    return Task(dataset=[Sample(id='containment', input='Run synthetic containment regressions.')],
                solver=regressions(), scorer=regression_scorer(), model='mockllm/model',
                sandbox=task_sandbox(), epochs=1)
