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
import time

# Inspect loads task files with scripts/ as its Python working directory. Use
# this checkout's package and sibling fixtures even when launched via the CLI.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from inspect_ai import SampleSource, Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, accuracy, scorer
from inspect_ai.solver import solver
from inspect_ai.util import sandbox

from cobolcodebench.publication import private_grading
from cobolcodebench.receipts import verify_receipt
from cobolcodebench.sandbox_runner import RUNNER, SETUP
from cobolcodebench.scoring import cleanup_candidate, verdict
from cobolcodebench.sandbox_state import MEMORY_EXHAUSTED, sandbox_failure
from cobolcodebench.task import task_sandbox
from scripts.linux_regressions import (
    DISK_CASES, FLAGS, KERNEL_CASES, case_request, expected_receipt, sysv_unavailable,
)

CASES = ('bytes', 'forks', 'memory_aggregate', *DISK_CASES, 'shm_readonly', 'ptrace_denied', 'detached')


def classification_evidence(pod, error, elapsed):
    """Allowlist kubelet evidence; never publish exec output or exception text."""
    def message(value):
        return value[:200] if value is not None else None

    def state(value):
        terminated = getattr(value, 'terminated', None)
        return {'terminated': None if terminated is None else {
            'reason': terminated.reason, 'exitCode': terminated.exit_code,
            'signal': terminated.signal, 'message': message(terminated.message),
        }}

    status = getattr(pod, 'status', None)
    return {
        'phase': getattr(status, 'phase', None),
        'reason': getattr(status, 'reason', None),
        'message': message(getattr(status, 'message', None)),
        'containerStatuses': [
            {'name': container.name, 'state': state(container.state),
             'lastState': state(container.last_state)}
            for container in (getattr(status, 'container_statuses', None) or ())
        ],
        'lookup_failed': error is not None,
        'lookup_exception': type(error).__name__ if error is not None else None,
        'pod_gone': error is not None and getattr(error, 'status', None) == 404,
        'exec_failure_to_lookup_seconds': elapsed,
    }


async def run_case(environment, name):
    summary = dict.fromkeys((*FLAGS, 'signed_receipt', 'expected',
                             'cleanup_succeeded', 'pod_usable', 'kernel_oom',
                             'candidate_incorrect', 'sysv_unavailable'), False)
    cleanup_after = 0
    runner_started = False
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
        runner_started = True
        try:
            async with asyncio.timeout(35):
                result = await environment.exec(
                    ['timeout', '-s', 'KILL', '30s', '/usr/local/bin/python3', '-I', '-c', RUNNER, work],
                    cwd='/', timeout=30, timeout_retry=False,
                )
        finally:
            runner_finished = time.monotonic()
        receipt = verify_receipt(result.stdout, key)
        if receipt is not None and receipt['cwd'] == work:
            cleanup_after = 0
            summary.update({flag: receipt.get(flag, False) for flag in FLAGS})
            summary['signed_receipt'] = True
            summary['expected'] = expected_receipt(name, receipt)
            summary['sysv_unavailable'] = sysv_unavailable(name, receipt)
    except Exception:
        # Never publish provider output, keys or exception chains.
        pass
    finally:
        if runner_started and not summary['signed_receipt']:
            evidence = summary['classification_evidence'] = []
            reason = await sandbox_failure(environment, on_lookup=lambda pod, error, started: evidence.append(
                classification_evidence(pod, error, started - runner_finished)))
        if runner_started and not summary['signed_receipt'] and name in KERNEL_CASES:
            # Only same-pod Kubernetes termination evidence can attribute OOM.
            summary['kernel_oom'] = reason == MEMORY_EXHAUSTED
            summary['candidate_incorrect'] = (
                reason is not None and verdict(reason).value == INCORRECT
            )
            summary['expected'] = summary['kernel_oom'] and summary['candidate_incorrect']
            if summary['expected']:
                cleanup_after = 0
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
        names = CASES if state.sample_id == 'containment' else (str(state.sample_id),)
        assert all(name in (*CASES, *KERNEL_CASES) for name in names)
        with private_grading(sandbox()) as environment:
            summary = {name: await run_case(environment, name) for name in names}
        state.metadata['regressions'] = summary
        print(json.dumps(summary, sort_keys=True))
        return state
    return solve


@scorer(metrics=[accuracy()])
def regression_scorer():
    async def score(state, target):
        summary = state.metadata.get('regressions', {})
        names = CASES if state.sample_id == 'containment' else (str(state.sample_id),)
        passed = (all(name in (*CASES, *KERNEL_CASES) for name in names)
                  and set(summary) == set(names) and all(
            summary[name].get('expected') is True and (
                all(summary[name].get(flag) is True for flag in
                    ('signed_receipt', 'cleanup_succeeded', 'pod_usable'))
                or (name in KERNEL_CASES and summary[name].get('signed_receipt') is False
                    and summary[name].get('kernel_oom') is True
                    and summary[name].get('candidate_incorrect') is True)
            ) for name in names))
        return Score(value=CORRECT if passed else INCORRECT,
                     explanation=json.dumps(summary, sort_keys=True))
    return score


@task
def k8s_regressions():
    return Task(dataset=RegressionSamples(),
                solver=regressions(), scorer=regression_scorer(), model='mockllm/model',
                sandbox=task_sandbox(), epochs=1)


class RegressionSamples(SampleSource):
    """Only enqueue lethal samples after prior samples finish, at any concurrency."""

    def __init__(self):
        self.remaining = iter(KERNEL_CASES)

    def initial_samples(self):
        return [Sample(id='containment', input='Run synthetic containment regressions.')]

    async def next_samples(self):
        name = next(self.remaining, None)
        return ([Sample(id=name, input='Run a synthetic kernel memory regression.')]
                if name is not None else None)
