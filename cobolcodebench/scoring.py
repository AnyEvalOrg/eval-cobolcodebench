"""All-tests pass@1; only the external sandbox runs candidate programs."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re

from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import TaskState
from inspect_ai.util import OutputLimitExceededError, sandbox

from .dataset import load_records
from .publication import private_grading
from .sandbox_runner import CLEANUP_COMMAND, QUIESCENCE_COMMAND, RUNNER, SETUP
from .execution import execution_request
from .code_extractor import assemble_program
from .comparison import compare_outputs


def verdict(reason: str, compile_success: bool | None = None,
            correct: bool = False, upstream_score: float = 0.0) -> Score:
    import json
    return Score(value=CORRECT if correct else INCORRECT, explanation=json.dumps({
        'compile_success': compile_success, 'upstream_score': upstream_score, 'reason': reason,
    }, sort_keys=True))


@scorer(metrics=[accuracy()])
def file_scorer(mode: str):
    """Every named file must match; the upstream fuzzy score is diagnostic only."""
    if mode not in {'instruct', 'complete'}:
        raise ValueError('Invalid mode')

    # Closure data is not a scorer argument (Inspect logs scorer arguments), sample
    # metadata, target, or store. Only the selected record is decoded when scoring.
    records = {record["program_name"]: record for record in load_records()}

    async def private_score(state: TaskState, target: Target) -> Score:
        record = records[str(state.sample_id)]
        code = assemble_program(state.output.completion, record, mode)
        env = sandbox()
        payload = execution_request(code, record)
        request = json.dumps(payload)
        # Compile and run are independently timed, credential-dropped steps
        # inside one root supervisor; no candidate-controlled driver verdict.
        deadline = payload['timeout'] + payload['run_timeout'] + 10
        receipt = None
        cleanup_after = 0
        try:
            with private_grading(env) as private:
                try:
                    async with asyncio.timeout(10):
                        setup = await private.exec(
                            ["timeout", "-s", "KILL", "5s",
                             "/usr/local/bin/python3", "-I", "-c", SETUP],
                            cwd="/", input=request, timeout=5, timeout_retry=False,
                        )
                    setup_receipt = json.loads(setup.stdout)
                    work = setup_receipt["cwd"]
                    key = bytes.fromhex(setup_receipt["key"])
                    if len(key) != 32:
                        raise RuntimeError("Invalid setup key")
                    if not re.fullmatch(r"/tmp/ccb-[a-zA-Z0-9_-]+", work):
                        raise RuntimeError("Invalid setup directory")
                    # If exec returns early without a receipt, wait through
                    # the outer deadline before sweeping: the supervisor may
                    # still be starting. This uses the host monotonic clock.
                    cleanup_after = asyncio.get_running_loop().time() + deadline + 5
                    try:
                        async with asyncio.timeout(deadline + 5):
                            result = await private.exec(
                                ["timeout", "-s", "KILL", f"{deadline}s",
                                 "/usr/local/bin/python3", "-I", "-c", RUNNER, work],
                                cwd="/", timeout=deadline, timeout_retry=False,
                            )
                        receipt = verify_receipt(result.stdout, key)
                        if receipt is not None and receipt["cwd"] == work:
                            # Authenticated completion means no later spawn;
                            # sweep immediately before starting the next test.
                            cleanup_after = 0
                        else:
                            receipt = None
                    except Exception:
                        # No authenticated supervisor report is a failed test,
                        # including a killed supervisor or lost exec response.
                        receipt = None
                finally:
                    # A separate sandbox exec, never the candidate's parent or
                    # session, enforces cleanup on EVERY path (also setup failure).
                    cleanup = asyncio.create_task(cleanup_candidate(private, cleanup_after))
                    try:
                        await asyncio.shield(cleanup)
                    except asyncio.CancelledError:
                        await cleanup
                        raise
        except TimeoutError:
            return verdict("supervisor did not complete")
        except OutputLimitExceededError:
            return verdict("supervisor did not complete")
        except Exception:
            # Provider exceptions may embed stdin or captured output. Do not
            # allow them (or their exception chain) into an Inspect error event.
            raise RuntimeError("Private sandbox operation failed; details withheld.") from None
        # Neither success nor returncode from the run provider is a verdict channel.
        if receipt is None:
            return verdict("supervisor did not complete")
        compiled = receipt['compile_success']
        if receipt['timeout']:
            return verdict(f"{receipt['stage']} timeout", compiled)
        if receipt['overflow']:
            return verdict('output limit exceeded', compiled)
        if receipt['returncode'] != 0:
            return verdict(f"{receipt['stage']} error (exit {receipt['returncode']})", compiled)
        if receipt['stage'] != 'run' or not compiled:
            return verdict('run did not complete', compiled)
        expected = json.loads(record['outputs'])
        correct, diagnostic, count = compare_outputs(receipt['outputs'], expected)
        return verdict(f'{count}/{len(expected)} output files match exactly', compiled,
                       correct=correct, upstream_score=diagnostic)

    async def score(state: TaskState, target: Target) -> Score:
        # Raise outside the private frame and except block: even Inspect's optional
        # traceback-locals display must not render records, requests, keys or output.
        try:
            return await private_score(state, target)
        except Exception:
            pass
        raise RuntimeError("Private scoring failed; details withheld.") from None

    return score


async def cleanup_candidate(environment, not_before: float = 0) -> None:
    """Trusted, independent UID sweep; never proceed if cleanup itself fails."""
    try:
        delay = not_before - asyncio.get_running_loop().time()
        if delay > 0:
            await asyncio.sleep(delay)
        async with asyncio.timeout(10):
            cleanup = await environment.exec(
                list(CLEANUP_COMMAND), cwd="/", timeout=5, timeout_retry=False,
            )
        if cleanup.returncode not in (0, 1):
            raise RuntimeError("UID cleanup failed")
        async with asyncio.timeout(10):
            checked = await environment.exec(
                list(QUIESCENCE_COMMAND), cwd="/", timeout=5, timeout_retry=False,
            )
        if checked.returncode != 0:
            raise RuntimeError("UID cleanup did not reach quiescence")
    except Exception:
        # In particular do not turn a cleanup timeout into a candidate verdict.
        raise RuntimeError("Private sandbox cleanup failed; details withheld.") from None


def verify_receipt(stdout: str, key: bytes) -> dict | None:
    """Authenticate exact wrapper bytes before interpreting status or output."""
    try:
        envelope = json.loads(stdout)
        body, tag = envelope["body"], envelope["tag"]
        if not hmac.compare_digest(hmac.new(key, body.encode(), hashlib.sha256).hexdigest(), tag):
            return None
        receipt = json.loads(body)
        if (type(receipt["returncode"]) is not int
                or type(receipt["timeout"]) is not bool
                or type(receipt["overflow"]) is not bool
                or receipt.get("stage") not in {"compile", "run"}
                or not re.fullmatch(r"/tmp/ccb-[a-zA-Z0-9_-]+", receipt["cwd"])):
            return None
        if type(receipt['compile_success']) is not bool or not isinstance(receipt['outputs'], dict):
            return None
        if receipt['stage'] == 'run' and not receipt['compile_success']:
            return None
        receipt['outputs'] = {
            name: None if value is None else base64.b64decode(value, validate=True)
            for name, value in receipt['outputs'].items()
        }
        # stdout is private and irrelevant to the verdict; retained for runner tests.
        receipt['output'] = base64.b64decode(receipt['output'], validate=True).decode('utf-8', errors='replace')
        return receipt
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None
