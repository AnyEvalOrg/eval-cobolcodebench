"""Kernel-attributed backstop for missing receipts, never sink enumeration.

Provider internals are pinned to inspect_ai 0.3.260 / k8s-sandbox 0.13.0.
Call only after successful SETUP and a RUNNER without an authenticated receipt.
Production callers receive only verdicts. An optional operator-regression
observer can inspect the exact lookup evidence without issuing another read.
"""
from __future__ import annotations

import asyncio
import time

from .publication import private_logging

MEMORY_EXHAUSTED = 'sandbox memory exhausted during candidate execution'
STORAGE_EXHAUSTED = 'sandbox storage exhausted during candidate execution'
LOOKUP_TIMEOUT = 4


def classify_pod(pod) -> str | None:
    """Classify a pod verified by _read_pod against the captured UID."""
    status = getattr(pod, 'status', None)
    if status is None:
        return None
    # Eviction is infrastructure unless explicitly attributed to storage.
    if status.reason == 'Evicted':
        if status.phase == 'Failed' and 'ephemeral-storage' in (status.message or '').lower():
            return STORAGE_EXHAUSTED
        return None
    for container in status.container_statuses or ():
        for state in (container.state, container.last_state):
            terminated = getattr(state, 'terminated', None)
            # A runsc sandbox killed by the host memory cgroup can be reported
            # by containerd as Error / exit 137 instead of OOMKilled. Require
            # Kubernetes termination evidence from the same pod UID, never
            # the RUNNER exec's exit code. Spot deletion yields 404; a NotReady
            # node with a Running/Unknown pod and no termination is inconclusive.
            if terminated is not None and (
                terminated.reason == 'OOMKilled'
                or terminated.exit_code == 137 or terminated.signal == 9
            ):
                return MEMORY_EXHAUSTED
    return None


def _read_pod(environment):
    from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy
    from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment
    from k8s_sandbox._kubernetes_api import k8s_client

    if isinstance(environment, SandboxEnvironmentProxy):
        environment = environment._sandbox
    if not isinstance(environment, K8sSandboxEnvironment):
        return None
    # This is the exact identity selected by the Helm release, not a label
    # search that could accidentally attribute another sample's termination.
    info = environment._pod.info
    # Obtain AND use the provider's thread-local client in the same thread.
    # It preserves kubeconfig context / in-cluster auth and token refresh.
    pod = k8s_client(info.context_name).read_namespaced_pod(
        name=info.name, namespace=info.namespace, _request_timeout=(1, 1),
    )
    return pod if pod.metadata.uid == info.uid else None


async def sandbox_failure(environment, *, on_lookup=None) -> str | None:
    """Bound API work and status propagation to four seconds; fail closed.

    Operator-only on_lookup(pod, error, started) observes each result using a
    monotonic lookup-start timestamp. Production scoring omits this observer.
    """
    lookup_started = time.monotonic()
    try:
        async with asyncio.timeout(LOOKUP_TIMEOUT):
            # Kubelet may report termination shortly after exec disconnects.
            for attempt in range(3):
                lookup_started = time.monotonic()
                with private_logging():
                    pod = await asyncio.to_thread(_read_pod, environment)
                if on_lookup is not None:
                    on_lookup(pod, None, lookup_started)
                if pod is None:
                    return None
                reason = classify_pod(pod)
                if reason is not None:
                    return reason
                if attempt < 2:
                    await asyncio.sleep(0.25)
    except Exception as error:
        # Never log an exception or the API response, even at debug level.
        if on_lookup is not None:
            on_lookup(None, error, lookup_started)
    return None
