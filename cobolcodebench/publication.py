"""Keep grading material out of Inspect events and provider diagnostic logs.

These private APIs are pinned to inspect_ai 0.3.260 / k8s-sandbox 0.13.0.
AnyEval does not interpret redaction.yaml or scrub sandbox input/output keys.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import logging

from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy

_PRIVATE = ContextVar("cobolcodebench_private_grading", default=False)


class _PrivateFilter(logging.Filter):
    def filter(self, record):
        return not _PRIVATE.get()


# K8s copies contextvars into its operation threads. Install once, without changing
# logger levels globally or suppressing concurrent samples' provenance diagnostics.
for _name in (
    "k8s_sandbox._logger",
    "inspect_ai.util._sandbox.docker.compose",
    "inspect_ai.util._sandbox.docker.util",
    "inspect_ai.util._subprocess",
):
    logging.getLogger(_name).addFilter(_PrivateFilter())


@contextmanager
def private_grading(environment):
    # A dedicated proxy avoids toggling the shared sample proxy's event switch.
    # Fail closed if Inspect changes its proxy contract.
    if not isinstance(environment, SandboxEnvironmentProxy):
        raise TypeError("Grading requires Inspect's pinned sandbox event proxy")
    private = SandboxEnvironmentProxy(environment._sandbox)
    token = _PRIVATE.set(True)
    try:
        with private.no_events():
            yield private
    finally:
        _PRIVATE.reset(token)
