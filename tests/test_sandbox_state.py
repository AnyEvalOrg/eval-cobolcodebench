import asyncio
import logging
import threading
from types import SimpleNamespace

import pytest
from kubernetes import client

from cobolcodebench import sandbox_state as module


def pod(*, phase='Running', reason=None, message=None, terminated=None, last=None,
        exit_code=1, signal=None):
    def state(reason):
        return client.V1ContainerState(terminated=(
            client.V1ContainerStateTerminated(exit_code=exit_code, signal=signal, reason=reason) if reason else None))
    return client.V1Pod(metadata=client.V1ObjectMeta(uid='sample-uid'), status=client.V1PodStatus(
        phase=phase, reason=reason, message=message, container_statuses=[
            client.V1ContainerStatus(name='default', image='fixture', image_id='fixture',
                                     ready=False, restart_count=0,
                                     state=state(terminated), last_state=state(last)),
        ]))


@pytest.mark.parametrize('fields,expected', [
    ({'phase': 'Failed', 'terminated': 'OOMKilled'}, module.MEMORY_EXHAUSTED),
    ({'last': 'OOMKilled'}, module.MEMORY_EXHAUSTED),
    ({'phase': 'Failed', 'terminated': 'Error', 'exit_code': 137}, module.MEMORY_EXHAUSTED),
    ({'last': 'Error', 'exit_code': 137}, module.MEMORY_EXHAUSTED),
    ({'terminated': 'Error', 'signal': 9}, module.MEMORY_EXHAUSTED),
    ({'last': 'Error', 'signal': 9}, module.MEMORY_EXHAUSTED),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Exceeded ephemeral-storage limit'}, module.STORAGE_EXHAUSTED),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Node had memory pressure'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': 'Node had DiskPressure'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'message': None}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'terminated': 'OOMKilled'}, None),
    ({'phase': 'Failed', 'reason': 'Evicted', 'terminated': 'Error', 'exit_code': 137}, None),
    ({'reason': 'Evicted', 'last': 'Error', 'signal': 9}, None),
    ({'phase': 'Unknown', 'reason': 'NodeNotReady'}, None),
    ({'phase': 'Running', 'reason': 'NodeNotReady'}, None),
    ({'phase': 'Failed', 'reason': 'Shutdown', 'message': 'Spot preemption'}, None),
    ({'phase': 'Failed', 'terminated': 'Error'}, None),
    ({'terminated': 'Error', 'exit_code': 143, 'signal': 15}, None),
    ({'phase': 'Succeeded', 'terminated': 'Completed'}, None),
    ({}, None),
])
def test_kernel_classification(fields, expected):
    assert module.classify_pod(pod(**fields)) == expected


@pytest.mark.parametrize('value', [None, client.V1Pod(), client.V1Pod(status=client.V1PodStatus())])
def test_absent_status_is_not_a_verdict(value):
    assert module.classify_pod(value) is None


@pytest.mark.parametrize('fields', [dict(terminated='OOMKilled'), dict(last='Error', exit_code=137),
                                  dict(terminated='Error', signal=9)])
def test_checks_all_container_statuses(fields):
    value = pod()
    value.status.container_statuses += pod(**fields).status.container_statuses
    assert module.classify_pod(value) == module.MEMORY_EXHAUSTED


@pytest.mark.parametrize('failure', [ConnectionError('PRIVATE'), TimeoutError('PRIVATE'),
                                     client.exceptions.ApiException(status=404, reason='PRIVATE')])
def test_lookup_failure_is_private_and_inconclusive(monkeypatch, caplog, failure):
    def lookup(environment):
        logging.getLogger('kubernetes.client.rest').warning('PRIVATE_RESPONSE')
        raise failure
    monkeypatch.setattr(module, '_read_pod', lookup)
    assert asyncio.run(module.sandbox_failure(object())) is None
    assert 'PRIVATE' not in caplog.text


def test_outer_deadline_bounds_even_stuck_lookup(monkeypatch):
    async def stuck(*args):
        await asyncio.Event().wait()
    monkeypatch.setattr(module.asyncio, 'to_thread', stuck)
    monkeypatch.setattr(module, 'LOOKUP_TIMEOUT', 0.01)
    assert asyncio.run(module.sandbox_failure(object())) is None


def test_lookup_waits_briefly_for_termination_status(monkeypatch):
    values = iter([pod(), pod(last='OOMKilled')])
    monkeypatch.setattr(module, '_read_pod', lambda env: next(values))
    assert asyncio.run(module.sandbox_failure(object())) == module.MEMORY_EXHAUSTED


@pytest.mark.parametrize('proxy', [False, True])
@pytest.mark.parametrize('uid', ['sample-uid', 'replacement-uid'])
@pytest.mark.parametrize('fields', [dict(terminated='OOMKilled'), dict(terminated='Error', exit_code=137),
                                  dict(last='Error', signal=9)])
def test_uses_provider_identity_context_client_and_network_timeout(monkeypatch, proxy, uid, fields):
    from inspect_ai.util._sandbox.events import SandboxEnvironmentProxy
    from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment
    from k8s_sandbox import _kubernetes_api
    environment = object.__new__(K8sSandboxEnvironment)
    environment._pod = SimpleNamespace(info=SimpleNamespace(
        name='exact-pod', namespace='sample-ns', context_name='sample-context', uid='sample-uid'))
    value = pod(**fields)
    value.metadata.uid = uid
    calls = []
    def get_client(context):
        calls.append((context, threading.get_ident()))
        def read(**kwargs):
            assert threading.get_ident() == calls[-1][1]
            assert kwargs == dict(name='exact-pod', namespace='sample-ns', _request_timeout=(1, 1))
            return value
        return SimpleNamespace(read_namespaced_pod=read)
    monkeypatch.setattr(_kubernetes_api, 'k8s_client', get_client)
    if proxy:
        environment = SandboxEnvironmentProxy(environment)
    result = asyncio.run(module.sandbox_failure(environment))
    assert result == (module.MEMORY_EXHAUSTED if uid == 'sample-uid' else None)
    assert calls[0][0] == 'sample-context'
    assert calls[0][1] != threading.get_ident()


def test_other_provider_is_inconclusive():
    assert asyncio.run(module.sandbox_failure(object())) is None
