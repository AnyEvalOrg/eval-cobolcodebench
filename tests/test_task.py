from importlib.resources import files
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from cobolcodebench import cobolcodebench_instruct as cobolcodebench


def test_docker_task_builds_offline():
    task = cobolcodebench(sandbox_type="docker")
    assert len(task.dataset) == 38
    assert task.epochs == 1
    assert task.sandbox.type == "docker"
    assert Path(task.sandbox.config).is_file()
    config = yaml.safe_load(Path(task.sandbox.config).read_text())
    service = config["services"]["default"]
    assert service["image"] == "eval-cobol-sandbox:local"
    assert service["build"]["dockerfile"] == "Dockerfile"
    assert set(service["cap_add"]) == {"SETUID", "SETGID", "KILL", "CHOWN", "DAC_OVERRIDE", "SYS_PTRACE"}
    assert service["network_mode"] == "none"
    assert service["user"] == "0:0"
    assert service["read_only"] is True
    assert service["volumes"] == ["/tmp"]
    assert service["tmpfs"] == ["/dev/shm:ro,size=16m"]
    assert not task.dataset[0].target


def test_default_k8s_values_match_anyeval_contract():
    task = cobolcodebench()
    assert task.sandbox.type == "k8s"
    assert task.sandbox.config.values.name == "values.yaml"
    values = yaml.safe_load(task.sandbox.config.values.read_text())
    service = values["services"]["default"]
    assert values["automountServiceAccountToken"] is False
    assert service["runtimeClassName"] == "gvisor"
    assert service["nodeSelector"] == {"cloud.google.com/gke-spot": "true"}
    assert service["image"] == "us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0"
    assert service["networkIsolated"] is True
    assert service["securityContext"]["runAsNonRoot"] is False
    assert service["securityContext"]["allowPrivilegeEscalation"] is False
    assert service["securityContext"]["capabilities"]["drop"] == ["ALL"]
    for key in ("allowDomains", "allowEntities", "allowCIDR"):
        assert values[key] == []
    policy = values["additionalResources"][0]["spec"]
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert policy["egress"] == []


def test_anyeval_chart_is_packaged_and_selected():
    pytest.importorskip("k8s_sandbox")
    task = cobolcodebench()
    assert task.sandbox.type == "k8s"
    assert Path(task.sandbox.config.chart).joinpath("Chart.yaml").is_file()
    assert task.sandbox.config.values.is_file()
    chart = files("cobolcodebench").joinpath("chart/templates/pod.yaml").read_text()
    assert "restartPolicy: Never" in chart
    assert "inspect/service: default" in chart
    assert "coredns" not in chart


@pytest.mark.parametrize("kwargs", [{"sandbox_type": "local"}])
def test_invalid_parameters_fail_early(kwargs):
    with pytest.raises(ValueError):
        cobolcodebench(**kwargs)


def test_values_follow_installed_pinned_provider_schema():
    provider = pytest.importorskip("k8s_sandbox")
    import json
    import jsonschema

    schema = Path(provider.__file__).parent / "resources/helm/agent-env/values.schema.json"
    values = yaml.safe_load(files("cobolcodebench").joinpath("values.yaml").read_text())
    jsonschema.validate(values, json.loads(schema.read_text()))


def test_builtin_chart_is_explicit_exception():
    task = cobolcodebench(anyeval_chart=False)
    assert Path(task.sandbox.config).name == "values.yaml"


HELM_INSTALL = (
    "Install Helm 3 or 4 (for example 3.19.0) from https://github.com/helm/helm/releases/tag/v3.19.0: "
    "download the official archive for your OS/architecture, verify its SHA-256 "
    "against the release checksum, extract it, and put helm on PATH. "
    "See README.md, Build, test and publication."
)


def require_helm():
    helm = shutil.which("helm")
    if helm is None:
        pytest.fail("helm is required on PATH. " + HELM_INSTALL, pytrace=False)
    return helm


@pytest.fixture(scope="module")
def helm():
    executable = require_helm()
    version = subprocess.run(
        [executable, "version", "--template", "{{ .Version }}"],
        capture_output=True, text=True, timeout=30,
    )
    assert version.returncode == 0, version.stdout + version.stderr
    assert version.stdout.strip().startswith(("v3.", "v4.")), HELM_INSTALL
    return executable


def test_missing_helm_fails_with_install_instructions(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(pytest.fail.Exception, match="helm is required on PATH") as error:
        require_helm()
    assert HELM_INSTALL in str(error.value)


def test_render_default_chart_matches_anyeval_pod_contract(helm):
    config = cobolcodebench().sandbox.config
    lint = subprocess.run(
        [helm, "lint", "--strict", str(config.chart), "-n", "anyeval-sandbox",
         "-f", str(config.values)],
        capture_output=True, text=True, timeout=30,
    )
    assert lint.returncode == 0, lint.stdout + lint.stderr
    result = subprocess.run(
        [helm, "template", "ccb-fixture", str(config.chart), "-n", "anyeval-sandbox",
         "-f", str(config.values)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rendered = result.stdout
    resources = [r for r in yaml.safe_load_all(rendered) if r]
    assert len(resources) == 2
    assert sum(r["kind"] == "Pod" for r in resources) == 1
    assert sum(r["kind"] == "NetworkPolicy" for r in resources) == 1
    assert {r["kind"] for r in resources if r} == {"Pod", "NetworkPolicy"}
    pod = next(r for r in resources if r and r["kind"] == "Pod")
    spec = pod["spec"]
    assert pod["metadata"]["namespace"] == "anyeval-sandbox"
    assert pod["metadata"]["name"] == "ccb-fixture-default"
    assert pod["metadata"]["labels"]["inspect/service"] == "default"
    assert spec["runtimeClassName"] == "gvisor"
    assert spec["nodeSelector"] == {"cloud.google.com/gke-spot": "true"}
    assert spec["automountServiceAccountToken"] is False
    assert spec["restartPolicy"] == "Never"
    assert "tolerations" not in spec
    assert not spec.get("hostNetwork", False)
    assert not any("hostPath" in v for v in spec.get("volumes", []))
    assert len(spec["containers"]) == 1
    container = spec["containers"][0]
    import tomllib
    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    version = project["project"]["version"]
    assert container["image"] == (
        "us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/"
        f"eval-cobol-sandbox:{version}"
    )
    assert container["resources"]["requests"] == container["resources"]["limits"]
    assert container["resources"]["requests"] == {
        "cpu": "1", "memory": "2Gi", "ephemeral-storage": "1Gi",
    }
    security = spec["containers"][0]["securityContext"]
    values = yaml.safe_load(config.values.read_text())
    assert security == values["services"]["default"]["securityContext"]
    assert security["runAsUser"] == security["runAsGroup"] == 0
    assert set(security["capabilities"]["add"]) == {"SETUID", "SETGID", "KILL", "CHOWN", "DAC_OVERRIDE", "SYS_PTRACE"}
    assert not security.get("privileged", False)
    assert security["seccompProfile"] == {"type": "RuntimeDefault"}
    assert security["runAsNonRoot"] is False
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert spec['volumes'] == [
        {'name': 'tmp', 'emptyDir': {'sizeLimit': '512Mi'}},
        {'name': 'shm', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '16Mi'}},
    ]
    assert container['volumeMounts'] == [
        {'name': 'tmp', 'mountPath': '/tmp'}, {'name': 'shm', 'mountPath': '/dev/shm', 'readOnly': True},
    ]
    assert security["capabilities"]["drop"] == ["ALL"]
    policy = next(r for r in resources if r and r["kind"] == "NetworkPolicy")
    assert policy["metadata"]["namespace"] == "anyeval-sandbox"
    assert policy["metadata"]["name"] == "ccb-fixture-cobolcodebench-deny-all"
    assert policy["spec"]["egress"] == []
    assert policy["spec"]["ingress"] == []
    assert set(policy["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    # The policy must select THIS release's pod and nothing else: `podSelector: {}` selects
    # every pod in the namespace (it starved the shared egress proxy on 2026-09-11), and the
    # instance label is what the Pod template stamps on the release's own pod.
    pod = next(r for r in resources if r and r["kind"] == "Pod")
    assert policy["spec"]["podSelector"] == {"matchLabels": {"app.kubernetes.io/instance": "ccb-fixture"}}
    assert pod["metadata"]["labels"]["app.kubernetes.io/instance"] == "ccb-fixture"
    assert "cilium" not in rendered.lower() and "coredns" not in rendered.lower()
    for template in Path(config.chart).joinpath("templates").rglob("*"):
        if template.is_file():
            source = template.read_text().lower()
            assert "cilium" not in source, template
            assert "statefulset" not in source, template


@pytest.mark.parametrize("original, replacement, diagnostic", [
    ('{{- $service := .Values.services.default }}', '', 'undefined variable "$service"'),
    ('{{- toYaml', '{{-toYaml', 'parse error'),
    ('.Values.services.default', '.Values.missing.default', 'nil pointer evaluating'),
], ids=["undeclared-service", "invalid-trim-marker", "unknown-values-path"])
def test_helm_rejects_invalid_chart_templates(helm, tmp_path, original, replacement, diagnostic):
    config = cobolcodebench().sandbox.config
    chart = tmp_path / "chart"
    shutil.copytree(config.chart, chart)
    template = chart / "templates/pod.yaml"
    source = template.read_text()
    assert original in source  # Ensure the mutation actually changes this chart.
    template.write_text(source.replace(original, replacement, 1))
    result = subprocess.run(
        [helm, "template", "ccb-fixture", str(chart), "-n", "anyeval-sandbox",
         "-f", str(config.values)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0, "Helm accepted an invalid template"
    assert "templates/pod.yaml" in result.stderr
    assert diagnostic in result.stderr


def test_default_namespace_is_anyeval_sandbox(monkeypatch):
    import os
    monkeypatch.delenv("INSPECT_K8S_DEFAULT_NAMESPACE", raising=False)
    cobolcodebench()
    assert os.environ["INSPECT_K8S_DEFAULT_NAMESPACE"] == "anyeval-sandbox"


def test_reverse_task_and_anyeval_catalog_match():
    import json
    from cobolcodebench import cobolcodebench_complete
    task = cobolcodebench_complete(sandbox_type='docker')
    assert len(task.dataset) == 38 and task.epochs == 1
    assert task.metadata['metric'] == 'pass@1'
    catalog = json.loads(Path('anyeval.json').read_text())
    assert catalog['execution']['class'] == 'sandbox-k8s'
    assert catalog['tasks'] == [{'name': 'cobolcodebench_instruct', 'samples': 38}, {'name': 'cobolcodebench_complete', 'samples': 38}]
    assert catalog['total_samples'] == 76
    assert catalog['upstream']['commit'] == '9d02534b7d1aabcbac1a1ec21c5a5e80c50323a8'


def test_generation_defaults_match_upstream_chat_api():
    task = cobolcodebench(sandbox_type='docker')
    assert task.config.temperature == 0.3
    assert task.config.max_tokens == 4096


def test_provider_chart_renders_identical_sandbox_storage(helm):
    provider = pytest.importorskip('k8s_sandbox')
    chart = Path(provider.__file__).parent / 'resources/helm/agent-env'
    values_path = cobolcodebench(anyeval_chart=False).sandbox.config
    result = subprocess.run([helm, 'template', 'ccb-provider', str(chart),
                             '-n', 'anyeval-sandbox', '-f', str(values_path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    resources = [r for r in yaml.safe_load_all(result.stdout) if r]
    workload = next(r for r in resources if r['kind'] == 'StatefulSet')
    spec = workload['spec']['template']['spec']
    service = yaml.safe_load(Path(values_path).read_text())['services']['default']
    container = next(c for c in spec['containers'] if c['name'] == 'default')
    assert container['securityContext'] == service['securityContext']
    assert set(container['securityContext']['capabilities']['add']) == {
        'SETUID', 'SETGID', 'KILL', 'CHOWN', 'DAC_OVERRIDE', 'SYS_PTRACE'}
    assert container['securityContext']['capabilities']['drop'] == ['ALL']
    assert container['securityContext']['readOnlyRootFilesystem'] is True
    assert [m for m in container['volumeMounts'] if m['mountPath'] in {'/tmp', '/dev/shm'}] == service['volumeMounts']
    for volume in service['volumes']:
        assert volume in spec['volumes']
