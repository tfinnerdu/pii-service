"""
tests/characterization/test_k8s_manifest.py

Pins required fields in K8s manifests. Manifest templating can silently drop
critical fields (imagePullSecrets, TLS secret name, Traefik middleware names).
This test is a tripwire for those silent drops.

When a manifest field changes intentionally:
  1. Update the manifest
  2. Update this test's expected value
  3. Update the comment to note when and why it changed
  4. All changes in the same commit
"""

from pathlib import Path
import yaml
import pytest


@pytest.fixture(scope="module")
def deployment_docs():
    path = Path(__file__).parent.parent.parent / "k8s" / "deployment.yaml"
    content = path.read_text()
    return list(yaml.safe_load_all(content))


@pytest.fixture(scope="module")
def deployment_doc(deployment_docs):
    return next((d for d in deployment_docs if d and d.get("kind") == "Deployment"), None)


@pytest.fixture(scope="module")
def ingress_doc(deployment_docs):
    return next((d for d in deployment_docs if d and d.get("kind") == "Ingress"), None)


@pytest.fixture(scope="module")
def middleware_doc(deployment_docs):
    return next((d for d in deployment_docs if d and d.get("kind") == "Middleware"), None)


# ---------------------------------------------------------------------------
# Deployment required fields — pinned 2025-05
# ---------------------------------------------------------------------------

class TestDeploymentManifest:
    """
    Known-good: Deployment in namespace=prod with imagePullSecrets=regcred.
    If namespace or imagePullSecrets change, update K8s cluster configuration first.
    """
    EXPECTED_NAMESPACE   = "prod"
    EXPECTED_IMAGE_SECRET = "regcred"
    EXPECTED_SERVICE_NAME = "pii-service"

    def test_deployment_exists(self, deployment_doc):
        assert deployment_doc is not None, "No Deployment document found in k8s/deployment.yaml"

    def test_namespace_is_prod(self, deployment_doc):
        ns = deployment_doc["metadata"]["namespace"]
        assert ns == self.EXPECTED_NAMESPACE, (
            f"Deployment namespace is '{ns}', expected '{self.EXPECTED_NAMESPACE}'. "
            "Deploying to the wrong namespace is a production incident."
        )

    def test_image_pull_secret_present(self, deployment_doc):
        secrets = deployment_doc["spec"]["template"]["spec"].get("imagePullSecrets", [])
        names = [s["name"] for s in secrets]
        assert self.EXPECTED_IMAGE_SECRET in names, (
            f"imagePullSecrets does not include '{self.EXPECTED_IMAGE_SECRET}'. "
            "The pod will fail to pull the private Docker Hub image without this."
        )

    def test_container_port_is_5900(self, deployment_doc):
        containers = deployment_doc["spec"]["template"]["spec"]["containers"]
        ports = [p["containerPort"] for c in containers for p in c.get("ports", [])]
        assert 5900 in ports, (
            "Container port 5900 not found in Deployment. "
            "Service targetPort and health probe path depend on this."
        )

    def test_liveness_probe_path_is_health(self, deployment_doc):
        containers = deployment_doc["spec"]["template"]["spec"]["containers"]
        for container in containers:
            probe = container.get("livenessProbe", {})
            http = probe.get("httpGet", {})
            assert http.get("path") == "/health", (
                f"Liveness probe path is '{http.get('path')}', expected '/health'. "
                "K8s will restart the pod if /health doesn't return 200."
            )

    def test_secret_key_ref_indentation(self, deployment_doc):
        """
        Footgun: secretKeyRef 'name' and 'key' must indent UNDER secretKeyRef,
        not at the same level. Verify the threshold env var is correctly structured.
        """
        containers = deployment_doc["spec"]["template"]["spec"]["containers"]
        for container in containers:
            for env in container.get("env", []):
                value_from = env.get("valueFrom", {})
                secret_key_ref = value_from.get("secretKeyRef", {})
                if secret_key_ref:
                    assert "name" in secret_key_ref, (
                        f"secretKeyRef for '{env.get('name')}' is missing 'name'. "
                        "This is the classic secretKeyRef indentation footgun."
                    )
                    assert "key" in secret_key_ref, (
                        f"secretKeyRef for '{env.get('name')}' is missing 'key'. "
                        "This is the classic secretKeyRef indentation footgun."
                    )


# ---------------------------------------------------------------------------
# Ingress required fields — pinned 2025-05
# ---------------------------------------------------------------------------

class TestIngressManifest:
    EXPECTED_HOST       = "du-int.doane.edu"
    EXPECTED_TLS_SECRET = "wildcard-doane-tls"
    EXPECTED_PATH       = "/prod/pii-service"

    def test_ingress_exists(self, ingress_doc):
        assert ingress_doc is not None, "No Ingress document found in k8s/deployment.yaml"

    def test_tls_secret_is_wildcard_doane(self, ingress_doc):
        tls = ingress_doc["spec"].get("tls", [])
        secret_names = [t["secretName"] for t in tls]
        assert self.EXPECTED_TLS_SECRET in secret_names, (
            f"TLS secret is not '{self.EXPECTED_TLS_SECRET}'. "
            "The wildcard cert covers all *.doane.edu — use it, don't create a separate cert."
        )

    def test_host_is_du_int(self, ingress_doc):
        rules = ingress_doc["spec"].get("rules", [])
        hosts = [r.get("host") for r in rules]
        assert self.EXPECTED_HOST in hosts, (
            f"Ingress host does not include '{self.EXPECTED_HOST}'. "
            "All Doane internal services route through du-int.doane.edu."
        )

    def test_path_includes_prod_prefix(self, ingress_doc):
        rules = ingress_doc["spec"].get("rules", [])
        all_paths = [
            p["path"]
            for r in rules
            for p in r.get("http", {}).get("paths", [])
        ]
        assert any(self.EXPECTED_PATH in path for path in all_paths), (
            f"Expected path prefix '{self.EXPECTED_PATH}' not found in Ingress. "
            "Traefik strip-prefix middleware depends on this path being correct."
        )


# ---------------------------------------------------------------------------
# Middleware required fields — pinned 2025-05
# ---------------------------------------------------------------------------

class TestMiddlewareManifest:
    EXPECTED_MIDDLEWARE_NAME = "prod-pii-service-prefix"
    EXPECTED_STRIP_PREFIX    = "/prod/pii-service"

    def test_middleware_exists(self, middleware_doc):
        assert middleware_doc is not None, "No Middleware document in k8s/deployment.yaml"

    def test_middleware_name(self, middleware_doc):
        name = middleware_doc["metadata"]["name"]
        assert name == self.EXPECTED_MIDDLEWARE_NAME, (
            f"Middleware name is '{name}', expected '{self.EXPECTED_MIDDLEWARE_NAME}'. "
            "The Ingress annotation references this middleware by name — rename must be atomic."
        )

    def test_strip_prefix_value(self, middleware_doc):
        prefixes = middleware_doc["spec"]["stripPrefix"]["prefixes"]
        assert self.EXPECTED_STRIP_PREFIX in prefixes, (
            f"stripPrefix does not include '{self.EXPECTED_STRIP_PREFIX}'. "
            "Flask routes at root level (/) only work because Traefik strips this prefix."
        )
