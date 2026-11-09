import pytest
from production_approval.authorization.isolation import LocalClients, Credentials, SafetyError, assert_local_url


@pytest.mark.parametrize("url", ["https://elasticfilesystem.us-east-1.amazonaws.com", "http://127.0.0.1:4566",
    "http://localhost:4570", "http://127.0.0.1.evil.test:4570", "http://127.0.0.1:4570.evil.test",
    "http://127.0.0.1:4570@aws.example.com", "http://127.0.0.1:4570/", "http://[::1]:4570", ""])
def test_non_allowlisted_endpoint_rejected(monkeypatch, url):
    monkeypatch.setenv("AWS_ENDPOINT_URL", url)
    with pytest.raises(SafetyError):
        LocalClients()


@pytest.mark.parametrize("key,value", [
    ("AWS_PROFILE", "production"), ("AWS_DEFAULT_PROFILE", "n8"),
    ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEPRODUCTION"), ("AWS_SECRET_ACCESS_KEY", "not-test"),
    ("AWS_SESSION_TOKEN", "real-session"), ("AWS_ROLE_ARN", "arn:aws:iam::123457089012:role/Admin"),
    ("AWS_WEB_IDENTITY_TOKEN_FILE", "/tmp/production-token"),
    ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/credentials"),
    ("AWS_CONFIG_FILE", "/tmp/production-config"), ("AWS_SHARED_CREDENTIALS_FILE", "/tmp/credentials"),
    ("AWS_EC2_METADATA_DISABLED", "false"), ("AWS_DEFAULT_REGION", "eu-west-1"),
    ("AWS_ENDPOINT_URL_EFS", "https://elasticfilesystem.us-east-1.amazonaws.com"),
])
def test_production_identity_sources_fail_closed(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(SafetyError):
        LocalClients()


def test_missing_endpoint_cannot_fall_back(monkeypatch):
    monkeypatch.delenv("AWS_ENDPOINT_URL")
    with pytest.raises(SafetyError):
        LocalClients()


def test_sdk_uses_explicit_credentials_and_endpoint(monkeypatch):
    import botocore.credentials
    def forbidden(*_, **__):
        raise AssertionError("SDK attempted credential chain")
    monkeypatch.setattr(botocore.credentials.CredentialResolver, "load_credentials", forbidden)
    client = LocalClients().client("efs")
    assert client.meta.endpoint_url == "http://127.0.0.1:4570"
    with pytest.raises(SafetyError):
        LocalClients().client("efs", Credentials("AKIAREAL", "secret"))


def test_runtime_send_hook_rejects_redirect_and_environment_change(monkeypatch):
    from types import SimpleNamespace
    client = LocalClients().client("efs")
    with pytest.raises(SafetyError):
        client.meta.events.emit("before-send.efs.DeleteAccessPoint", request=SimpleNamespace(url="https://aws.example.com"))
    monkeypatch.setenv("AWS_PROFILE", "production")
    with pytest.raises(SafetyError):
        client.meta.events.emit("before-send.efs.DeleteAccessPoint", request=SimpleNamespace(url="http://127.0.0.1:4570/2015-02-01/access-points/fsap-example"))
