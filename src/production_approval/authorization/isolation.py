"""An intentionally non-configurable public-cloud boundary for this pilot."""
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import boto3
from botocore.config import Config

ENDPOINT = "http://127.0.0.1:4570"
ACCOUNT = "000000000000"
REGION = "us-east-1"
MARKER = {"ApprovalPOC": "disposable"}


class SafetyError(RuntimeError):
    pass


def assert_local_environment():
    if os.environ.get("AWS_ENDPOINT_URL") != ENDPOINT:
        raise SafetyError("AWS_ENDPOINT_URL must equal the single allowlisted Floci endpoint")
    if any(os.environ.get(k) for k in (
        "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    )):
        raise SafetyError("Profiles, role/web/container credentials and ambient sessions are forbidden")
    if (os.environ.get("AWS_ACCESS_KEY_ID"), os.environ.get("AWS_SECRET_ACCESS_KEY")) != ("test", "test"):
        raise SafetyError("Only explicit synthetic test/test bootstrap environment is accepted")
    for key in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        if os.environ.get(key) != os.devnull:
            raise SafetyError("Normal AWS config/credential files must be disabled")
    if os.environ.get("AWS_EC2_METADATA_DISABLED") != "true":
        raise SafetyError("AWS metadata credential discovery must be disabled")
    for key, value in os.environ.items():
        if key.startswith("AWS_ENDPOINT_URL") and value != ENDPOINT:
            raise SafetyError("A service-specific endpoint attempts to escape Floci")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if os.environ.get(key) != REGION:
            raise SafetyError("Only the synthetic pilot Region is accepted")


def assert_local_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme, parsed.hostname, parsed.port) != ("http", "127.0.0.1", 4570) or parsed.username or parsed.password or parsed.fragment:
        raise SafetyError("AWS request destination is not the exact loopback endpoint")


@dataclass(frozen=True, repr=False)
class Credentials:
    key: str = field(repr=False)
    secret: str = field(repr=False)
    token: str | None = field(default=None, repr=False)


class LocalClients:
    """No default boto3 session, profile chain, metadata, proxy or endpoint fallback.

    Issued credentials are admitted only from responses of this guarded emulator.
    The bootstrap identity is an emulator administrator, not an IAM-bound user.
    """
    def __init__(self):
        assert_local_environment()
        self.bootstrap = Credentials("test", "test")
        self._issued = {self.bootstrap}

    def admit_floci_credentials(self, data):
        assert_local_environment()
        c = Credentials(data["AccessKeyId"], data["SecretAccessKey"], data.get("SessionToken"))
        self._issued.add(c)
        return c

    def client(self, service, credentials=None):
        assert_local_environment()
        c = credentials or self.bootstrap
        if c not in self._issued:
            raise SafetyError("Credentials were not issued by the guarded local emulator")
        session = boto3.session.Session(aws_access_key_id=c.key, aws_secret_access_key=c.secret,
                                       aws_session_token=c.token, region_name=REGION)
        client = session.client(service, endpoint_url=ENDPOINT, config=Config(
            proxies={}, retries={"max_attempts": 0}, connect_timeout=2, read_timeout=5,
            endpoint_discovery_enabled=False, signature_version="v4"))
        if client.meta.endpoint_url != ENDPOINT:
            raise SafetyError("SDK endpoint mismatch")
        def before_send(request, **_):
            assert_local_environment()
            assert_local_url(request.url)
        client.meta.events.register("before-send.*.*", before_send)
        return client
