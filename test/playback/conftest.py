from _pytest.fixtures import SubRequest
from pathlib import Path
from typing import Any, Dict, Generator, List, Union
from vcr import VCR
from vcr.request import Request

import functools
import json
import logging
import pytest

LOG = logging.getLogger(__name__)


def pytest_addoption(parser: pytest.Parser) -> None:
    """Parameters for setting up, recording and replaying cassettes."""
    group = parser.getgroup("ovh")

    # S3 Users: admin credentials
    group.addoption(
        "--ovh-s3-admin-access-key-id",
        action="store",
        default="not-configured",
        help="OVH S3 Access Key ID for the admin user (for setup)",
    )
    group.addoption(
        "--ovh-s3-admin-secret-access-key",
        action="store",
        default="not-configured",
        help="OVH S3 Secret Access Key for the admin user (for setup)",
    )

    # S3 Users: user1 credentials
    group.addoption(
        "--ovh-s3-user1-access-key-id",
        action="store",
        default="not-configured",
        help="OVH S3 Access Key ID for the user 1",
    )
    group.addoption(
        "--ovh-s3-user1-secret-access-key",
        action="store",
        default="not-configured",
        help="OVH S3 Secret Access Key for the user 1",
    )

    # S3 Buckets
    group.addoption(
        "--ovh-s3-bucket-existing-name",
        action="store",
        default="",
        help="Name of OVH S3 Bucket that exists (required when recording)",
    )
    group.addoption(
        "--ovh-s3-bucket-existing-setup",
        action="store_true",
        default=False,
        help=(
            "If true, when NOT replaying the cassettes (using --record-mode=rewrite or --disable-recording),\n"
            "use the S3 admin credentials to create the bucket (name from --ovh-s3-bucket-name-existing)\n"
            "use the OVH API credentials to set up the user policy for user1 (name from --ovh-api-user1-username)\n"
            "See test/playback/README.md for manual setup steps"
        ),
    )

    # S3 Region
    group.addoption(
        "--ovh-s3-region",
        action="store",
        default=None,
        help="OVH S3 Region (required when recording)",
    )

    # OVH API Credentials for test setup when recording
    # For now OVH-EU is assumed
    group.addoption(
        "--ovh-api-application-key",
        action="store",
        default="not-configured",
        help="OVH API Application Key for the admin user (for setup)",
    )
    group.addoption(
        "--ovh-api-application-secret",
        action="store",
        default="not-configured",
        help="OVH API Application Secret for the admin user (for setup)",
    )
    group.addoption(
        "--ovh-api-consumer-key",
        action="store",
        default="not-configured",
        help="OVH API Application Consumer Key for the admin user (for setup)",
    )
    group.addoption(
        "--ovh-api-project",
        action="store",
        default="not-configured",
        help="OVH API Project ID (for setup)",
    )
    group.addoption(
        "--ovh-api-user1-username",
        action="store",
        default="not-configured",
        help=(
            'OVH API Username to configure the S3 user "user1" (for setup). Note this is the user name (e.g. user-hExStR), '
            "not the hex or numeric ID."
        ),
    )


@pytest.hookimpl(trylast=True)
def pytest_report_header(config: pytest.Config) -> List[str]:
    """Useful headers at the beginning of the pytest session, to be able to diagnose issues."""
    options = []
    for cred in ("admin", "user1"):
        if (value := config.getoption(f"--ovh-s3-{cred}-access-key-id")) and value != "not-configured":
            redacted_value = f"<{value[:4]}..redacted({len(value)})>"
            options.append(f"{cred}-access-key-id={redacted_value}")
        if (value := config.getoption(f"--ovh-s3-{cred}-secret-access-key")) and value != "not-configured":
            redacted_value = f"<redacted({len(value)})>"
            options.append(f"{cred}-secret-access-key={redacted_value}")
    if value := config.getoption("--ovh-s3-bucket-existing-name"):
        options.append(f"bucket-existing-name={value!r}")
    if value := config.getoption("--ovh-s3-bucket-existing-setup"):
        options.append(f"bucket-existing-setup={value!r}")
    if value := config.getoption("--ovh-s3-region"):
        options.append(f"region={value!r}")

    api_options = []
    for cred in ("application-key", "application-secret", "consumer-key"):
        if (value := config.getoption("--ovh-api-" + cred)) and value != "not-configured":
            redacted_value = f"<redacted({len(value)})>"
            api_options.append(f"{cred}={redacted_value}")
    if value := config.getoption("--ovh-api-project"):
        api_options.append(f"project={value!r}")
    if value := config.getoption("--ovh-api-user1-username"):
        api_options.append(f"user1-username={value!r}")

    # pytest-recording v0.13.4 does not have a report header, so we add it here for convenience
    pytest_recording_options = []
    if value := config.getoption("--record-mode"):
        pytest_recording_options.append(f"record-mode={value!r}")
    if value := config.getoption("--block-network"):
        pytest_recording_options.append(f"block-network={value!r}")
    if value := config.getoption("--allowed-hosts"):
        pytest_recording_options.append(f"allowed-hosts={value!r}")
    if value := config.getoption("--disable-recording"):
        pytest_recording_options.append(f"disable-recording={value!r}")

    lines = [
        "recording: " + ", ".join(pytest_recording_options or ["(default)"]),
        "cassette(ovh-s3): " + ", ".join(options or ["(default)"]),
        "cassette(ovh-api): " + ", ".join(api_options or ["(default)"]),
    ]
    return lines


@pytest.fixture(scope="module")
def stored_cassette_parameters(
    request: SubRequest,
    vcr_cassette_dir: str,
    record_mode: str,
) -> Generator[Dict[str, str], None, None]:
    """Store the important test parameters used during recording to make the assertions correct and still configurable.

    For now, we store one file per module. This means entire modules have to be re-recorded together. It is simpler to
    implement this way, as there are some module-scoped fixtures that can re-use this as well."""
    vcr_cassette_path = Path(vcr_cassette_dir)
    test_params_path = vcr_cassette_path / "test_params.json"
    if test_params_path.exists():
        with test_params_path.open("r") as f:
            cassette_test_params = json.load(f)
        LOG.info("Read stored cassette record parameters %r", cassette_test_params)
        yield cassette_test_params
    else:
        LOG.info("No stored cassette record parameters found at %s", vcr_cassette_path)
        yield {}
    if record_mode == "none" or not vcr_cassette_path.exists():
        LOG.info("Will not store cassette record parameters with record_mode=%r at path %s", record_mode, vcr_cassette_path)
        return

    # Only store non-sensitive information here, that is also relevant for the recorded cassettes
    cassette_test_params = {
        "--ovh-s3-bucket-existing-name": request.config.getoption("--ovh-s3-bucket-existing-name"),
        "--ovh-s3-region": request.config.getoption("--ovh-s3-region"),
    }
    with test_params_path.open("w") as f:
        json.dump(cassette_test_params, f, indent=2, sort_keys=True)
        f.write("\n")
    LOG.info("Stored cassette record parameters to %s", test_params_path)


def _prefer_string_headers_over_bytes(request: Request) -> Request:
    """For pretty human-readable rendering in the YAML cassette files."""
    new_headers = request.headers.copy()
    for k, value in new_headers.items():
        if isinstance(value, bytes):
            try:
                str_value = value.decode("ascii")
            except UnicodeDecodeError:
                pass
            else:
                new_headers[k] = str_value
    request.headers = new_headers
    return request


def _redact_boto3_authorization_header(
    key: str,
    value: Union[str, bytes],
    request: Request,
    *,
    admin_access_key_id: str,
    user1_access_key_id: str,
) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    value = value.replace(admin_access_key_id, "{admin_access_key_id}")
    value = value.replace(user1_access_key_id, "{user1_access_key_id}")
    return value


@pytest.fixture(scope="module")
def vcr_config(request: SubRequest, stored_cassette_parameters: Dict[str, str]) -> Dict[str, Any]:
    """Common VCR configuration for all tests.

    We redact sensitive credentials that would show up in the botocore requests.
    In theory, the authorization header will only contain the access key id, which is not sensitive by itself.

    We could also redact the "random request id" or timestamps in the headers to have smaller diffs when re-recording,
    but we might be losing some important information for diagnosing problems.
    """
    admin_access_key_id = (
        request.config.getoption("--ovh-s3-admin-access-key-id")
        or stored_cassette_parameters.get("--ovh-s3-admin-access-key-id")
        or "not-configured"
    )
    user1_access_key_id = (
        request.config.getoption("--ovh-s3-user1-access-key-id")
        or stored_cassette_parameters.get("--ovh-s3-user1-access-key-id")
        or "not-configured"
    )

    return {
        "filter_headers": [
            (
                "authorization",
                functools.partial(
                    _redact_boto3_authorization_header,
                    admin_access_key_id=admin_access_key_id,
                    user1_access_key_id=user1_access_key_id,
                ),
            ),
        ],
        "allow_playback_repeats": False,
        "before_record_request": [
            _prefer_string_headers_over_bytes,
        ],
    }


def pytest_recording_configure(config: pytest.Config, vcr: VCR) -> None:
    """We don't need to configure any matchers or serializers. This log line can be useful to know what is going on."""
    LOG.info("VCR recording configured")
