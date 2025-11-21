from _pytest.fixtures import SubRequest
from pathlib import Path
from rohmu import factory
from typing import Dict, Generator, Optional

import boto3
import dataclasses
import json
import logging
import ovh
import pytest

_DEFAULT_STORAGE_CONFIG: factory.Config = {
    "storage_type": "s3",
    "port": 443,
    "is_secure": True,
    "is_verify_tls": True,
    "encrypted": True,
}


LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class OVHS3Credentials:
    aws_access_key_id: str
    aws_secret_access_key: str


@dataclasses.dataclass(frozen=True)
class OVHApiCredentials:
    application_key: str
    application_secret: str
    consumer_key: str
    project: str
    user1_username: str


@dataclasses.dataclass(frozen=True)
class OVHS3Config:
    region: str
    host: str


def _reconcile_with_stored_param(
    param: str,
    request: SubRequest,
    stored_cassette_parameters: Dict[str, str],
    record_mode: str,
) -> str:
    stored_value = stored_cassette_parameters.get(param)
    value = request.config.getoption(param)
    if stored_value and value and stored_value != value and record_mode == "none":
        raise ValueError(
            f"Parameter {param}={value!r} does not match the stored parameter used when recording {stored_value!r}"
        )

    if value:
        LOG.info("Using %r=%r from config", param, value)
        return value
    elif stored_value:
        LOG.info("Using %r=%r from stored cassette parameters", param, stored_value)
        return stored_value
    raise ValueError(f"Parameter {param!r} is required")


@pytest.fixture(name="ovh_api_credentials", scope="module")
def fixture_ovh_api_credentials(request: SubRequest, record_mode: str, disable_recording: bool) -> OVHApiCredentials:
    application_key = request.config.getoption("--ovh-api-application-key") or "not-configured"
    application_secret = request.config.getoption("--ovh-api-application-secret") or "not-configured"
    consumer_key = request.config.getoption("--ovh-api-consumer-key") or "not-configured"
    project = request.config.getoption("--ovh-api-project") or "not-configured"
    user1_username = request.config.getoption("--ovh-api-user1-username") or "not-configured"
    if _is_setup_enabled(request, record_mode, disable_recording) and "not-configured" in (
        application_key,
        application_secret,
        consumer_key,
        project,
        user1_username,
    ):
        raise ValueError(f"API Credentials are required when running in {record_mode = !r} {disable_recording = !r}")
    return OVHApiCredentials(
        application_key=application_key,
        application_secret=application_secret,
        consumer_key=consumer_key,
        project=project,
        user1_username=user1_username,
    )


@pytest.fixture(name="ovh_s3_admin_credentials", scope="module")
def fixture_ovh_s3_admin_credentials(request: SubRequest, record_mode: str, disable_recording: bool) -> OVHS3Credentials:
    aws_access_key_id = request.config.getoption("--ovh-s3-admin-access-key-id") or "not-configured"
    aws_secret_access_key = request.config.getoption("--ovh-s3-admin-secret-access-key") or "not-configured"
    if (record_mode != "none" or disable_recording) and (
        aws_access_key_id == "not-configured" or aws_secret_access_key == "not-configured"
    ):
        raise ValueError(f"S3 admin credentials are required when running in {record_mode = !r} {disable_recording = !r}")
    return OVHS3Credentials(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )


@pytest.fixture(name="ovh_s3_user1_credentials", scope="module")
def fixture_ovh_s3_user1_credentials(request: SubRequest, record_mode: str, disable_recording: bool) -> OVHS3Credentials:
    aws_access_key_id = request.config.getoption("--ovh-s3-user1-access-key-id") or "not-configured"
    aws_secret_access_key = request.config.getoption("--ovh-s3-user1-secret-access-key") or "not-configured"
    if (record_mode != "none" or disable_recording) and (
        aws_access_key_id == "not-configured" or aws_secret_access_key == "not-configured"
    ):
        raise ValueError(f"S3 user1 credentials are required when running in {record_mode = !r} {disable_recording = !r}")
    return OVHS3Credentials(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )


@pytest.fixture(name="ovh_s3_config", scope="module")
def fixture_ovh_s3_config(request: SubRequest, stored_cassette_parameters: Dict[str, str], record_mode: str) -> OVHS3Config:
    region = _reconcile_with_stored_param(
        param="--ovh-s3-region",
        request=request,
        stored_cassette_parameters=stored_cassette_parameters,
        record_mode=record_mode,
    )
    return OVHS3Config(
        region=region,
        host=f"s3.{region}.io.cloud.ovh.net",
    )


@pytest.fixture(name="ovh_s3_bucket_which_exists", scope="module")
def fixture_ovh_s3_bucket_which_exists(
    request: SubRequest,
    stored_cassette_parameters: Dict[str, str],
    record_mode: str,
) -> str:
    name = _reconcile_with_stored_param(
        param="--ovh-s3-bucket-existing-name",
        request=request,
        stored_cassette_parameters=stored_cassette_parameters,
        record_mode=record_mode,
    )
    return name


def _is_setup_enabled(request: SubRequest, record_mode: str, disable_recording: bool) -> bool:
    setup_enabled = request.config.getoption("--ovh-s3-bucket-existing-setup")
    if setup_enabled and record_mode == "none" and not disable_recording:
        raise ValueError(
            f"Parameter --ovh-s3-bucket-existing-setup cannot be used "
            f"when running in {record_mode = !r} {disable_recording = !r}"
        )

    return setup_enabled


@pytest.fixture(name="ovh_s3_module_setup_bucket", scope="module")
def fixture_ovh_s3_module_setup_bucket(
    request: SubRequest,
    ovh_s3_admin_credentials: OVHS3Credentials,
    ovh_s3_config: OVHS3Config,
    ovh_s3_bucket_which_exists: str,
    record_mode: str,
    disable_recording: bool,
) -> Generator[Optional[str], None, None]:
    if not _is_setup_enabled(request, record_mode, disable_recording):
        yield None
        return

    LOG.info("Setting up OVH S3 bucket...")
    s3 = boto3.client(
        "s3",
        region_name=ovh_s3_config.region,
        aws_access_key_id=ovh_s3_admin_credentials.aws_access_key_id,
        aws_secret_access_key=ovh_s3_admin_credentials.aws_secret_access_key,
        endpoint_url=f"https://{ovh_s3_config.host}",
    )

    s3.create_bucket(Bucket=ovh_s3_bucket_which_exists)
    LOG.info("Created bucket %r", ovh_s3_bucket_which_exists)

    yield ovh_s3_bucket_which_exists
    LOG.info("Cleaning up OVH S3 bucket...")

    s3.delete_bucket(Bucket=ovh_s3_bucket_which_exists)
    LOG.info("Deleted bucket %r", ovh_s3_bucket_which_exists)


def load_user_policy_document(filename: str, bucket_name: str) -> str:
    with Path(__file__).with_name(filename).open() as f:
        policy_doc_template = json.load(f)
    policy_doc_str = json.dumps(policy_doc_template, separators=(",", ":"))
    policy_doc_str.replace("{BUCKET_NAME_HERE}", bucket_name)
    try:
        json.loads(policy_doc_str)
    except ValueError as ex:
        raise RuntimeError("Bad bucket name or policy file - rudimentary templating failed to produce valid JSON") from ex
    return policy_doc_str


def load_user_id(client: ovh.Client, project: str, username: str) -> str:
    users = client.get(f"/cloud/project/{project}/user")
    user = next((user for user in users if username == user["username"]), None)
    if user is None:
        raise ValueError(f"User with username={username} not found (out of {len(users)} users)")
    return user["id"]


@pytest.fixture(name="ovh_s3_module_setup_user1", scope="module")
def fixture_ovh_s3_module_setup_user1(
    request: SubRequest,
    ovh_api_credentials: OVHApiCredentials,
    ovh_s3_config: OVHS3Config,
    ovh_s3_bucket_which_exists: str,
    record_mode: str,
    disable_recording: bool,
) -> Generator[Optional[str], None, None]:
    if not _is_setup_enabled(request, record_mode, disable_recording):
        yield None
        return

    LOG.info("Setting up OVH S3 user1...")

    client = ovh.Client(
        endpoint="ovh-eu",
        application_key=ovh_api_credentials.application_key,
        application_secret=ovh_api_credentials.application_secret,
        consumer_key=ovh_api_credentials.consumer_key,
    )

    policy_doc_str = load_user_policy_document("s3-user1-user-policy.json", bucket_name=ovh_s3_bucket_which_exists)
    user_id = load_user_id(client=client, project=ovh_api_credentials.project, username=ovh_api_credentials.user1_username)
    created_policy = client.post(
        f"/cloud/project/{ovh_api_credentials.project}/user/{user_id}/policy", policy=policy_doc_str
    )
    LOG.info("Created policy %r for user %r", created_policy, user_id)

    yield None


@pytest.fixture(name="ovh_s3_module_setup", scope="module")
def fixture_ovh_s3_module_setup(
    request: SubRequest,
    record_mode: str,
    disable_recording: bool,
    ovh_s3_module_setup_bucket: None,
    ovh_s3_module_setup_user1: None,
) -> Generator[None, None, None]:
    enabled = _is_setup_enabled(request, record_mode, disable_recording)
    if not enabled:
        LOG.info("Disabled OVH S3 module setup. Nothing to set up.")

    yield None

    if not enabled:
        LOG.info("Disabled OVH S3 module setup. Nothing to clean up.")


@pytest.fixture(name="ovh_s3_admin_existing_bucket_storage_config", scope="function")
def fixture_ovh_s3_admin_existing_bucket_storage_config(
    request: SubRequest,
    ovh_s3_admin_credentials: OVHS3Credentials,
    ovh_s3_config: OVHS3Config,
    ovh_s3_bucket_which_exists: str,
) -> factory.Config:
    return {
        **_DEFAULT_STORAGE_CONFIG,
        "bucket_name": ovh_s3_bucket_which_exists,
        **dataclasses.asdict(ovh_s3_config),
        **dataclasses.asdict(ovh_s3_admin_credentials),
    }


@pytest.fixture(name="ovh_s3_user1_existing_bucket_storage_config", scope="function")
def fixture_ovh_s3_user1_existing_bucket_storage_config(
    request: SubRequest,
    ovh_s3_user1_credentials: OVHS3Credentials,
    ovh_s3_config: OVHS3Config,
    ovh_s3_bucket_which_exists: str,
) -> factory.Config:
    return {
        **_DEFAULT_STORAGE_CONFIG,
        "bucket_name": ovh_s3_bucket_which_exists,
        **dataclasses.asdict(ovh_s3_config),
        **dataclasses.asdict(ovh_s3_user1_credentials),
    }


# Fixtures need to be explicitly listed here for pytest to register them
__all__ = (
    "fixture_ovh_api_credentials",
    "fixture_ovh_s3_admin_credentials",
    "fixture_ovh_s3_admin_existing_bucket_storage_config",
    "fixture_ovh_s3_bucket_which_exists",
    "fixture_ovh_s3_config",
    "fixture_ovh_s3_module_setup",
    "fixture_ovh_s3_module_setup_bucket",
    "fixture_ovh_s3_module_setup_user1",
    "fixture_ovh_s3_user1_credentials",
    "fixture_ovh_s3_user1_existing_bucket_storage_config",
)
