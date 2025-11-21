from .fixtures.ovh_setup import *  # noqa: F403  # This module defines __all__ so it's not a real issue
from rohmu import factory, get_transfer
from rohmu.errors import (
    TransferObjectStoreMissingError,
)
from rohmu.object_storage.s3 import S3Transfer
from typing import Optional
from vcr.cassette import Cassette

import logging
import pytest

LOG = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.usefixtures("ovh_s3_module_setup"),  # More explicit than an autouse=True fixture in another module
    pytest.mark.block_network,  # Disable network calls when replaying tests
    pytest.mark.vcr,  # All tests in this module are VCR tests
]


def test_transfer_init__noop(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect no HTTP requests when initializing the transfer object the "new" way."""
    transfer = get_transfer(ovh_s3_admin_existing_bucket_storage_config, ensure_object_store_available=False)
    assert isinstance(transfer, S3Transfer)
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 0, "Expected no requests at all"
        assert vcr.all_played


def test_transfer_init__compat_existing(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect some HTTP requests to check for existence when initializing in compat mode.
    Creation attempt not covered here, since it is similar to the function called in the constructor."""
    transfer = get_transfer(ovh_s3_admin_existing_bucket_storage_config, ensure_object_store_available=True)
    assert isinstance(transfer, S3Transfer)
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 200


def test_verify_object_storage__existing(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect a single successful HEAD request when a bucket already exists."""
    transfer = get_transfer(ovh_s3_admin_existing_bucket_storage_config, ensure_object_store_available=False)
    transfer.verify_object_storage()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 200


def test_verify_object_storage__new_bucket(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect a single 404 HEAD request when a bucket does not exist (and no attempt to create it)."""
    ovh_new_bucket_storage_config = {
        **ovh_s3_admin_existing_bucket_storage_config,
        "bucket_name": ovh_s3_admin_existing_bucket_storage_config["bucket_name"] + "-new-does-not-exist",
    }
    transfer = get_transfer(ovh_new_bucket_storage_config, ensure_object_store_available=False)
    with pytest.raises(TransferObjectStoreMissingError):
        transfer.verify_object_storage()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 404, "Expecting a 404 from the S3 API"


def test_verify_object_storage__bad_aws_secret_access_key(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect a single 403 HEAD request when a bucket does not exist (and no attempt to create it).

    This is because we make an assumption about the permissions that our credentials would usually have.
    """
    ovh_new_bucket_storage_config = {
        **ovh_s3_admin_existing_bucket_storage_config,
        "aws_secret_access_key": ovh_s3_admin_existing_bucket_storage_config["aws_secret_access_key"] + "-intentionally-bad",
    }
    transfer = get_transfer(ovh_new_bucket_storage_config, ensure_object_store_available=False)

    # We expect no errors here because it's swallowed silently in the implementation
    transfer.verify_object_storage()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 403


def test_verify_object_storage__missing_permission(
    ovh_s3_user1_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    transfer = get_transfer(ovh_s3_user1_existing_bucket_storage_config, ensure_object_store_available=False)

    # We expect no errors here because it's swallowed silently in the implementation
    transfer.verify_object_storage()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 403


def test_create_object_store_if_needed__missing_permission(
    ovh_s3_user1_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    transfer = get_transfer(ovh_s3_user1_existing_bucket_storage_config, ensure_object_store_available=False)

    # We expect no errors here because we make a HEAD call that fails and then a PUT call that fails and is swallowed
    transfer.create_object_store_if_needed()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 403


def test_create_object_store_if_needed__existing(
    ovh_s3_admin_existing_bucket_storage_config: factory.Config,
    vcr: Optional[Cassette],
    record_mode: str,
) -> None:
    """Expect a single successful HEAD request when a bucket already exists (and no attempt to create it)."""
    transfer = get_transfer(ovh_s3_admin_existing_bucket_storage_config, ensure_object_store_available=False)
    transfer.create_object_store_if_needed()
    if record_mode == "none" and vcr is not None:
        assert vcr.play_count == 1, "Expected a single HEAD request"
        assert vcr.all_played

    if vcr is not None:
        assert len(vcr.responses) == 1
        assert vcr.responses[0]["status"]["code"] == 200
