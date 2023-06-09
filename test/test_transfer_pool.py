"""Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/"""
from dataclasses import dataclass
from rohmu import transfer_pool
from rohmu.errors import InvalidTransferError
from rohmu.object_storage.local import LocalTransfer
from unittest.mock import patch

import pytest
import time


@dataclass(frozen=True)
class FakeTransfer:
    name: str
    is_thread_safe: bool = False
    # needed for safe transfer tests
    prefix: str = "prefix"
    notifier: str = "notifier"
    stats: str = "stats"
    config_model: str = "config_model"


def test_transfer_pool() -> None:
    """Test that a cached transfer object is returned, if available."""
    storage_config_1 = {"storage_type": "azure"}
    storage_config_2 = {"storage_type": "gcp"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        pool = transfer_pool.TransferPool()
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        with pool.with_transfer(storage_config_1) as transfer:
            rohmu_get_transfer.assert_called_once_with(storage_config_1)
            assert transfer is not None

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        with pool.with_transfer(storage_config_1) as next_transfer:
            assert next_transfer == transfer
            with pool.with_transfer(storage_config_2) as next_transfer_2:
                assert next_transfer_2 is not None
                assert next_transfer_2 != transfer


def test_transfer_pool_context_manager_returns_transfer_on_exception() -> None:
    """Test that a cached transfer object is returned, if available."""
    storage_config_1 = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        pool = transfer_pool.TransferPool()
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        try:
            with pool.with_transfer(storage_config_1) as transfer:
                raise ValueError("Some error happens")
        except ValueError:
            pass

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        with pool.with_transfer(storage_config_1) as next_transfer:
            # the contextmanager should have returned the transfer to the pool, so we expect to get the same one
            assert next_transfer == transfer


def test_transfer_pool_expiration() -> None:
    """Test that a cached transfer object is not returned, if too old."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        pool = transfer_pool.TransferPool()

        with pool.with_transfer(storage_config) as transfer:
            # let's create an item
            pass

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        transfer_item = list(pool._caches.values())[0].transfers_heap[0]  # pylint: disable=protected-access
        transfer_item.create_time = time.monotonic() - (3600 * 2)
        with pool.with_transfer(storage_config) as next_transfer:
            assert next_transfer == transfer
        transfer_item.create_time = time.monotonic() - (3600 * 3)
        with pool.with_transfer(storage_config) as next_transfer:
            assert next_transfer != transfer


def test_transfer_pool_get_oldest() -> None:
    """Test that when getting a transfer object from a pool, the oldest one available is returned."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        pool = transfer_pool.TransferPool()

        with pool.with_transfer(storage_config) as transfer_1:
            rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
            with pool.with_transfer(storage_config):
                # do nothing and put the transfers back in the pool
                pass

        with pool.with_transfer(storage_config) as next_transfer:
            assert next_transfer == transfer_1


def test_transfer_pool_for_thread_safe_transfer_always_returns_the_same_instance() -> None:
    """Test that when using a threadsafe transfer object the pool always returns the same instance"""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1", is_thread_safe=True)
        pool = transfer_pool.TransferPool()

        with pool.with_transfer(storage_config) as transfer_1, pool.with_transfer(storage_config) as transfer_2:
            assert transfer_1 == transfer_2


def test_transfer_pool_for_thread_safe_transfer_does_not_expire() -> None:
    """Test that a cached transfer object is not returned, if too old, even for thread-safe transfers."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1", is_thread_safe=True)
        pool = transfer_pool.TransferPool()

        with pool.with_transfer(storage_config) as transfer:
            # let's create an item
            pass

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2", is_thread_safe=True)
        transfer_item = list(pool._caches.values())[0].transfers_heap[0]  # pylint: disable=protected-access
        transfer_item.create_time = time.monotonic() - (3600 * 2)
        with pool.with_transfer(storage_config) as next_transfer:
            assert next_transfer == transfer
        transfer_item.create_time = time.monotonic() - (3600 * 3)
        with pool.with_transfer(storage_config) as next_transfer:
            # for thread-safe we do not expire the transfers
            assert next_transfer == transfer


# pylint: disable=protected-access
def test_transfer_pool_get_return_api() -> None:
    """Test that a cached transfer object is returned, if available."""
    storage_config_1 = {"storage_type": "azure"}
    storage_config_2 = {"storage_type": "gcp"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        pool = transfer_pool.TransferPool()
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        safe_transfer = pool.get_transfer(storage_config_1)
        transfer = safe_transfer._item.transfer
        rohmu_get_transfer.assert_called_once_with(storage_config_1)
        assert transfer is not None
        safe_transfer.return_to_pool()

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        next_safe_transfer_1 = pool.get_transfer(storage_config_1)
        assert next_safe_transfer_1._item.transfer == transfer
        next_safe_transfer_2 = pool.get_transfer(storage_config_2)
        assert next_safe_transfer_2 is not None
        assert next_safe_transfer_2._item.transfer != transfer


# pylint: disable=protected-access
def test_transfer_pool_expiration_get_return_api() -> None:
    """Test that a cached transfer object is not returned, if too old."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        pool = transfer_pool.TransferPool()

        safe_transfer = pool.get_transfer(storage_config)
        transfer_item = safe_transfer._item
        safe_transfer.return_to_pool()
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        transfer_item.create_time = time.monotonic() - (3600 * 2)
        next_safe_transfer = pool.get_transfer(storage_config)
        assert next_safe_transfer._item.transfer == transfer_item.transfer
        next_safe_transfer.return_to_pool()
        transfer_item.create_time = time.monotonic() - (3600 * 3)
        next_safe_transfer = pool.get_transfer(storage_config)
        assert next_safe_transfer._item.transfer != transfer_item.transfer


# pylint: disable=protected-access
def test_transfer_pool_get_oldest_get_return_api() -> None:
    """Test that when getting a transfer object from a pool, the oldest one available is returned."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1")
        pool = transfer_pool.TransferPool()

        safe_transfer_1 = pool.get_transfer(storage_config)
        transfer_1 = safe_transfer_1._item.transfer
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2")
        safe_transfer_2 = pool.get_transfer(storage_config)
        safe_transfer_1.return_to_pool()
        safe_transfer_2.return_to_pool()

        next_safe_transfer = pool.get_transfer(storage_config)
        assert next_safe_transfer._item.transfer == transfer_1


# pylint: disable=protected-access
def test_transfer_pool_for_thread_safe_transfer_always_returns_the_same_instance_get_return_api() -> None:
    """Test that when using a threadsafe transfer object the pool always returns the same instance"""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1", is_thread_safe=True)
        pool = transfer_pool.TransferPool()

        transfer_1 = pool.get_transfer(storage_config)
        transfer_2 = pool.get_transfer(storage_config)
        assert transfer_1._item.transfer == transfer_2._item.transfer


# pylint: disable=protected-access
def test_transfer_pool_for_thread_safe_transfer_does_not_expire_get_return_api() -> None:
    """Test that a cached transfer object is not returned, if too old, even for thread-safe transfers."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_1", is_thread_safe=True)
        pool = transfer_pool.TransferPool()

        safe_transfer = pool.get_transfer(storage_config)
        transfer_item = safe_transfer._item
        transfer = transfer_item.transfer
        safe_transfer.return_to_pool()

        rohmu_get_transfer.return_value = FakeTransfer("mock_transfer_2", is_thread_safe=True)

        transfer_item.create_time = time.monotonic() - (3600 * 2)
        next_safe_transfer = pool.get_transfer(storage_config)
        assert next_safe_transfer._item.transfer == transfer
        next_safe_transfer.return_to_pool()
        transfer_item.create_time = time.monotonic() - (3600 * 3)
        next_safe_transfer = pool.get_transfer(storage_config)
        # We do not expire transfers for thread-safe transfers
        assert next_safe_transfer._item.transfer == transfer


@pytest.mark.parametrize(
    "attr_name",
    [
        "is_thread_safe",
        "config_model",
        "prefix",
        "notifier",
        "stats",
        "copy_file",
        "format_key_for_backend",
        "format_key_from_backend",
        "delete_key",
        "delete_keys",
        "delete_tree",
        "get_contents_to_file",
        "get_contents_to_fileobj",
        "get_contents_to_string",
        "get_file_size",
        "get_metadata_for_key",
        "list_path",
        "list_iter",
        "list_prefixes",
        "iter_prefixes",
        "iter_key",
        "sanitize_metadata",
        "store_file_from_memory",
        "store_file_from_disk",
        "store_file_object",
        "from_model",
    ],
)
def test_safe_transfer_prevents_access_after_returning(attr_name: str) -> None:
    """Test that a cached transfer object is not returned, if too old, even for thread-safe transfers."""
    storage_config = {"storage_type": "azure"}

    with patch("rohmu.transfer_pool.rohmu_get_transfer") as rohmu_get_transfer:
        rohmu_get_transfer.return_value = LocalTransfer("mock_transfer_1")
        pool = transfer_pool.TransferPool()

        safe_transfer = pool.get_transfer(storage_config)
        getattr(safe_transfer, attr_name)
        safe_transfer.return_to_pool()
        with pytest.raises(InvalidTransferError):
            getattr(safe_transfer, attr_name)
