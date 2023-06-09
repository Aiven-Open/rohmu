"""
rohmu - transfer_pool

Copyright (c) 2023 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""

from __future__ import annotations

from . import get_transfer as rohmu_get_transfer
from .errors import InvalidTransferError
from .object_storage.base import BaseTransfer, StorageModel
from contextlib import contextmanager
from typing import Any, Callable, Generator, Optional

import heapq
import json
import logging
import threading
import time

LOG = logging.getLogger(__name__)

TRANSFER_MAX_AGE = 60 * 60 * 3
TRANSFER_CACHE_MAX_AGE = TRANSFER_MAX_AGE * 2


class TransferCacheItem:
    create_time: float
    cache_key: str
    transfer: BaseTransfer[StorageModel]
    max_age: float

    def __init__(self, pool_key: str, transfer: BaseTransfer[StorageModel], max_age: float = TRANSFER_MAX_AGE) -> None:
        self.create_time = time.monotonic()
        self.cache_key = pool_key
        self.transfer = transfer
        self.max_age = max_age

    def age(self) -> float:
        return time.monotonic() - self.create_time

    def is_expired(self) -> bool:
        return self.age() > self.max_age

    def __gt__(self, other: TransferCacheItem) -> bool:
        """Ordering by creation time, needed for storing these in a heap."""
        return self.create_time > other.create_time


class _TransferCache:
    transfers_heap: list[TransferCacheItem]
    last_used: float
    max_age: float

    def __init__(self, max_age: float = TRANSFER_CACHE_MAX_AGE) -> None:
        self.transfers_heap = []
        self.last_used = time.monotonic()
        self.max_age = max_age

    def prune_expired(self) -> None:
        while self.transfers_heap and self.transfers_heap[0].is_expired():
            heapq.heappop(self.transfers_heap)

    def get(self) -> Optional[TransferCacheItem]:
        self.last_used = time.monotonic()
        self.prune_expired()
        if self.transfers_heap:
            try:
                return heapq.heappop(self.transfers_heap)
            except IndexError:
                pass
        return None

    def put(self, transfer: TransferCacheItem) -> None:
        self.last_used = time.monotonic()
        if not transfer.is_expired():
            heapq.heappush(self.transfers_heap, transfer)

    def age(self) -> float:
        return time.monotonic() - self.last_used

    def is_expired(self) -> bool:
        return self.age() > self.max_age


class _TransferCacheForThreadSafeTransfer(_TransferCache):
    """This _TransferCache subclass is a simple implementation that works when the transfer is thread-safe.

    In that case we can have a single instance and always return that one.

    No expiration logic is applied to the transfer instance.
    """

    def __init__(self, transfer_item: TransferCacheItem, max_age: float = TRANSFER_CACHE_MAX_AGE) -> None:
        super().__init__(max_age)
        self.transfers_heap.append(transfer_item)

    def get(self) -> Optional[TransferCacheItem]:
        self.last_used = time.monotonic()
        # there will always be only one transfer instance at most in this cache type
        return self.transfers_heap[0]

    def put(self, transfer: TransferCacheItem) -> None:
        self.last_used = time.monotonic()


_BASE_TRANSFER_INSTANCE_ATTRS = {"config_model", "log", "notifier", "prefix", "stats"}
_BASE_TRANSFER_ATTRS = {attr for attr in vars(BaseTransfer) if not attr.startswith("__")} | _BASE_TRANSFER_INSTANCE_ATTRS

# pylint: disable=abstract-method,super-init-not-called
class SafeTransfer(BaseTransfer[StorageModel]):
    """Helper class that helps the users in finding bugs in their code handling transfers.

    This class prevents any call to a transfer instance that was returned to the pool.
    It also logs a warning if the instance is garbage collected (returning it to the pool).

    """

    def __init__(self, item: TransferCacheItem, pool_reclaim: Callable[[TransferCacheItem], None]) -> None:
        self._item = item
        self._pool_reclaim = pool_reclaim
        self._done = False

    def __del__(self) -> None:
        if not self._done:
            LOG.warning("Transfer not marked as done was garbage collected. Returning it to the pool now.")

    def __getattribute__(self, attr: str) -> Any:
        if attr in _BASE_TRANSFER_ATTRS:
            if self._done:
                raise InvalidTransferError("Trying to access transfer instance already returned to the pool")
            else:
                return getattr(self._item.transfer, attr)
        return super().__getattribute__(attr)

    @classmethod
    def from_model(cls, model: StorageModel) -> BaseTransfer[StorageModel]:
        raise InvalidTransferError("You should not call class methods on SafeTransfer instances")

    def return_to_pool(self) -> None:
        """Return the underlying transfer instance to the pool.

        After this call all uses of this transfer instance will raise InvalidTransferError.

        This method can be called multiple times.
        """
        if self._done:
            return
        self._pool_reclaim(self._item)
        self._done = True
        del self._item


class TransferPool:
    def __init__(self, *, max_pool_age: float = TRANSFER_CACHE_MAX_AGE, max_transfer_age: float = TRANSFER_MAX_AGE):
        self._max_pool_age = max_pool_age
        self._max_transfer_age = max_transfer_age
        self._caches: dict[str, _TransferCache] = {}
        self._is_thread_safe: dict[str, bool] = {}
        self._mutex = threading.Lock()

    @contextmanager
    def with_transfer(self, storage_config: dict[str, Any]) -> Generator[BaseTransfer[StorageModel], None, None]:
        """Yield a transfer object according to the provided storage_config.

        The transfer object may be created or cached. While the context manager is running the transfer object
        won't be available to other threads.

        Users of this contextmanager should NOT use the transfer object outside the `with` block
        """
        transfer = self._get(storage_config)
        try:
            yield transfer.transfer
        finally:
            self._put(transfer)

    def get_transfer(self, storage_config: dict[str, Any]) -> SafeTransfer:
        """Returns a transfer object.

        The object returned is a proxy that will forward all accesses to the underlying transfer instance.
        You MUST call `return_to_pool()` method once you are done with this transfer, and any access to the proxy
        afterwards will raise an `InvalidTransferError`.

        """
        return SafeTransfer(item=self._get(storage_config), pool_reclaim=self._put)

    def _prune_expired_caches(self) -> None:
        self._caches = {key: pool for key, pool in self._caches.items() if not pool.is_expired()}

    def _get(self, storage_config: dict[str, Any]) -> TransferCacheItem:
        cache_key = _cache_key(storage_config)
        with self._mutex:
            if (cache := self._caches.get(cache_key)) and (cached_transfer := cache.get()):
                return cached_transfer
            transfer = rohmu_get_transfer(storage_config)
            item = TransferCacheItem(cache_key, transfer, max_age=self._max_transfer_age)
            if transfer.is_thread_safe:
                self._caches[cache_key] = _TransferCacheForThreadSafeTransfer(item, max_age=self._max_pool_age)
            else:
                self._caches[cache_key] = _TransferCache(max_age=self._max_pool_age)

            return item

    def _put(self, transfer: TransferCacheItem) -> None:
        with self._mutex:
            transfer_pool = self._caches.get(transfer.cache_key)
            if transfer_pool:
                transfer_pool.put(transfer)
            self._prune_expired_caches()


def _cache_key(storage_config: dict[str, Any]) -> str:
    return json.dumps(storage_config, sort_keys=True)


DEFAULT_TRANSFER_POOL = TransferPool()
with_transfer = DEFAULT_TRANSFER_POOL.with_transfer
get_transfer = DEFAULT_TRANSFER_POOL.get_transfer
