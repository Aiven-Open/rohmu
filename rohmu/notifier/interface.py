"""Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/"""
from abc import ABC, abstractmethod
from typing import Optional


class Notifier(ABC):
    """This interface allows external code to be notified about object changes."""

    @abstractmethod
    def object_created(self, key: str, size: Optional[int]) -> None:
        """Called when an object is created."""

    @abstractmethod
    def object_deleted(self, key: str) -> None:
        """Called when an object is deleted.

        Note: This may be called with each individual object as a side-effect
        of `delete_tree`, for drivers that do not support the higher level
        operation.
        """

    @abstractmethod
    def tree_deleted(self, key: str) -> None:
        """May be called when a tree is deleted.

        Note: Not every driver supports this operation, for those objects will
        be listed and deleted individually, in that case `object_deleted` is
        called instead.
        """

    def object_copied(self, key: str, size: Optional[int]) -> None:
        """Called when an object is copied."""
        self.object_created(key=key, size=size)

    def close(self) -> None:
        """Method used to clean resources of the notifier, if any."""
