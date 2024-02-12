##########################
 Python API Documentation
##########################

********
 Common
********

.. autoclass:: rohmu.BaseTransfer

.. autofunction:: rohmu.get_class_for_notifier

.. autofunction:: rohmu.get_class_for_storage_driver

.. autofunction:: rohmu.get_class_for_transfer

.. autofunction:: rohmu.get_notifier

.. autofunction:: rohmu.get_transfer_from_model

.. autofunction:: rohmu.get_transfer_model

.. autofunction:: rohmu.get_transfer

.. autoclass:: rohmu.Notifier

.. autoclass:: rohmu.ProxyInfo

.. autodata:: rohmu.S3AddressingStyle

.. autoclass:: rohmu.StorageDriver

.. autoclass:: rohmu.StorageModel

***************
 Delta Backups
***************

.. automodule:: rohmu.delta
   :members:

.. automodule:: rohmu.delta.common
   :members:

.. automodule:: rohmu.delta.snapshot
   :members:

***********
 Notifiers
***********

.. automodule:: rohmu.notifier
   :members:

.. automodule:: rohmu.notifier.interface
   :members:

HTTP Notifier
=============

.. automodule:: rohmu.notifier.http
   :members:

Logger Notifier
===============

.. automodule:: rohmu.notifier.logger
   :members:

Null Notifier
=============

.. automodule:: rohmu.notifier.null
   :members:

*****************
 Object Storages
*****************

.. include:: api__object_storage.rst

************
 Exceptions
************

.. automodule:: rohmu.errors
   :members:
