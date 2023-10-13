#######
 Rohmu
#######

..
   start-include-intro

|Rohmu logo|

|Build badge| |PyPI badge| |Python versions badge|

Rohmu is a Python library for building backup tools for databases providing functionality for
compression, encryption, and transferring data between the database and an object storage. Rohmu
supports main public clouds such as GCP, AWS, and Azure for backup storage. Rohmu is used in various
backup tools such as PGHoard_ for PostgreSQL, MyHoard_ for MySQL, and Astacus_ for M3, ClickHouse,
and other databases.

..
   end-include-intro

..
   start-include-features

**********
 Features
**********

-  Supported object storages: Azure, GCP, S3, Swift (OpenStack), local file storage, and SFTP.
-  Supported compression algorithms: Snappy_, zstd_, and lzma_.

..
   end-include-features

..
   start-include-requirements

**************
 Requirements
**************

Rohmu requires Python >= 3.8. For Python library dependencies, refer to setup.cfg_.

..
   end-include-requirements

..
   start-include-usage

***************
 Usage example
***************

*Add usage example here*

For real-world usage, see `how Rohmu is used in PGHoard`_.

..
   end-include-usage

*************
 Development
*************

*TODO*

..
   start-include-building-the-package

**********************
 Building the package
**********************

To build an installation package for your distribution, go to the root directory of a Rohmu Git
checkout and run:

Fedora:

.. code::

   sudo make fedora-dev-setup
   make rpm

This will produce a ``.rpm`` package usually into ``rpm/RPMS/noarch/``.

..
   end-include-building-the-package

..
   start-include-license

*********
 License
*********

Rohmu is licensed under the Apache license, version 2.0. Full license text is available in the
LICENSE_ file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from
its contributors.

..
   end-include-license

..
   start-include-trademarks-and-credits

************
 Trademarks
************

PostgreSQL, MySQL, M3 and ClickHouse are trademarks and property of their respective owners. All
product and service names used in this website are for identification purposes only and do not imply
endorsement.

*********
 Credits
*********

Rohmu was created by and is maintained by Aiven_.

Rohmu was originally a part of PGHoard_ but was later extracted to its own GitHub project.

The Rohmu logo was created by `@evche-aiven`_.

..
   end-include-trademarks-and-credits

..
   start-include-contact

*********
 Contact
*********

Bug reports and patches are very welcome; please post them as GitHub issues and pull requests at
rohmu_repo_. To report any possible vulnerabilities or other serious issues, please see our
security_ policy.

..
   end-include-contact

..
   start-include-copyright

***********
 Copyright
***********

Copyright (C) 2023 Aiven Ltd and contributors to the Rohmu project.

..
   end-include-copyright

..
   start-include-links

..
   --------- Links ---------

.. _@evche-aiven: https://github.com/evche-aiven

.. _aiven: https://aiven.io

.. _astacus: https://github.com/Aiven-Open/astacus

.. _how rohmu is used in pghoard: https://github.com/Aiven-Open/pghoard/tree/main/pghoard/basebackup

.. _license: https://github.com/Aiven-Open/rohmu/blob/main/LICENSE

.. _lzma: https://docs.python.org/3/library/lzma.html

.. _myhoard: https://github.com/Aiven-Open/myhoard

.. _pghoard: https://github.com/Aiven-Open/pghoard

.. _rohmu_repo: https://github.com/Aiven-Open/rohmu

.. _security: https://github.com/Aiven-Open/rohmu/blob/main/SECURITY.md

.. _setup.cfg: https://github.com/Aiven-Open/rohmu/blob/main/setup.cfg

.. _snappy: https://github.com/andrix/python-snappy

.. _zstd: https://github.com/facebook/zstd

..
   --------- Badges & Images ---------

.. |Rohmu logo| image:: https://raw.githubusercontent.com/Aiven-Open/rohmu/main/logo.png

.. |Build badge| image:: https://github.com/Aiven-Open/rohmu/actions/workflows/build.yml/badge.svg
   :alt: Build status
   :target: https://github.com/Aiven-Open/rohmu/actions

.. |PyPI badge| image:: https://img.shields.io/pypi/v/rohmu.svg
   :alt: PyPI version
   :target: https://pypi.org/project/rohmu/

.. |Python versions badge| image:: https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue
