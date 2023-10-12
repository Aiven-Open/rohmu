|Rohmu logo|

|Build badge| |PyPI badge| |Python versions badge|

Rohmu is a Python library for building backup tools for databases providing functionality for compression, encryption, and transferring data between the database and an object storage. Rohmu supports main public clouds such as GCP, AWS, and Azure for backup storage. Rohmu is used in various backup tools such as `PGHoard`_ for PostgreSQL, `MyHoard`_ for MySQL, and `Astacus`_ for M3, ClickHouse, and other databases.

Features
========

- Supported object storages: Azure, GCP, S3, Swift (OpenStack), local file storage, and SFTP.
- Supported compression algorithms: `Snappy`_, `zstd`_, and `lzma`_.

Requirements
============

Rohmu requires Python >= 3.8. For Python library dependencies, refer to `setup.cfg`_.

Usage example
=============

*Add usage example here*

For real-world usage, see `how Rohmu is used in PGHoard`_.

Development
===========

*TODO*

License
=======

Rohmu is licensed under the Apache license, version 2.0. Full license text is available in the `LICENSE`_ file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

Trademarks
==========

PostgreSQL, MySQL, M3 and ClickHouse are trademarks and property of
their respective owners. All product and service names used in this
website are for identification purposes only and do not imply
endorsement.

Credits
=======

Rohmu was created by and is maintained by `Aiven`_.

Rohmu was originally a part of `PGHoard`_ but was later extracted to its own GitHub project.

The Rohmu logo was created by `@evche-aiven`_.

Contact
=======

Bug reports and patches are very welcome; please post them as GitHub issues and pull requests at `rohmu_repo`_. To report any possible vulnerabilities or other serious issues, please see our `security`_ policy.


Copyright
=========

Copyright (C) 2023 Aiven Ltd and contributors to the Rohmu project.

..
    --------- Links ---------

.. _rohmu_repo: https://github.com/Aiven-Open/rohmu

.. _PGHoard: https://github.com/Aiven-Open/pghoard

.. _MyHoard: https://github.com/Aiven-Open/myhoard

.. _Astacus: https://github.com/Aiven-Open/astacus

.. _Snappy: https://github.com/andrix/python-snappy

.. _zstd: https://github.com/facebook/zstd

.. _lzma: https://docs.python.org/3/library/lzma.html

.. _setup.cfg: https://github.com/Aiven-Open/rohmu/blob/main/setup.cfg

.. _how Rohmu is used in PGHoard: https://github.com/Aiven-Open/pghoard/tree/main/pghoard/basebackup

.. _LICENSE: https://github.com/Aiven-Open/rohmu/blob/main/LICENSE

.. _Aiven: https://aiven.io

.. _@evche-aiven: https://github.com/evche-aiven

.. _security: https://github.com/Aiven-Open/rohmu/blob/main/SECURITY.md

..
    --------- Badges & Images ---------

.. |Rohmu logo| image:: https://raw.githubusercontent.com/Aiven-Open/rohmu/main/logo.png
   :alt: Rohmu logo

.. |Build badge| image:: https://github.com/Aiven-Open/rohmu/actions/workflows/build.yml/badge.svg
   :target: https://github.com/Aiven-Open/rohmu/actions
   :alt: Build status

.. |PyPI badge| image:: https://img.shields.io/pypi/v/rohmu.svg
   :target: https://pypi.org/project/rohmu/
   :alt: PyPI version

.. |Python versions badge| image:: https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue
