.. image:: logo.png

Rohmu is a Python library for building backup tools for databases
providing functionality for compression, encryption and transferring
data between the database and an object storage. Rohmu supports main
public clouds such as GCP, AWS and Azure for backup storage. Rohmu is
used in various backup tools such as
`PGHoard <https://github.com/aiven/pghoard>`__ for PostgreSQL,
`MyHoard <https://github.com/aiven/myhoard>`__ for MySQL and
`Astacus <https://github.com/aiven/astacus>`__ for M3 and ClickHouse and
other databases.

Features
========

-  Supported object storages: Azure, GCP, S3, Swift (OpenStack), local
   file storage and SFTP.
-  Supported compression algorithms: Snappy,
   `zstd <https://github.com/facebook/zstd>`__ and
   `lzma <https://docs.python.org/3/library/lzma.html>`__.

Requirements
============

Rohmu requires Python >= 3.8. For Python library dependencies, have a
look at
`requirements.txt <https://github.com/aiven/rohmu/blob/main/requirements.txt>`__.

Usage example
=============

*Add usage example here*

For real-world usage you can have a look at `how Rohmu is used in
PGHoard <https://github.com/aiven/pghoard/blob/main/pghoard/basebackup.py>`__.

Development
===========

*TODO*

License
=======

Rohmu is licensed under the Apache license, version 2.0. Full license
text is available in the `LICENSE <LICENSE>`__ file.

Please note that the project explicitly does not require a CLA
(Contributor License Agreement) from its contributors.

Trademarks
==========

PostgreSQL, MySQL, M3 and ClickHouse are trademarks and property of
their respective owners. All product and service names used in this
website are for identification purposes only and do not imply
endorsement.

Credits
=======

Rohmu was created by and is maintained by `Aiven
<https://aiven.io>`__.

Rohmu was originally a part of `PGHoard
<https://github.com/aiven/pghoard>`__ but was later extracted to its
own GitHub project.

The Rohmu logo was created by `@evche-aiven
<https://github.com/evche-aiven>`__.

Contact
=======

Bug reports and patches are very welcome, please post them as GitHub
issues and pull requests at https://github.com/aiven/rohmu . To report
any possible vulnerabilities or other serious issues please see our
`security <SECURITY.md>`__ policy.

Copyright
=========

Copyright (C) 2022 Aiven Ltd and contributors to the Rohmu project.
