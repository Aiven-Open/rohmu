Rohmu
======================
Rohmu is a Python library for building backup tools for databases providing
functionality for compression, encryption and transferring data between the
database and an object storage. Rohmu supports main public clouds such as GCP,
AWS and Azure for backup storage.  Rohmu is used in various backup tools such
as [PGHhoard](https://github.com/aiven/pghoard) for PostgreSQL,
[MyHoard](https://github.com/aiven/myhoard) for MySQL and
[Astacus](https://github.com/aiven/astacus) for M3 and ClickHouse and other
databases.


Features
============

* Supported object storages: Azure, GCP, S3, Swift (OpenStack), local file storage and SFTP. 
* Supported compression algorithms: Snappy, [zstd](https://github.com/facebook/zstd) and [lzma](https://docs.python.org/3/library/lzma.html).

Requirements
============

Rohmu requires Python >= 3.6+. For Python libary dependencies, have a look at [`requirements.txt`](https://github.com/aiven/rohmu/blob/main/requirements.txt).

Usage example
=============

***Add usage example here***

For real-world usage you can have a look at [how Rohmu is used in PGHoard](https://github.com/aiven/pghoard/blob/main/pghoard/basebackup.py).

Development
============

***TODO***

License
============
Rohmu is licensed under the Apache license, version 2.0. Full license text is
available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor
License Agreement) from its contributors.

Contact
============
Bug reports and patches are very welcome, please post them as GitHub issues and
pull requests at https://github.com/aiven/rohmu .  To report any possible
vulnerabilities or other serious issues please see our [security](SECURITY.md)
policy.
