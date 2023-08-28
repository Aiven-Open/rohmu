"""
rohmu - azure object store interface

Copyright (c) 2016 Ohmu Ltd
Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
See LICENSE for details
"""

from __future__ import annotations

from enum import Enum, unique
from pathlib import Path
from pydantic import Field
from rohmu.common.models import ProxyInfo, StorageDriver, StorageModel
from typing import Any, Dict, Final, Literal, Optional, TypeVar

import platform

StorageModelT = TypeVar("StorageModelT", bound=StorageModel)


def get_total_memory() -> Optional[int]:
    """Return total system memory in mebibytes (or None if parsing meminfo fails)

    Used for transfer block and chunk sizes calculation."""
    if platform.system() != "Linux":
        return None

    with open("/proc/meminfo", "r", encoding="utf-8") as in_file:
        for line in in_file:
            info = line.split()
            if info[0] == "MemTotal:" and info[-1] == "kB":
                memory_mb = int(int(info[1]) / 1024)
                return memory_mb

    return None


def calculate_azure_max_block_size() -> int:
    total_mem_mib = get_total_memory() or 0
    # At least 4 MiB, at most 100 MiB. Max block size used for hosts with ~100+ GB of memory
    return max(min(int(total_mem_mib / 1000), 100), 4) * 1024 * 1024


# Increase block size based on host memory. Azure supports up to 50k blocks and up to 5 TiB individual
# files. Default block size is set to 4 MiB so only ~200 GB files can be uploaded. In order to get close
# to that 5 TiB increase the block size based on host memory; we don't want to use the max 100 for all
# hosts because the uploader will allocate (with default settings) 3 x block size of memory.
AZURE_MAX_BLOCK_SIZE: Final[int] = calculate_azure_max_block_size()


# googleapiclient download performs some 3-4 times better with 50 MB chunk size than 5 MB chunk size;
# but decrypting/decompressing big chunks needs a lot of memory so use smaller chunks on systems with less
# than 2 GB RAM
GOOGLE_DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5 if (get_total_memory() or 0) < 2048 else 1024 * 1024 * 50
GOOGLE_UPLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5


LOCAL_CHUNK_SIZE: Final[int] = 1024 * 1024


def calculate_s3_chunk_size() -> int:
    total_mem_mib = get_total_memory() or 0
    # At least 5 MiB, at most 524 MiB. Max block size used for hosts with ~210+ GB of memory
    return max(min(int(total_mem_mib / 400), 524), 5) * 1024 * 1024


# Set chunk size based on host memory. S3 supports up to 10k chunks and up to 5 TiB individual
# files. Minimum chunk size is 5 MiB, which means max ~50 GB files can be uploaded. In order to get
# to that 5 TiB increase the block size based on host memory; we don't want to use the max for all
# hosts to avoid allocating too large portion of all available memory.
S3_MULTIPART_CHUNK_SIZE: Final[int] = calculate_s3_chunk_size()
S3_READ_BLOCK_SIZE: Final[int] = 1024 * 1024 * 1


SWIFT_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5  # 5 Mi
SWIFT_SEGMENT_SIZE: Final[int] = 1024 * 1024 * 1024 * 3  # 3 Gi


class AzureObjectStorageConfig(StorageModel):
    bucket_name: Optional[str]
    account_name: str
    account_key: Optional[str] = Field(None, repr=False)
    sas_token: Optional[str] = Field(None, repr=False)
    prefix: Optional[str] = None
    azure_cloud: Optional[str] = None
    proxy_info: Optional[ProxyInfo] = None
    storage_type: Literal[StorageDriver.azure] = StorageDriver.azure


class GoogleObjectStorageConfig(StorageModel):
    project_id: str
    bucket_name: Optional[str]
    # Don't use pydantic FilePath, that class checks the file exists at the wrong time
    credential_file: Optional[Path] = None
    credentials: Optional[Dict[str, Any]] = Field(None, repr=False)
    proxy_info: Optional[ProxyInfo] = None
    prefix: Optional[str] = None
    storage_type: Literal[StorageDriver.google] = StorageDriver.google


class LocalObjectStorageConfig(StorageModel):
    # Don't use pydantic DirectoryPath, that class checks the dir exists at the wrong time
    directory: Path
    prefix: Optional[str] = None
    storage_type: Literal[StorageDriver.local] = StorageDriver.local


@unique
class S3AddressingStyle(Enum):
    auto = "auto"
    path = "path"
    virtual = "virtual"


class S3ObjectStorageConfig(StorageModel):
    region: str
    bucket_name: Optional[str]
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = Field(None, repr=False)
    prefix: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    addressing_style: S3AddressingStyle = S3AddressingStyle.path
    is_secure: bool = False
    is_verify_tls: bool = False
    segment_size: int = S3_MULTIPART_CHUNK_SIZE
    encrypted: bool = False
    proxy_info: Optional[ProxyInfo] = None
    connect_timeout: Optional[str] = None
    read_timeout: Optional[str] = None
    aws_session_token: Optional[str] = Field(None, repr=False)
    storage_type: Literal[StorageDriver.s3] = StorageDriver.s3


class SFTPObjectStorageConfig(StorageModel):
    server: str
    port: int
    username: str
    password: Optional[str] = Field(None, repr=False)
    private_key: Optional[str] = Field(None, repr=False)
    prefix: Optional[str] = None
    storage_type: Literal[StorageDriver.sftp] = StorageDriver.sftp


class SwiftObjectStorageConfig(StorageModel):
    user: str
    key: str = Field(repr=False)
    container_name: str
    auth_url: str
    auth_version: str = "2.0"
    tenant_name: Optional[str] = None
    segment_size: int = SWIFT_SEGMENT_SIZE
    region_name: Optional[str] = None
    user_id: Optional[str] = None
    user_domain_id: Optional[str] = None
    user_domain_name: Optional[str] = None
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    project_domain_id: Optional[str] = None
    project_domain_name: Optional[str] = None
    service_type: Optional[str] = None
    endpoint_type: Optional[str] = None
    prefix: Optional[str] = None
    storage_type: Literal[StorageDriver.swift] = StorageDriver.swift
