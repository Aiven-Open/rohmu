# Copyright (c) 2016 Ohmu Ltd
# Copyright (c) 2022 Aiven, Helsinki, Finland. https://aiven.io/
# See LICENSE for details
"""Rohmu - azure object store interface"""

from __future__ import annotations

from enum import Enum, unique
from pathlib import Path
from pydantic.v1 import Field, root_validator, validator
from rohmu.common.models import ProxyInfo, StorageDriver, StorageModel
from typing import Any, Final, Literal, TypeVar

import platform
import re

StorageModelT = TypeVar("StorageModelT", bound=StorageModel)


def get_total_memory() -> int | None:
    """Return total system memory in mebibytes (or None if parsing meminfo fails)

    Used for transfer block and chunk sizes calculation."""
    if platform.system() != "Linux":
        return None

    with open("/proc/meminfo", encoding="utf-8") as in_file:
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


AZURE_ENDPOINT_SUFFIXES = {
    None: "core.windows.net",
    "germany": "core.cloudapi.de",  # Azure Germany is a completely separate cloud from the regular Azure Public cloud
    "china": "core.chinacloudapi.cn",
    "public": "core.windows.net",
}
# Increase block size based on host memory. Azure supports up to 50k blocks and up to 5 TiB individual
# files. Default block size is set to 4 MiB so only ~200 GB files can be uploaded. In order to get close
# to that 5 TiB increase the block size based on host memory; we don't want to use the max 100 for all
# hosts because the uploader will allocate (with default settings) 3 x block size of memory.
AZURE_MAX_BLOCK_SIZE: Final[int] = calculate_azure_max_block_size()
AZURE_MAX_NUM_PARTS_PER_UPLOAD: Final[int] = 10000

# googleapiclient download performs some 3-4 times better with 50 MB chunk size than 5 MB chunk size;
# but decrypting/decompressing big chunks needs a lot of memory so use smaller chunks on systems with less
# than 2 GB RAM
GOOGLE_DOWNLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5 if (get_total_memory() or 0) < 2048 else 1024 * 1024 * 50
GOOGLE_UPLOAD_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5
GOOGLE_MAX_NUM_PARTS_PER_UPLOAD: Final[int] = 10000
# GCS region/location names as used in regional endpoint hostnames, e.g. "us-west4", "europe-west1", "nam4".
GOOGLE_DIRECT_LOCATION_PATTERN: Final[str] = r"^[a-z0-9]+(-[a-z0-9]+)*$"

LOCAL_CHUNK_SIZE: Final[int] = 1024 * 1024


S3_MAX_NUM_PARTS_PER_UPLOAD: Final[int] = 10000
S3_MAX_COPY_SIZE_BYTES: Final[int] = 5 * 1024**3
S3_MIN_PART_SIZE_MB: Final[int] = 5
S3_MAX_PART_SIZE_MB: Final[int] = 524
S3_MIN_PART_SIZE_BYTES: Final[int] = S3_MIN_PART_SIZE_MB * 1024 * 1024
S3_MAX_PART_SIZE_BYTES: Final[int] = S3_MAX_PART_SIZE_MB * 1024 * 1024
# Above the AWS CLI default of 10; adaptive retries back off if a shared bucket gets throttled
S3_DEFAULT_MAX_CONCURRENT_REQUESTS: Final[int] = 20
# Deletes stay sequential unless the caller opts in
S3_DEFAULT_MAX_CONCURRENT_DELETE_REQUESTS: Final[int] = 1


def calculate_s3_chunk_size() -> int:
    total_mem_mib = get_total_memory() or 0
    # At least 5 MiB, at most 524 MiB. Max block size used for hosts with ~210+ GB of memory
    return max(min(int(total_mem_mib / 400), S3_MAX_PART_SIZE_MB), S3_MIN_PART_SIZE_MB) * 1024 * 1024


# Set chunk size based on host memory. S3 supports up to 10k chunks and up to 5 TiB individual
# files. Minimum chunk size is 5 MiB, which means max ~50 GB files can be uploaded. In order to get
# to that 5 TiB increase the block size based on host memory; we don't want to use the max for all
# hosts to avoid allocating too large portion of all available memory.
S3_DEFAULT_MULTIPART_CHUNK_SIZE: Final[int] = calculate_s3_chunk_size()
S3_READ_BLOCK_SIZE: Final[int] = 1024 * 1024 * 1


SWIFT_CHUNK_SIZE: Final[int] = 1024 * 1024 * 5  # 5 Mi
SWIFT_SEGMENT_SIZE: Final[int] = 1024 * 1024 * 1024 * 3  # 3 Gi
SWIFT_MAX_NUM_PARTS_PER_UPLOAD = 10000


class AzureObjectStorageConfig(StorageModel):
    bucket_name: str | None
    account_name: str
    account_key: str | None = Field(None, repr=False)
    sas_token: str | None = Field(None, repr=False)
    prefix: str | None = None
    is_secure: bool = True
    host: str | None = None
    port: int | None = None
    azure_cloud: str | None = None
    proxy_info: ProxyInfo | None = None
    storage_type: Literal[StorageDriver.azure] = StorageDriver.azure

    @root_validator
    @classmethod
    def host_and_port_must_be_set_together(cls, values: dict[str, Any]) -> dict[str, Any]:
        if (values["host"] is None) != (values["port"] is None):
            raise ValueError("host and port must be set together")
        return values

    @validator("azure_cloud")
    @classmethod
    def valid_azure_cloud_endpoint(cls, v: str) -> str:
        if v not in AZURE_ENDPOINT_SUFFIXES:
            raise ValueError(f"azure_cloud must be one of {AZURE_ENDPOINT_SUFFIXES.keys()}")
        return v


class GoogleObjectStorageConfig(StorageModel):
    project_id: str | None
    bucket_name: str | None
    # Don't use pydantic FilePath, that class checks the file exists at the wrong time
    credential_file: Path | None = None
    credentials: dict[str, Any] | None = Field(None, repr=False)
    proxy_info: ProxyInfo | None = None
    direct_location: str | None = None
    prefix: str | None = None
    storage_type: Literal[StorageDriver.google] = StorageDriver.google

    @root_validator
    @classmethod
    def project_id_or_bucket_name_must_be_given(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values["project_id"] is None and values["bucket_name"] is None:
            raise ValueError("at least one of project_id, bucket_name must be set")
        return values

    @validator("direct_location")
    @classmethod
    def valid_direct_location(cls, v: str | None) -> str | None:
        # None means "use the global endpoint". Anything else is interpolated into a hostname,
        # so reject malformed values here; "" would otherwise yield
        # https://storage..rep.googleapis.com/storage/v1/
        if v is None:
            return v
        if not re.fullmatch(GOOGLE_DIRECT_LOCATION_PATTERN, v):
            raise ValueError(f"invalid direct_location: {v!r}, must match {GOOGLE_DIRECT_LOCATION_PATTERN}")
        return v


class LocalObjectStorageConfig(StorageModel):
    # Don't use pydantic DirectoryPath, that class checks the dir exists at the wrong time
    directory: Path
    prefix: str | None = None
    storage_type: Literal[StorageDriver.local] = StorageDriver.local


@unique
class S3AddressingStyle(Enum):
    auto = "auto"
    path = "path"
    virtual = "virtual"


class S3ObjectStorageConfig(StorageModel):
    region: str
    bucket_name: str | None
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = Field(None, repr=False)
    prefix: str | None = None
    host: str | None = None
    port: str | None = None
    addressing_style: S3AddressingStyle = S3AddressingStyle.path
    is_secure: bool = False
    is_verify_tls: bool = False
    cert_path: Path | None = None
    segment_size: int = S3_DEFAULT_MULTIPART_CHUNK_SIZE
    encrypted: bool = False
    proxy_info: ProxyInfo | None = None
    connect_timeout: str | None = None
    read_timeout: str | None = None
    aws_session_token: str | None = Field(None, repr=False)
    use_dualstack_endpoint: bool | None = True
    storage_type: Literal[StorageDriver.s3] = StorageDriver.s3
    min_multipart_chunk_size: int | None = None
    user_agent_extra: str | None = None
    # Some S3-compatible providers return object metadata keys in
    # Title-Case. But AWS lowercases user defined metadata keys
    # ref: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html)
    # Enable this to normalize (lower case) keys on read so callers can look up lowercased keys.
    lowercase_metadata_keys: bool = False
    # Upper bound on concurrent requests per transfer (listing HEADs, key and part copies); also the connection pool size
    max_concurrent_requests: int = Field(default=S3_DEFAULT_MAX_CONCURRENT_REQUESTS, ge=1)
    # Upper bound on concurrent DeleteObjects requests in delete_keys and delete_tree
    max_concurrent_delete_requests: int = Field(default=S3_DEFAULT_MAX_CONCURRENT_DELETE_REQUESTS, ge=1)

    @root_validator(skip_on_failure=True)
    @classmethod
    def validate_is_verify_tls_and_cert_path(cls, values: dict[str, Any]) -> dict[str, Any]:
        if not values["is_verify_tls"] and values["cert_path"] is not None:
            raise ValueError("cert_path is set but is_verify_tls is False")
        return values


class SFTPObjectStorageConfig(StorageModel):
    server: str
    port: int
    username: str
    password: str | None = Field(None, repr=False)
    private_key: str | None = Field(None, repr=False)
    prefix: str | None = None
    storage_type: Literal[StorageDriver.sftp] = StorageDriver.sftp


class SwiftObjectStorageConfig(StorageModel):
    user: str
    key: str = Field(repr=False)
    container_name: str
    auth_url: str
    auth_version: str = "2.0"
    tenant_name: str | None = None
    segment_size: int = SWIFT_SEGMENT_SIZE
    region_name: str | None = None
    user_id: str | None = None
    user_domain_id: str | None = None
    user_domain_name: str | None = None
    tenant_id: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    project_domain_id: str | None = None
    project_domain_name: str | None = None
    service_type: str | None = None
    endpoint_type: str | None = None
    prefix: str | None = None
    storage_type: Literal[StorageDriver.swift] = StorageDriver.swift
