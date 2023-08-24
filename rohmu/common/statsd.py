"""
Copyright (c) 2020 Aiven Ltd
See LICENSE for details

StatsD client

Supports telegraf's statsd protocol extension for 'key=value' tags:

  https://github.com/influxdata/telegraf/tree/master/plugins/inputs/statsd

This is combination of:
- pghoard base (pghoard.metrics.statsd)
- myhoard timing_manager method
- pydantic configuration + explicit typing

"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from rohmu.common.strenum import StrEnum
from typing import AsyncIterator, Dict, Iterator, Optional, Union

import pydantic
import socket
import time


class MessageFormat(StrEnum):
    datadog = "datadog"
    telegraf = "telegraf"


Tags = Dict[str, Union[int, str, None]]


class StatsdConfig(pydantic.BaseModel):
    host: str = "127.0.0.1"
    port: int = 8125
    message_format: MessageFormat = MessageFormat.telegraf
    tags: Tags = {}
    operation_map: Dict[str, str] = {}

    class Config:
        use_enum_values = True
        extra = "forbid"
        validate_all = True


class StatsClient:
    _enabled = True

    def __init__(self, config: Optional[StatsdConfig]):
        self._operation_map = {}
        if not config:
            self._enabled = False
            return
        if not isinstance(config, StatsdConfig):
            config = StatsdConfig.parse_obj(config)
        self._dest_addr = (config.host, config.port)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tags = config.tags
        self._message_format = config.message_format
        self._operation_map = config.operation_map

    @asynccontextmanager
    async def async_timing_manager(self, metric: str, tags: Optional[Tags] = None) -> AsyncIterator[None]:
        with self.timing_manager(metric, tags=tags):
            yield

    @contextmanager
    def timing_manager(self, metric: str, tags: Optional[Tags] = None) -> Iterator[None]:
        start_time = time.monotonic()
        tags = (tags or {}).copy()
        try:
            yield
        except:  # noqa pylint: disable=broad-except,bare-except
            tags["success"] = "0"
            self.timing(metric, time.monotonic() - start_time, tags=tags)
            raise
        tags["success"] = "1"
        self.timing(metric, time.monotonic() - start_time, tags=tags)

    def gauge(self, metric: str, value: Union[int, float], *, tags: Optional[Tags] = None) -> None:
        self._send(metric, b"g", value, tags)

    def increase(self, metric: str, *, inc_value: int = 1, tags: Optional[Tags] = None) -> None:
        self._send(metric, b"c", inc_value, tags)

    def timing(self, metric: str, value: Union[int, float], *, tags: Optional[Tags] = None) -> None:
        self._send(metric, b"ms", value, tags)

    def unexpected_exception(self, ex: BaseException, where: str, *, tags: Optional[Tags] = None) -> None:
        all_tags: Tags = {
            "exception": ex.__class__.__name__,
            "where": where,
        }
        all_tags.update(tags or {})
        self.increase("exception", tags=all_tags)

    def operation(self, operation: str, *, count: int = 1, size: Union[int, None] = None) -> None:
        tags: Tags = {"operation": self._operation_map.get(str(operation), str(operation))}
        self.increase("rohmu_operation_count", tags=tags, inc_value=count)
        if size is not None:
            self.increase("rohmu_operation_size", tags=tags, inc_value=size)

    def _send(self, metric: str, metric_type: bytes, value: Union[int, float], tags: Optional[Tags]) -> None:
        if not self._enabled:
            # stats sending is disabled
            return

        # telegraf format: "user.logins,service=payroll,region=us-west:1|c"
        # datadog format: metric.name:value|type|@sample_rate|#tag1:value,tag2
        #                 http://docs.datadoghq.com/guides/dogstatsd/#datagram-format

        parts = [metric.encode("utf-8"), b":", str(value).encode("utf-8"), b"|", metric_type]
        send_tags = self._tags.copy()
        send_tags.update(tags or {})
        if self._message_format == MessageFormat.datadog:
            for index, (tag, val) in enumerate(send_tags.items()):
                if index == 0:
                    separator = "|#"
                else:
                    separator = ","
                if val is None:
                    pattern = "{}{}"
                else:
                    pattern = "{}{}:{}"
                parts.append(pattern.format(separator, tag, val).encode("utf-8"))
        elif self._message_format == MessageFormat.telegraf:
            for tag, val in send_tags.items():
                parts.insert(1, f",{tag}={val}".encode("utf-8"))
        else:
            raise NotImplementedError("Unsupported message format")

        self._socket.sendto(b"".join(parts), self._dest_addr)
