"""
proxy_logger.py by Talia

Requirement E - Logging
This module implements structured logging for the proxy server.

What this module logs:
1. Incoming requests
2. Outgoing responses
3. Cache hits / misses
4. HTTPS tunnel events
5. Errors and exceptions

Each log entry is one JSON object on a single line
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def utc_now_iso() -> str:
    #Return the current UTC time in ISO 8601 format for consistency accross machines.

    return datetime.now(timezone.utc).isoformat()


@dataclass
class LogEntry:
    """
    Represents one structured log entry.

    Every field is optional except:
    - timestamp
    - event

    Common event values:
    - request_received
    - response_sent
    - cache_hit
    - cache_miss
    - cache_store
    - https_tunnel_started
    - https_tunnel_closed
    - error
    """
    timestamp: str
    event: str
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    cache_status: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class ProxyLogger:
    """
    Thread-safe logger for the proxy server.

    Thread safety matters because the proxy is expected to handle multiple
    client connections concurrently. If two threads write to the same log file
    at the same time, the output can become corrupted or interleaved.

    To prevent that, we use a lock around file writes.
    """

    def __init__(self, log_file: str = "proxy.log.jsonl") -> None:
        """
        Create a logger instance.

        Parameters:
            log_file: path of the log file to append entries to
        """
        self.log_path = Path(log_file)
        self._lock = threading.Lock()

        # Ensure parent directory exists before writing.
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, entry: LogEntry) -> None:
        """
        Internal helper to append one log entry to the log file.

        This method:
        1. Converts the dataclass to a dictionary
        2. Removes fields whose values are None
        3. Serializes the result as one JSON line
        4. Appends the line to the log file safely
        """
        data = {k: v for k, v in asdict(entry).items() if v is not None}

        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def log_request(
        self,
        client_ip: str,
        client_port: int,
        target_host: str,
        target_port: int,
        method: str,
        url: str,
    ) -> None:

        #Log that the proxy received a request from a client and is about to process/forward it.
        
        self._write(
            LogEntry(
                timestamp=utc_now_iso(),
                event="request_received",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                method=method,
                url=url,
            )
        )

    def log_response(
        self,
        client_ip: str,
        client_port: int,
        target_host: str,
        target_port: int,
        method: str,
        url: str,
        status_code: int,
        cache_status: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """
        Log that a response was sent back to the client.

        cache_status values can be:
        - HIT  -> served from cache
        - MISS -> fetched from origin server
        - BYPASS -> intentionally not cached
        """
        self._write(
            LogEntry(
                timestamp=utc_now_iso(),
                event="response_sent",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                method=method,
                url=url,
                status_code=status_code,
                cache_status=cache_status,
                message=message,
            )
        )

    def log_cache_event(
        self,
        event: str,
        url: str,
        target_host: str,
        target_port: int,
        message: Optional[str] = None,
    ) -> None:
        """
        Log a cache-related event.

        Expected event values:
        - cache_hit
        - cache_miss
        - cache_store
        - cache_expired
        """
        self._write(
            LogEntry(
                timestamp=utc_now_iso(),
                event=event,
                target_host=target_host,
                target_port=target_port,
                url=url,
                message=message,
            )
        )

    def log_https_event(
        self,
        event: str,
        client_ip: str,
        client_port: int,
        target_host: str,
        target_port: int,
        message: Optional[str] = None,
    ) -> None:
        """
        Log HTTPS tunnel events.

        Expected event values:
        - https_tunnel_started
        - https_tunnel_closed
        """
        self._write(
            LogEntry(
                timestamp=utc_now_iso(),
                event=event,
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                message=message,
            )
        )

    def log_error(
        self,
        message: str,
        error: str,
        client_ip: Optional[str] = None,
        client_port: Optional[int] = None,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        method: Optional[str] = None,
        url: Optional[str] = None,
    ) -> None:
        """
        Log an error or exception.

        Use this whenever:
        - connection to target server fails
        - request parsing fails
        - tunnel creation fails
        - cache parsing fails
        - any unexpected exception occurs
        """
        self._write(
            LogEntry(
                timestamp=utc_now_iso(),
                event="error",
                client_ip=client_ip,
                client_port=client_port,
                target_host=target_host,
                target_port=target_port,
                method=method,
                url=url,
                message=message,
                error=error,
            )
        )
