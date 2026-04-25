"""
proxy_cache.py by Talia

Requirement F - Content Caching
This module implements a thread-safe in-memory HTTP response cache.

Main design choices:
- Only cache HTTP GET responses
- Use an in-memory dictionary for simplicity
- Support expiration using:
  1. Cache-Control: max-age=...
  2. Expires header
  3. Fallback custom TTL

This module does not try to be a full RFC-compliant web cache.
"""

from __future__ import annotations

import email.utils
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class CacheEntry:
    """
    Represents one cached response.

    Fields:
    - response_bytes: the full raw HTTP response returned by the origin server
    - expiry_time: UNIX timestamp after which the entry is considered expired
    - status_code: stored only for easier debugging/reporting
    - stored_at: UNIX timestamp indicating when the entry was inserted
    """
    response_bytes: bytes
    expiry_time: float
    status_code: int
    stored_at: float


class ProxyCache:
    """
    Thread-safe in-memory cache for proxy responses.

    Thread safety matters because:
    - several client threads may read/write the cache simultaneously
    - race conditions can corrupt shared state if not protected
    """

    def __init__(self, default_ttl: int = 60, max_entries: int = 256) -> None:
        """
        Parameters:
            default_ttl: fallback cache lifetime in seconds if headers do not
                         specify cache duration
            max_entries: soft size limit for the cache
        """
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.Lock()

    @staticmethod
    def build_cache_key(method: str, host: str, port: int, path: str) -> str:
        """
        Create a unique key for a resource.

        include:
        - method distinguishes GET from other methods
        - host distinguishes different domains
        - port distinguishes different services
        - path distinguishes resources on the same host
        """
        return f"{method.upper()}:{host}:{port}:{path}"

    @staticmethod
    def _parse_headers_from_response(response_bytes: bytes) -> Dict[str, str]:
        #Extract HTTP response headers from raw response bytes.
        try:
            header_blob = response_bytes.split(b"\r\n\r\n", 1)[0].decode(
                "iso-8859-1", errors="replace"
            )
        except Exception:
            return {}

        lines = header_blob.split("\r\n")
        headers: Dict[str, str] = {}

        # Skip the first line because it is the status line, not a header.
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        return headers

    @staticmethod
    def _extract_status_code(response_bytes: bytes) -> int:
        """
        Extract the status code from the HTTP status line.

        Example status line:
            HTTP/1.1 200 OK

        Returns:
            integer status code if parsing succeeds, otherwise 0
        """
        try:
            status_line = response_bytes.split(b"\r\n", 1)[0].decode(
                "iso-8859-1", errors="replace"
            )
            parts = status_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
        except Exception:
            pass
        return 0

    def _compute_expiry_time(self, response_bytes: bytes) -> Optional[float]:
        """
        Decide how long this response may stay in cache.

        Priority:
        1. Respect Cache-Control directives when possible
        2. Respect Expires if available
        3. Fallback to default TTL

        Returns:
            expiry UNIX timestamp, or None if response should not be cached
        """
        headers = self._parse_headers_from_response(response_bytes)
        now = time.time()

        cache_control = headers.get("cache-control", "").lower()

        # Responses marked no-store must never be cached.
        if "no-store" in cache_control:
            return None

        # This project keeps things conservative and avoids storing private data.
        if "private" in cache_control:
            return None

        # Look for "max-age=number"
        if "max-age=" in cache_control:
            try:
                fragments = [fragment.strip() for fragment in cache_control.split(",")]
                for fragment in fragments:
                    if fragment.startswith("max-age="):
                        seconds = int(fragment.split("=", 1)[1])
                        if seconds < 0:
                            return None
                        return now + seconds
            except Exception:
                # Fall through to other mechanisms if parsing fails.
                pass

        expires_header = headers.get("expires")
        if expires_header:
            try:
                dt = email.utils.parsedate_to_datetime(expires_header)
                return dt.timestamp()
            except Exception:
                pass

        # If no cache duration info exists, use project-defined fallback.
        return now + self.default_ttl

    def should_cache_request(self, method: str) -> bool:
        """
        Decide whether the REQUEST method is cacheable.

        For this project, we cache only GET requests because:
        - GET is safe and commonly cacheable
        - POST/PUT/DELETE usually should not be cached in a simple proxy
        """
        return method.upper() == "GET"

    def get(self, key: str) -> Optional[CacheEntry]:
        """
        Retrieve a non-expired cache entry.

        Returns:
            CacheEntry if found and valid
            None if not found or expired
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None

            if time.time() >= entry.expiry_time:
                # Remove expired items eagerly to keep the cache clean.
                del self._cache[key]
                return None

            return entry

    def put(self, key: str, response_bytes: bytes) -> bool:
        """
        Store a response in the cache if allowed.

        Returns:
            True  -> stored successfully
            False -> not stored (non-cacheable or invalid)
        """
        expiry = self._compute_expiry_time(response_bytes)
        if expiry is None:
            return False

        status_code = self._extract_status_code(response_bytes)

        with self._lock:
            # Simple eviction strategy:
            # if full, remove the entry with the earliest expiry time.
            if len(self._cache) >= self.max_entries:
                oldest_key = min(self._cache, key=lambda k: self._cache[k].expiry_time)
                del self._cache[oldest_key]

            self._cache[key] = CacheEntry(
                response_bytes=response_bytes,
                expiry_time=expiry,
                status_code=status_code,
                stored_at=time.time(),
            )
        return True

    def clear(self) -> None:
        #Remove all entries from the cache.
        with self._lock:
            self._cache.clear()

    def stats(self) -> Dict[str, int]:
        #Return simple cache statistics useful for the admin interface or report.
    
        with self._lock:
            return {
                "entries": len(self._cache),
                "max_entries": self.max_entries,
                "default_ttl": self.default_ttl,
            }
