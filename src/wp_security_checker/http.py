"""A polite HTTP client with timeouts, retries and exponential backoff."""

from __future__ import annotations

import time
from typing import Callable, List, Optional

import requests

DEFAULT_USER_AGENT = "wp-security-checker"
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class HttpClient:
    """Thin wrapper around :class:`requests.Session`.

    * waits at least ``delay`` seconds between requests,
    * retries timeouts, connection errors and 429/5xx answers up to ``retries``
      times with exponential backoff (``backoff * 2**attempt``, capped), honouring
      a numeric ``Retry-After`` header,
    * never raises for network problems: :meth:`request` returns ``None`` and the
      reason is appended to :attr:`errors`.
    """

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 10.0,
        delay: float = 0.5,
        retries: int = 2,
        backoff: float = 0.5,
        max_backoff: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.timeout = timeout
        self.delay = delay
        self.retries = max(0, retries)
        self.backoff = backoff
        self.max_backoff = max_backoff
        self.errors: List[str] = []
        self._sleep = sleep
        self._clock = clock
        self._last: Optional[float] = None
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = user_agent

    def _pace(self) -> None:
        if self._last is not None and self.delay > 0:
            wait = self.delay - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()

    def _retry_wait(self, attempt: int, response: Optional[requests.Response]) -> float:
        wait = self.backoff * (2**attempt)
        if response is not None:
            header = response.headers.get("Retry-After", "")
            if header.strip().isdigit():
                wait = max(wait, float(header))
        return min(wait, self.max_backoff)

    def request(
        self,
        url: str,
        method: str = "GET",
        allow_redirects: bool = False,
        stream: bool = False,
    ) -> Optional[requests.Response]:
        """Perform a request; return the response or None on network failure."""
        last_response: Optional[requests.Response] = None
        for attempt in range(self.retries + 1):
            self._pace()
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    stream=stream,
                )
            except requests.exceptions.SSLError as exc:
                self.errors.append(f"{url}: TLS error ({exc.__class__.__name__})")
                return None
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                self.errors.append(f"{url}: {exc.__class__.__name__}")
                if attempt < self.retries:
                    self._sleep(self._retry_wait(attempt, None))
                    continue
                return None
            except requests.RequestException as exc:
                self.errors.append(f"{url}: {exc.__class__.__name__}")
                return None
            last_response = response
            if response.status_code in RETRY_STATUSES and attempt < self.retries:
                wait = self._retry_wait(attempt, response)
                response.close()
                self._sleep(wait)
                continue
            return response
        return last_response

    @staticmethod
    def read_head(response: requests.Response, size: int = 512) -> bytes:
        """Read at most ``size`` bytes of the body and close the connection."""
        try:
            return next(response.iter_content(size), b"")
        finally:
            response.close()
