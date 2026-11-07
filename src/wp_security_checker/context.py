"""Per-scan context handed to every check."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from .http import HttpClient


class ScanContext:
    """Holds the target URL, the HTTP client and a cached home page."""

    def __init__(self, base_url: str, client: HttpClient) -> None:
        self.base_url = base_url if base_url.endswith("/") else base_url + "/"
        self.client = client
        self._home: Optional[requests.Response] = None
        self._home_loaded = False
        self._soup: Optional[BeautifulSoup] = None

    def url(self, path: str) -> str:
        """Absolute URL for a path relative to the site root."""
        return urljoin(self.base_url, path.lstrip("/"))

    def http_url(self) -> str:
        """The plain-HTTP variant of the base URL."""
        parts = urlparse(self.base_url)
        return urlunparse(parts._replace(scheme="http"))

    @property
    def home(self) -> Optional[requests.Response]:
        """The home page response (redirects followed), fetched once."""
        if not self._home_loaded:
            self._home = self.client.request(self.base_url, allow_redirects=True)
            self._home_loaded = True
        return self._home

    @property
    def soup(self) -> Optional[BeautifulSoup]:
        """Parsed home page, or None when it is missing or not HTML."""
        if self._soup is None and self.home is not None:
            ctype = self.home.headers.get("Content-Type", "").lower()
            if "html" in ctype or self.home.text.lstrip().startswith("<"):
                self._soup = BeautifulSoup(self.home.text, "html.parser")
        return self._soup
