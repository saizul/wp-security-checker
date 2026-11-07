import pytest
import responses

from wp_security_checker.context import ScanContext
from wp_security_checker.http import HttpClient

BASE = "https://example.com/"


@pytest.fixture
def client():
    return HttpClient(delay=0, retries=0, sleep=lambda s: None)


@pytest.fixture
def ctx(client):
    return ScanContext(BASE, client)


@pytest.fixture
def mock():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


def html(mock, body="<html><head></head><body>hi</body></html>", headers=None, url=BASE):
    mock.add(responses.GET, url, body=body, content_type="text/html", headers=headers or {})
