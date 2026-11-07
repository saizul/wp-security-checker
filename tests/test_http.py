import requests
import responses

from wp_security_checker.http import HttpClient


def test_user_agent_header(mock):
    mock.add(responses.GET, "https://a.test/", body="x")
    c = HttpClient(delay=0, retries=0)
    c.request("https://a.test/")
    assert mock.calls[0].request.headers["User-Agent"] == "wp-security-checker"


def test_custom_user_agent(mock):
    mock.add(responses.GET, "https://a.test/", body="x")
    HttpClient(user_agent="custom", delay=0, retries=0).request("https://a.test/")
    assert mock.calls[0].request.headers["User-Agent"] == "custom"


def test_returns_none_on_connection_error(mock):
    mock.add(responses.GET, "https://a.test/", body=requests.ConnectionError("boom"))
    c = HttpClient(delay=0, retries=0)
    assert c.request("https://a.test/") is None
    assert "ConnectionError" in c.errors[0]


def test_retries_on_503_then_succeeds(mock):
    mock.add(responses.GET, "https://a.test/", status=503)
    mock.add(responses.GET, "https://a.test/", status=200, body="ok")
    sleeps = []
    c = HttpClient(delay=0, retries=2, backoff=1, sleep=sleeps.append)
    assert c.request("https://a.test/").status_code == 200
    assert sleeps == [1]


def test_backoff_is_exponential(mock):
    for _ in range(3):
        mock.add(responses.GET, "https://a.test/", status=500)
    sleeps = []
    c = HttpClient(delay=0, retries=2, backoff=1, sleep=sleeps.append)
    resp = c.request("https://a.test/")
    assert resp.status_code == 500
    assert sleeps == [1, 2]


def test_retry_after_header_is_honoured(mock):
    mock.add(responses.GET, "https://a.test/", status=429, headers={"Retry-After": "7"})
    mock.add(responses.GET, "https://a.test/", status=200)
    sleeps = []
    HttpClient(delay=0, retries=1, backoff=0.1, sleep=sleeps.append).request("https://a.test/")
    assert sleeps == [7.0]


def test_backoff_capped(mock):
    mock.add(responses.GET, "https://a.test/", status=429, headers={"Retry-After": "999"})
    mock.add(responses.GET, "https://a.test/", status=200)
    sleeps = []
    HttpClient(delay=0, retries=1, max_backoff=5, sleep=sleeps.append).request("https://a.test/")
    assert sleeps == [5]


def test_timeout_retried_then_none(mock):
    mock.add(responses.GET, "https://a.test/", body=requests.Timeout("slow"))
    mock.add(responses.GET, "https://a.test/", body=requests.Timeout("slow"))
    sleeps = []
    c = HttpClient(delay=0, retries=1, backoff=2, sleep=sleeps.append)
    assert c.request("https://a.test/") is None
    assert sleeps == [2]
    assert len(c.errors) == 2


def test_ssl_error_not_retried(mock):
    mock.add(responses.GET, "https://a.test/", body=requests.exceptions.SSLError("bad cert"))
    sleeps = []
    c = HttpClient(delay=0, retries=3, sleep=sleeps.append)
    assert c.request("https://a.test/") is None
    assert sleeps == []
    assert "TLS" in c.errors[0]


def test_delay_between_requests(mock):
    mock.add(responses.GET, "https://a.test/", body="x")
    sleeps = []
    now = [100.0]
    c = HttpClient(delay=0.5, retries=0, sleep=sleeps.append, clock=lambda: now[0])
    c.request("https://a.test/")
    assert sleeps == []
    c.request("https://a.test/")
    assert sleeps == [0.5]


def test_timeout_is_passed_to_session(mock):
    mock.add(responses.GET, "https://a.test/", body="x")
    HttpClient(timeout=3, delay=0, retries=0).request("https://a.test/")
    assert mock.calls[0].request.req_kwargs["timeout"] == 3


def test_read_head_limits_bytes(mock):
    mock.add(responses.GET, "https://a.test/", body="A" * 5000)
    resp = HttpClient(delay=0, retries=0).request("https://a.test/", stream=True)
    assert len(HttpClient.read_head(resp, 100)) <= 100
