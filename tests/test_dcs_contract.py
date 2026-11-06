"""DCS HTTP contracts from the official 6.10 status and assets examples."""

import httpx
import pytest

from symantec_dcs_aiops import ops
from symantec_dcs_aiops.connection import DcsConnection, DcsError


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("SYMANTEC_DCS_URL", "https://dcs.example:4443")
    monkeypatch.setenv("SYMANTEC_DCS_USERNAME", "reader")
    monkeypatch.setenv("SYMANTEC_DCS_PASSWORD", "secret")


def test_auth_status_and_asset_pagination():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        if request.url.path.endswith("/status/server"):
            return httpx.Response(200, json={"total": 10, "offline": 2})
        return httpx.Response(200, json=[{"rid": 1}, {"rid": 2}, {"rid": 3}])

    conn = DcsConnection(
        httpx.Client(base_url="https://dcs.example:4443", transport=httpx.MockTransport(handler))
    )
    assert ops.status(conn, "server")["data"]["offline"] == 2
    page = ops.assets(conn, "rid", limit=2)
    assert page["truncated"] and page["nextOffset"] == 2
    assert seen[0].method == "POST" and seen[0].url.path == "/sis-ui/api/v2/auth/token"
    assert seen[1].headers["authorization"] == "JWT t"
    assert seen[2].url.params["sort"] == "rid"
    assert seen[2].url.params["limit"] == "3"


def test_bad_page_and_no_post_mutation():
    def handler(request):
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        return httpx.Response(200, json={"items": []})

    conn = DcsConnection(
        httpx.Client(base_url="https://dcs.example:4443", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DcsError, match="unexpected page"):
        ops.alerts(conn, "rid")
    with pytest.raises(ValueError, match="read operations"):
        conn.query("/sis-ui/api/v2/policies", {"name": "bad"})


def test_unpaged_error_response_is_capped_and_flagged():
    def handler(request):
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        return httpx.Response(200, json=[{"eventId": 1}, {"eventId": 2}])

    conn = DcsConnection(
        httpx.Client(base_url="https://dcs.example:4443", transport=httpx.MockTransport(handler))
    )
    result = ops.asset_errors(conn, 7, limit=1)
    assert result["returned"] == 1 and result["truncated"] is True


def test_asset_and_report_job_read_paths():
    seen = []

    def handler(request):
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        seen.append(request.url.path)
        return httpx.Response(200, json={"rid": 7})

    conn = DcsConnection(
        httpx.Client(base_url="https://dcs.example:4443", transport=httpx.MockTransport(handler))
    )
    assert ops.asset(conn, 7)["data"]["rid"] == 7
    assert ops.report_job(conn, 9)["data"]["rid"] == 7
    assert seen == ["/sis-ui/api/v1/sa/assets/7", "/sis-ui/api/v2/reports/jobs/9"]
    with pytest.raises(ValueError, match="positive"):
        ops.asset(conn, -1)


def test_filtered_event_stats_validate_response_shape():
    def handler(request):
        if request.url.path.endswith("/auth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        assert request.url.params["filter"] == "severity:=:critical"
        return httpx.Response(200, json=[])

    conn = DcsConnection(
        httpx.Client(base_url="https://dcs.example:4443", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DcsError, match="unexpected object"):
        ops.event_stats(conn, "severity:=:critical")


@pytest.mark.parametrize("oversized_login", [False, True])
def test_stream_stops_reading_after_response_limit(monkeypatch, oversized_login):
    import symantec_dcs_aiops.connection as connection_module

    monkeypatch.setattr(connection_module, "_MAX_RESPONSE_BYTES", 70_000)

    class ProbeStream(httpx.SyncByteStream):
        def __init__(self):
            self.read_chunks = 0
            self.closed = False

        def __iter__(self):
            for _ in range(3):
                self.read_chunks += 1
                yield b" " * (64 * 1024)

        def close(self):
            self.closed = True

    probe = ProbeStream()

    def handler(request):
        if (request.url.path == "/sis-ui/api/v2/auth/token") == oversized_login:
            return httpx.Response(200, stream=probe)
        if request.url.path == "/sis-ui/api/v2/auth/token":
            return httpx.Response(200, content=b'{"access_token":"t","expires_in":3600}')
        return httpx.Response(200, json={})

    conn = DcsConnection(
        httpx.Client(base_url="https://example.test", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DcsError, match="response exceeds 16 MiB"):
        conn.get("/sis-ui/api/v2/status/server")
    assert probe.read_chunks == 2
    assert probe.closed
