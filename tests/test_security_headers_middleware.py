# tests/test_security_headers_middleware.py
"""
Focused regression coverage for `SecurityHeadersMiddleware`
(core/middleware.py), added alongside the HSTS + Permissions-Policy
hardening:

  1. HSTS is emitted only for HTTPS requests, including those reaching
     the app over a reverse proxy (`X-Forwarded-Proto: https`).
  2. HSTS is absent on plain HTTP so local/dev deployments are unaffected.
  3. `Permissions-Policy` locks down camera/geolocation but preserves
     same-origin microphone access (`microphone=(self)`), so the app's
     own voice/STT flow (`getUserMedia({ audio: true })`) keeps working.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.middleware import SecurityHeadersMiddleware


def _build_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/")
    def root():
        return {"ok": True}

    return app


def _client(base_url="http://testserver"):
    return TestClient(_build_app(), base_url=base_url)


def test_hsts_absent_on_plain_http():
    response = _client().get("/")

    assert "strict-transport-security" not in response.headers


def test_hsts_present_for_direct_https_requests():
    response = _client(base_url="https://testserver").get("/")

    assert response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_hsts_present_via_x_forwarded_proto_https():
    response = _client().get("/", headers={"X-Forwarded-Proto": "https"})

    assert response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains"
    )


def test_permissions_policy_locks_camera_and_geolocation_but_allows_self_microphone():
    response = _client().get("/")

    policy = response.headers["permissions-policy"]
    assert policy == "camera=(), microphone=(self), geolocation=()"

    # Explicitly pin the contract the reviewer flagged: an empty allowlist
    # would also block the app's own same-origin voice/STT button.
    assert "microphone=()" not in policy
    assert "microphone=(self)" in policy


def test_framing_denied_by_default(monkeypatch):
    monkeypatch.delenv("EMBED_ALLOWED_ORIGINS", raising=False)

    response = _client().get("/")

    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_embed_allowed_origins_extend_frame_ancestors(monkeypatch):
    monkeypatch.setenv(
        "EMBED_ALLOWED_ORIGINS",
        "http://localhost:3000, https://dash.example.com/",
    )

    response = _client().get("/")

    csp = response.headers["content-security-policy"]
    assert "frame-ancestors 'self' http://localhost:3000 https://dash.example.com" in csp
    # XFO can't express an allowlist — it must be omitted so it doesn't
    # override the CSP in browsers that would otherwise honour it.
    assert "x-frame-options" not in response.headers


def test_embed_allowed_origins_ignores_non_http_entries(monkeypatch):
    monkeypatch.setenv("EMBED_ALLOWED_ORIGINS", "javascript:alert(1), , ftp://x")

    response = _client().get("/")

    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
