"""Unit tests for presets."""

from fastapi_security_headers.presets import Presets


def test_preset_default():
    config = Presets.default()
    compiled = dict(config.compile_headers())
    assert compiled[b"x-frame-options"] == b"DENY"
    assert compiled[b"x-content-type-options"] == b"nosniff"


def test_preset_api():
    config = Presets.api()
    compiled = dict(config.compile_headers())
    assert compiled[b"content-security-policy"] == b"default-src 'none'; frame-ancestors 'none'"
    assert compiled[b"referrer-policy"] == b"no-referrer"
    assert b"accelerometer=()" in compiled[b"permissions-policy"]


def test_preset_swagger_friendly():
    config = Presets.swagger_friendly()
    compiled = dict(config.compile_headers())
    csp = compiled[b"content-security-policy"].decode("latin-1")
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://fastapi.tiangolo.com" in csp
    assert "frame-ancestors 'none'" in csp


def test_preset_strict():
    config = Presets.strict()
    compiled = dict(config.compile_headers())
    assert compiled[b"cross-origin-embedder-policy"] == b"require-corp"
    assert b"preload" in compiled[b"strict-transport-security"]
    assert b"max-age=63072000" in compiled[b"strict-transport-security"]
    assert compiled[b"referrer-policy"] == b"no-referrer"
