"""Unit tests for tanuki's pure helpers — no network, no lab needed.

Covers base64url round-tripping, the classify() verdict function across all four
outcomes (bypass / access-bypass / accepted / rejected), and the claim helpers.
"""
import os

import pytest

from tanuki import (
    b64url_encode,
    b64url_decode,
    encode_segment,
    classify,
    suggest_modifications,
    parse_custom_claims,
    JWT,
)


# ── base64url round-trip ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"\x00\x01\x02\xff\xfe",
        os.urandom(64),
        "hello world".encode(),
    ],
)
def test_b64url_roundtrip_bytes(raw):
    enc = b64url_encode(raw)
    # URL-safe base64url has no padding and none of +/=
    assert "=" not in enc
    assert "+" not in enc and "/" not in enc
    assert b64url_decode(enc) == raw


def test_b64url_accepts_str_input():
    assert b64url_decode(b64url_encode("café".encode())) == "café".encode()
    # encoding a str is treated as its utf-8 bytes
    assert b64url_encode("abc") == b64url_encode(b"abc")


def test_encode_segment_is_compact_json():
    seg = encode_segment({"alg": "none", "typ": "JWT"})
    decoded = b64url_decode(seg).decode()
    assert decoded == '{"alg":"none","typ":"JWT"}'  # no spaces


# ── classify() verdicts ───────────────────────────────────────────────────────
def test_classify_rejected():
    # forged token denied with 401/403
    for status in (401, 403):
        kind, text, _ = classify((200, 100, ""), (status, 50, ""))
        assert kind == "rejected"
        assert "rejected" in text.lower()


def test_classify_access_bypass():
    # baseline was denied (403), forged token is accepted (200) -> access bypass
    kind, text, _ = classify((403, 30, "forbidden"), (200, 400, "admin"))
    assert kind == "bypass"
    assert "ACCESS BYPASS" in text


def test_classify_bypass_on_length_change():
    # baseline accepted, forged accepted but response differs -> behaviour change
    kind, text, _ = classify((200, 100, "user"), (200, 250, "admin"))
    assert kind == "bypass"
    assert "BYPASS" in text


def test_classify_accepted_no_baseline():
    kind, text, _ = classify(None, (200, 80, "ok"))
    assert kind == "accepted"
    assert "ACCEPTED" in text.upper()


def test_classify_accepted_unchanged():
    kind, text, _ = classify((200, 100, "same"), (200, 100, "same"))
    assert kind == "accepted"
    assert "unchanged" in text.lower()


def test_classify_error_cases():
    assert classify(None, None)[0] == "error"
    assert classify((200, 1, ""), ("ERR", 0, "boom"))[0] == "error"


# ── claim helpers ─────────────────────────────────────────────────────────────
def test_suggest_modifications_flips_role_and_bumps_exp():
    payload = {"sub": "wiener", "role": "user", "exp": 1600000000}
    modified, changed = suggest_modifications(payload)
    assert modified["role"] == "admin"
    assert modified["exp"] == 9999999999
    changed_keys = {c[0] for c in changed}
    assert "role" in changed_keys and "exp" in changed_keys


def test_suggest_modifications_preserves_bool_and_list_types():
    payload = {"isAdmin": False, "groups": ["users"]}
    modified, _ = suggest_modifications(payload)
    assert modified["isAdmin"] is True
    assert isinstance(modified["groups"], list)
    assert "admin" in modified["groups"]


def test_parse_custom_claims_type_inference():
    out = parse_custom_claims("role=admin,isAdmin=true,active=false,level=5,x=null")
    assert out == {
        "role": "admin",
        "isAdmin": True,
        "active": False,
        "level": 5,
        "x": None,
    }


def test_jwt_parse_roundtrip():
    header = encode_segment({"alg": "HS256", "typ": "JWT"})
    payload = encode_segment({"sub": "wiener", "role": "user"})
    token = f"{header}.{payload}.deadbeef"
    jwt = JWT(token)
    assert jwt.header["alg"] == "HS256"
    assert jwt.payload["role"] == "user"
    assert jwt.signing_input == f"{header}.{payload}"


def test_jwt_rejects_garbage():
    with pytest.raises(ValueError):
        JWT("not-a-jwt")
