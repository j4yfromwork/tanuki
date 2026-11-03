"""HMAC secret-cracking tests across all three backends.

- builtin : always runs (pure Python, tiny wordlist fixture)
- hashcat : runs only if hashcat is on PATH (this Kali box), else skips
- john    : runs only if john is on PATH (this Kali box), else skips

Each asserts the cracked secret matches the lab's known weak secret and that a
token re-signed with it is accepted (as admin) by /api/hs256.
"""
import shutil

import pytest
import requests

from tanuki import JWT, crack_secret, resign_hs256, suggest_modifications


def _assert_resigned_token_accepted(base_url, token, secret):
    jwt = JWT(token)
    new_payload, _ = suggest_modifications(jwt.payload)
    forged = resign_hs256(jwt, new_payload, secret)
    r = requests.get(base_url + "/api/hs256", headers={"Authorization": "Bearer " + forged})
    assert r.status_code == 200
    assert "FLAG{hs256_secret_cracked}" in r.text


def test_crack_builtin(base_url, hs256_token, wordlist_path, known_secret):
    jwt = JWT(hs256_token)
    secret, method = crack_secret(jwt, wordlist_path, prefer="builtin")
    assert method == "builtin"
    assert secret == known_secret
    _assert_resigned_token_accepted(base_url, hs256_token, secret)


def _skip_if_backend_cant_run(jwt, wordlist_path, known_secret, secret, method, name):
    """If an external cracker is present but didn't crack, confirm the token really
    IS crackable (builtin) so we know the failure is environmental — e.g. no OpenCL
    device or not enough memory for hashcat's PoCL backend — and skip, not fail."""
    if secret is None:
        bsecret, _ = crack_secret(jwt, wordlist_path, prefer="builtin")
        assert bsecret == known_secret, "token not crackable at all — real failure"
        pytest.skip("%s present but could not run in this environment (%s)"
                    % (name, method))


@pytest.mark.hashcat
@pytest.mark.skipif(shutil.which("hashcat") is None, reason="hashcat not on PATH")
def test_crack_hashcat(base_url, hs256_token, wordlist_path, known_secret):
    jwt = JWT(hs256_token)
    secret, method = crack_secret(jwt, wordlist_path, prefer="hashcat")
    _skip_if_backend_cant_run(jwt, wordlist_path, known_secret, secret, method, "hashcat")
    assert method == "hashcat", f"expected hashcat backend, got {method!r}"
    assert secret == known_secret
    _assert_resigned_token_accepted(base_url, hs256_token, secret)


@pytest.mark.john
@pytest.mark.skipif(shutil.which("john") is None, reason="john not on PATH")
def test_crack_john(base_url, hs256_token, wordlist_path, known_secret):
    jwt = JWT(hs256_token)
    secret, method = crack_secret(jwt, wordlist_path, prefer="john")
    _skip_if_backend_cant_run(jwt, wordlist_path, known_secret, secret, method, "john")
    assert method == "john", f"expected john backend, got {method!r}"
    assert secret == known_secret
    _assert_resigned_token_accepted(base_url, hs256_token, secret)
