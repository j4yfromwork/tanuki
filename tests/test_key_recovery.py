"""RSA public-key recovery from two signatures (GCD-of-signatures attack).

Known-answer tests: generate an RSA keypair, sign two tokens, discard the public
key, and assert the tool recovers the exact modulus — plus PKCS#1/SPKI PEM
round-trips, PKCS#1 padding correctness, and the error paths. Pure Python; no
network or lab needed.

Note on exponents: e=3 recovery is instant at any key size, so the full-pipeline
known-answer test uses a real 1024-bit e=3 keypair. e=65537 means raising to the
65537th power and GCD-ing multi-megabit integers — instant to verify but heavy to
compute for large keys in pure Python — so its known-answer test uses a small
(but real) RSA key, which still exercises the exact e=65537 code path.
"""
import random
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import tanuki as jf
from tanuki import tanuki as _mod   # for the private EMSA helper

REPO_ROOT = Path(__file__).resolve().parent.parent


# ── helpers ───────────────────────────────────────────────────────────────────
def _sign_rs256(priv, payload):
    h = jf.encode_segment({"alg": "RS256", "typ": "JWT"})
    p = jf.encode_segment(payload)
    sig = priv.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{jf.b64url_encode(sig)}"


def _fake_rs256(payload, sig_bytes):
    h = jf.encode_segment({"alg": "RS256", "typ": "JWT"})
    p = jf.encode_segment(payload)
    return f"{h}.{p}.{jf.b64url_encode(sig_bytes)}"


def _is_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits, rng):
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c) and (c - 1) % 65537:
            return c


def _run_cli(args, timeout=60):
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", *args],
        cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def e3_key():
    """A real 1024-bit RSA keypair with e=3 and two tokens signed by it."""
    priv = rsa.generate_private_key(public_exponent=3, key_size=1024)
    n = priv.public_key().public_numbers().n
    t0 = _sign_rs256(priv, {"sub": "wiener", "role": "user"})
    t1 = _sign_rs256(priv, {"sub": "carlos", "role": "user", "k": 2})
    return {"priv": priv, "n": n, "t0": t0, "t1": t1}


# ── known-answer: full pipeline, e=3 (real 1024-bit key) ──────────────────────
def test_recover_modulus_e3_full_pipeline(e3_key):
    results = jf.derive_public_key(e3_key["t0"], e3_key["t1"])
    assert results, "no key recovered"
    assert results[0]["e"] == 3
    assert results[0]["n"] == e3_key["n"], "recovered modulus != real modulus"


def test_recovered_pems_parse_back_to_modulus(e3_key):
    r = jf.derive_public_key(e3_key["t0"], e3_key["t1"])[0]
    for pem_key in ("pkcs1_pem", "spki_pem"):
        pub = serialization.load_pem_public_key(r[pem_key].encode())
        nums = pub.public_numbers()
        assert nums.n == e3_key["n"], "%s modulus mismatch" % pem_key
        assert nums.e == 3
    assert "BEGIN RSA PUBLIC KEY" in r["pkcs1_pem"]   # PKCS#1
    assert "BEGIN PUBLIC KEY" in r["spki_pem"]        # SPKI / X.509


# ── PKCS#1 v1.5 EMSA padding matches a real signature ─────────────────────────
def test_emsa_padding_matches_real_signature(e3_key):
    j = jf.JWT(e3_key["t0"])
    emlen = len(j.signature)                                   # modulus byte length
    m = _mod._emsa_pkcs1v15_int(j.signing_input.encode(), "SHA256", emlen)
    sig = int.from_bytes(j.signature, "big")
    # sig^e mod n must equal our EMSA-encoded integer
    assert pow(sig, 3, e3_key["n"]) == m


def _e65537_known_answer(rng, bits):
    """Build an (sig0, m0, sig1, m1) sample for a real e=65537 key of `bits`
    half-primes, returning it alongside the true modulus."""
    p, q = _prime(bits, rng), _prime(bits, rng)
    n, e = p * q, 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    m0, m1 = rng.randrange(2, n), rng.randrange(2, n)
    sig0, sig1 = pow(m0, d, n), pow(m1, d, n)
    return sig0, m0, sig1, m1, n


# ── known-answer: the real e=65537 code path (small but real RSA key) ─────────
def test_recover_modulus_e65537_core():
    sig0, m0, sig1, m1, n = _e65537_known_answer(random.Random(2024), 24)
    results = jf.recover_modulus(sig0, m0, sig1, m1, (3, 65537))
    assert (n, 65537) in results, "did not recover the exact modulus for e=65537"
    # and the PEMs for that recovered modulus parse back to the same (n, e)
    pkcs1_pem, spki_pem = jf.rsa_public_pems(n, 65537)
    for pem in (pkcs1_pem, spki_pem):
        nums = serialization.load_pem_public_key(pem.encode()).public_numbers()
        assert nums.n == n and nums.e == 65537


# ── gmpy2 path and pure-Python path recover the IDENTICAL modulus ─────────────
def test_gmpy2_and_pure_python_agree(monkeypatch):
    sig0, m0, sig1, m1, n = _e65537_known_answer(random.Random(99), 28)
    real_gmpy2 = _mod._GMPY2

    # force the pure-Python path regardless of whether gmpy2 is installed
    monkeypatch.setattr(_mod, "_GMPY2", None)
    pure = _mod.recover_modulus(sig0, m0, sig1, m1, (3, 65537))
    assert (n, 65537) in pure

    if real_gmpy2 is None:
        pytest.skip("gmpy2 not installed — only the pure-Python path is available")
    monkeypatch.setattr(_mod, "_GMPY2", real_gmpy2)
    accel = _mod.recover_modulus(sig0, m0, sig1, m1, (3, 65537))
    assert accel == pure, "gmpy2 and pure-Python paths disagree"


# ── --derive-timeout actually aborts a runaway derivation ─────────────────────
def test_recover_modulus_timed_aborts(monkeypatch):
    import time as _time
    # stand in a slow recovery; the timeout must kill it rather than hang
    monkeypatch.setattr(_mod, "recover_modulus",
                        lambda *a, **k: (_time.sleep(30), [])[1])
    with pytest.raises(TimeoutError):
        _mod.recover_modulus_timed(6, 2, 15, 3, (3,), timeout=1)


def test_recover_modulus_timed_no_limit_runs_inprocess():
    # timeout 0 / None runs in-process and still returns the right answer
    sig0, m0, sig1, m1, n = _e65537_known_answer(random.Random(7), 24)
    assert (n, 65537) in _mod.recover_modulus_timed(sig0, m0, sig1, m1, (3, 65537),
                                                    timeout=0)


def test_rsa_public_pems_roundtrip():
    rng = random.Random(7)
    p, q = _prime(256, rng), _prime(256, rng)
    n, e = p * q, 65537
    pkcs1_pem, spki_pem = jf.rsa_public_pems(n, e)
    for pem in (pkcs1_pem, spki_pem):
        nums = serialization.load_pem_public_key(pem.encode()).public_numbers()
        assert nums.n == n and nums.e == e


# ── error paths: clear messages, no tracebacks ────────────────────────────────
def test_error_mismatched_signature_length():
    t0 = _fake_rs256({"a": 1}, b"\x11" * 128)   # 128-byte sig
    t1 = _fake_rs256({"a": 2}, b"\x22" * 256)   # 256-byte sig
    with pytest.raises(ValueError) as ei:
        jf.derive_public_key(t0, t1)
    assert "length" in str(ei.value).lower()


def test_error_non_rs_algorithm(e3_key):
    hs = (jf.encode_segment({"alg": "HS256", "typ": "JWT"}) + "."
          + jf.encode_segment({"sub": "x"}) + ".c2ln")
    with pytest.raises(ValueError) as ei:
        jf.derive_public_key(e3_key["t0"], hs)
    assert "RS256" in str(ei.value) or "RS" in str(ei.value)


def test_error_different_algorithms():
    t_rs256 = _fake_rs256({"a": 1}, b"\x11" * 128)
    t_rs384 = (jf.encode_segment({"alg": "RS384", "typ": "JWT"}) + "."
               + jf.encode_segment({"a": 2}) + "." + jf.b64url_encode(b"\x22" * 128))
    with pytest.raises(ValueError) as ei:
        jf.derive_public_key(t_rs256, t_rs384)
    assert "algorithm" in str(ei.value).lower()


# ── CLI ───────────────────────────────────────────────────────────────────────
def test_cli_derive_only(e3_key):
    rc, out = _run_cli([e3_key["t0"], "--derive-key", e3_key["t1"],
                        "--derive-only", "-q", "--no-color"])
    assert rc == 0, out[-2000:]
    assert "BEGIN RSA PUBLIC KEY" in out       # PKCS#1 PEM printed
    assert "BEGIN PUBLIC KEY" in out           # SPKI PEM printed
    assert "recovered RSA public key" in out


def test_cli_derive_only_without_second_token_errors(e3_key):
    rc, out = _run_cli([e3_key["t0"], "--derive-only", "-q", "--no-color"])
    assert rc == 1
    assert "second token" in out.lower() or "--derive-key" in out
    assert "Traceback" not in out


def test_cli_hint_when_no_key_and_no_second_token(e3_key):
    # RS token, no --pubkey, no reachable JWKS, no second token -> actionable hint
    rc, out = _run_cli([e3_key["t0"], "--no-crack", "--no-replay", "-q", "--no-color"])
    assert "--derive-key" in out
    assert "recover the key from two signatures" in out
