#!/usr/bin/env python3
"""
jwt-demo-lab — a deliberately vulnerable JWT web app.

Built to exercise every attack in tanuki. Each endpoint demonstrates one
JWT failure mode, plus one correctly-secured control endpoint so a scan shows
the contrast.

    DO NOT DEPLOY THIS. It is intentionally insecure. Run it on localhost only.

Endpoints
---------
  GET  /                         lab index (how to get a token, endpoint list)
  POST /login                    issue an RS256 token  {"user":"wiener"} -> role:user
  POST /login-hs256              issue an HS256 token (weak secret)
  GET  /.well-known/jwks.json    public key for RS256 (enables JWKS discovery)

  GET  /api/user     RS256, trusts the alg header   [VULN: alg:none, key confusion]
  GET  /api/admin    RS256, trusts the alg header   [VULN: access bypass to admin]
  GET  /api/hs256    HS256, weak secret             [VULN: secret cracking]
  GET  /api/kid      key chosen by kid header        [VULN: kid path traversal]
  GET  /api/secure   RS256, algorithm pinned         [SECURE control: rejects all]

A token is read from the Authorization: Bearer header, OR a `session` cookie,
OR a JSON body field `token` — so you can practise all three replay styles.
"""

import os
import json
import base64
import hmac
import hashlib
import time
import itertools
from collections import defaultdict
from pathlib import Path

from flask import (Flask, request, jsonify, Response,
                   render_template, redirect, url_for)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# ── Config — deliberately weak ───────────────────────────────────────────────
HS256_SECRET = "secret123"           # in rockyou — crackable in seconds
KEYDIR = Path(__file__).parent / "keys"
KEYDIR.mkdir(exist_ok=True)
PRIV_PATH = KEYDIR / "private.pem"
PUB_PATH = KEYDIR / "public.pem"


# ── Key management — generate an RSA keypair on first run ────────────────────
def load_or_create_keys():
    if PRIV_PATH.exists() and PUB_PATH.exists():
        priv = serialization.load_pem_private_key(PRIV_PATH.read_bytes(), password=None)
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        PRIV_PATH.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        PUB_PATH.write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return priv, priv.public_key()


PRIV_KEY, PUB_KEY = load_or_create_keys()
PUB_PEM = PUB_PATH.read_bytes()

# ── A SECOND, HIDDEN RSA keypair (the "no exposed key" scenario) ──────────────
# Distinct from the keypair above and deliberately NEVER served: not in the JWKS,
# not on any route, header, or error message. Tokens for /api/noexposedkey are
# signed with it, so tanuki can't discover the key and must RECOVER it from two
# signatures (the derive-modulus-from-two-signatures attack). 2048-bit / e=65537,
# matching the PortSwigger "algorithm confusion, no exposed key" lab.
REC_PRIV_PATH = KEYDIR / "recovery_private.pem"
REC_PUB_PATH = KEYDIR / "recovery_public.pem"


def load_or_create_recovery_keys():
    if REC_PRIV_PATH.exists() and REC_PUB_PATH.exists():
        priv = serialization.load_pem_private_key(REC_PRIV_PATH.read_bytes(), password=None)
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        REC_PRIV_PATH.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        REC_PUB_PATH.write_bytes(priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return priv, priv.public_key()


REC_PRIV_KEY, REC_PUB_KEY = load_or_create_recovery_keys()
REC_PUB_PEM = REC_PUB_PATH.read_bytes()
_REC_NONCE = itertools.count(1)   # guarantees two sequential logins differ

# The kid-based key store. 'key-1' is the real HMAC key the app signs kid tokens
# with. The vulnerability is that the lookup does not sanitise the kid, so a
# path-traversal kid (…/dev/null) loads an empty file => empty signing key.
KID_KEYS = {"key-1": b"s3cr3t-kid-signing-key"}

# ── Browsable web frontend config ─────────────────────────────────────────────
# A session-cookie UI over the SAME vulnerable verification. Credentials for the
# demo user only — there is deliberately NO administrator login: admin is reachable
# ONLY by forging the token. That is the whole point of the lab.
WEB_USERS = {"wiener": "peter"}                        # username -> password (role:user)
ADMIN_USERS = ["wiener", "carlos", "steve", "administrator"]  # shown in the admin panel
WIN_TARGET = "carlos"                                  # deleting carlos = lab solved
# Server-side lab state, mirroring PortSwigger's "solved" flag.
LAB_STATE = {"solved": False, "deleted": []}

# Test-support instrumentation (not a vulnerability): count hits to /api/* routes
# so the suite can assert that passive discovery / recon never touches them.
_API_HITS = defaultdict(int)


@app.before_request
def _count_api_hits():
    if request.path.startswith("/api/"):
        _API_HITS[request.path] += 1


@app.route("/_debug/hits")
def _debug_hits():
    return jsonify(dict(_API_HITS))


# ── base64url helpers ────────────────────────────────────────────────────────
def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_uint(n):
    length = (n.bit_length() + 7) // 8
    return b64url_encode(n.to_bytes(length, "big"))


def encode_segment(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":")))


# ── Token issuing ────────────────────────────────────────────────────────────
def sign_rs256(payload, kid="key-1"):
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    signing_input = f"{encode_segment(header)}.{encode_segment(payload)}"
    sig = PRIV_KEY.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url_encode(sig)}"


def sign_hs256(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{encode_segment(header)}.{encode_segment(payload)}"
    sig = hmac.new(secret.encode() if isinstance(secret, str) else secret,
                   signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def sign_kid(payload, kid="key-1"):
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = f"{encode_segment(header)}.{encode_segment(payload)}"
    key = KID_KEYS.get(kid, b"")
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def sign_rs256_recovery(payload):
    """RS256, signed with the HIDDEN recovery key. No kid (the key is unfindable)."""
    header = {"alg": "RS256", "typ": "JWT"}
    signing_input = f"{encode_segment(header)}.{encode_segment(payload)}"
    sig = REC_PRIV_KEY.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url_encode(sig)}"


# ── Token extraction (header / cookie / body) ────────────────────────────────
def get_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    cookie_tok = request.cookies.get("session")
    if cookie_tok:
        return cookie_tok
    if request.is_json:
        data = request.get_json(silent=True) or {}
        if "token" in data:
            return data["token"]
    return None


def split(token):
    h, p, s = token.split(".")
    return h, p, s, json.loads(b64url_decode(h)), json.loads(b64url_decode(p))


# ── Verification routines ────────────────────────────────────────────────────
def verify_trusting_alg(token):
    """VULNERABLE: trusts the alg header.

    - alg=none  -> accepted with no signature
    - alg=HS256 -> verified with the RSA *public key* as the HMAC secret
    - alg=RS256 -> verified properly with the public key

    This single mistake enables both alg:none and RS256->HS256 key confusion.
    """
    try:
        h, p, s, header, payload = split(token)
        signing_input = f"{h}.{p}".encode()
        alg = header.get("alg", "")
        if alg == "none":
            return True, payload
        if alg == "HS256":
            expected = hmac.new(PUB_PEM, signing_input, hashlib.sha256).digest()
            return hmac.compare_digest(expected, b64url_decode(s)), payload
        if alg == "RS256":
            try:
                PUB_KEY.verify(b64url_decode(s), signing_input,
                               padding.PKCS1v15(), hashes.SHA256())
                return True, payload
            except Exception:
                return False, None
        return False, None
    except Exception:
        return False, None


def verify_hs256_weak(token):
    """VULNERABLE: HS256 signed with a weak, crackable secret."""
    try:
        h, p, s, header, payload = split(token)
        if header.get("alg") != "HS256":
            return False, None
        signing_input = f"{h}.{p}".encode()
        expected = hmac.new(HS256_SECRET.encode(), signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(expected, b64url_decode(s)), payload
    except Exception:
        return False, None


def verify_kid(token):
    """VULNERABLE: kid chooses the signing key via an unsanitised file/dict lookup.

    Real apps often do: open(f"keys/{kid}").read(). Here we emulate the same flaw
    with a path-aware lookup — a traversal kid like '../../dev/null' yields an
    empty key, and alg=none is also honoured.
    """
    try:
        h, p, s, header, payload = split(token)
        signing_input = f"{h}.{p}".encode()
        alg = header.get("alg", "")
        if alg == "none":
            return True, payload
        kid = str(header.get("kid", ""))
        # emulate a filesystem-backed key lookup without sanitising kid
        if ".." in kid or kid.endswith("/dev/null") or kid == "":
            key = b""                       # traversal -> empty file contents
        elif kid in KID_KEYS:
            key = KID_KEYS[kid]
        else:
            # emulate "SELECT key FROM keys WHERE kid = '<kid>'" returning nothing;
            # a SQLi kid that forces a known value is left as an exercise, but an
            # unknown kid falls back to empty here too (common real-world bug)
            key = b""
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        return hmac.compare_digest(expected, b64url_decode(s)), payload
    except Exception:
        return False, None


def verify_secure(token):
    """SECURE control: algorithm pinned to RS256, verified with PyJWT.

    Rejects alg:none, HS256 confusion, jwk/jku/kid tricks — everything.
    """
    try:
        import jwt  # PyJWT
        payload = jwt.decode(token, PUB_PEM, algorithms=["RS256"],
                             options={"verify_exp": False})
        return True, payload
    except Exception:
        return False, None


def verify_trusting_alg_recovery(token):
    """VULNERABLE, identical flaw to verify_trusting_alg — but bound to the HIDDEN
    recovery key. RS256 is checked against the recovery public key, and the HS256
    'confusion' secret is the recovery public key PEM. So once tanuki RECOVERS
    that key from two signatures, RS256->HS256 confusion works exactly as it does
    on the exposed-key endpoints. The key itself is never served anywhere."""
    try:
        h, p, s, header, payload = split(token)
        signing_input = f"{h}.{p}".encode()
        alg = header.get("alg", "")
        if alg == "none":
            return True, payload
        if alg == "HS256":
            expected = hmac.new(REC_PUB_PEM, signing_input, hashlib.sha256).digest()
            return hmac.compare_digest(expected, b64url_decode(s)), payload
        if alg == "RS256":
            try:
                REC_PUB_KEY.verify(b64url_decode(s), signing_input,
                                   padding.PKCS1v15(), hashes.SHA256())
                return True, payload
            except Exception:
                return False, None
        return False, None
    except Exception:
        return False, None


# ── Response helpers ─────────────────────────────────────────────────────────
def user_view(payload):
    role = payload.get("role", "user")
    if role == "admin":
        return jsonify(page="user", role="admin",
                       data="user home — admin widgets visible",
                       admin_widgets=["user-management", "audit-log", "billing"])
    return jsonify(page="user", role=role, data="user home")


def admin_view(payload):
    return jsonify(page="admin", role="admin",
                   secret="FLAG{admin_panel_unlocked}",
                   all_users=["wiener", "carlos", "administrator"])


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("user", "wiener")
    role = "admin" if user == "administrator" else "user"
    token = sign_rs256({"sub": user, "role": role, "iss": "jwt-demo-lab",
                        "exp": 1600000000})
    return jsonify(token=token, user=user, role=role)


@app.route("/login-hs256", methods=["POST"])
def login_hs256():
    data = request.get_json(silent=True) or {}
    user = data.get("user", "wiener")
    role = "admin" if user == "administrator" else "user"
    token = sign_hs256({"sub": user, "role": role, "iss": "jwt-demo-lab"},
                       HS256_SECRET)
    return jsonify(token=token, user=user, role=role)


@app.route("/login-kid", methods=["POST"])
def login_kid():
    data = request.get_json(silent=True) or {}
    user = data.get("user", "wiener")
    role = "admin" if user == "administrator" else "user"
    token = sign_kid({"sub": user, "role": role, "iss": "jwt-demo-lab"})
    return jsonify(token=token, user=user, role=role)


@app.route("/.well-known/jwks.json")
def jwks():
    nums = PUB_KEY.public_numbers()
    return jsonify(keys=[{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key-1",
        "n": b64url_uint(nums.n), "e": b64url_uint(nums.e),
    }])


@app.route("/api/user")
def api_user():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_trusting_alg(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    return user_view(payload)


@app.route("/api/admin")
def api_admin():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_trusting_alg(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    if payload.get("role") != "admin":
        return jsonify(error="forbidden — admin only"), 403
    return admin_view(payload)


@app.route("/api/hs256")
def api_hs256():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_hs256_weak(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    if payload.get("role") != "admin":
        return jsonify(page="hs256", role=payload.get("role"), data="standard area"), 200
    return jsonify(page="hs256", role="admin", secret="FLAG{hs256_secret_cracked}")


@app.route("/api/kid")
def api_kid():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_kid(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    if payload.get("role") != "admin":
        return jsonify(page="kid", role=payload.get("role"), data="standard area"), 200
    return jsonify(page="kid", role="admin", secret="FLAG{kid_traversal}")


@app.route("/api/secure")
def api_secure():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_secure(token)
    if not valid:
        return jsonify(error="invalid token (algorithm pinned to RS256)"), 401
    if payload.get("role") != "admin":
        return jsonify(page="secure", role=payload.get("role"), data="standard area"), 200
    return jsonify(page="secure", role="admin", secret="FLAG{should_never_see_this}")


# ── Discoverable surface (for tanuki --discover) ────────────────────────────
# A front-end bundle that references the real API routes in a mix of styles, an
# OpenAPI spec, and one deliberately destructive route that must NOT be scanned
# automatically. None of this changes the existing endpoints' behaviour.
APP_JS = r"""// jwt-demo-lab front-end bundle (exists so passive discovery has real refs).
// These calls are illustrative; the page does not actually execute them.
import axios from "https://cdn.example.com/lib.js";   // external reference

async function loadUser() {
  const r = await fetch("/api/user");                 // fetch() style
  return r.json();
}

function loadAdmin() {
  return axios.get("/api/admin");                      // axios.get style
}

function loadUserById(id) {
  return axios.get(`/api/users/${id}`);               // templated path
}

function deleteAccount() {
  return fetch("/api/account/delete", { method: "DELETE" });  // destructive
}

const xhr = new XMLHttpRequest();
xhr.open("GET", "/api/kid");                           // XHR .open style
xhr.send();
"""

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "jwt-demo-lab", "version": "1.0.0"},
    "paths": {
        "/api/user":   {"get": {"summary": "user home"}},
        "/api/admin":  {"get": {"summary": "admin panel"}},
        "/api/hs256":  {"get": {"summary": "hs256 area"}},
        "/api/kid":    {"get": {"summary": "kid-routed area"}},
        "/api/secure": {"get": {"summary": "secure control"}},
    },
}


@app.route("/static/app.js")
def static_app_js():
    return Response(APP_JS, mimetype="application/javascript")


@app.route("/openapi.json")
def openapi_json():
    return jsonify(OPENAPI_SPEC)


@app.route("/api/account/delete")
def api_account_delete():
    # Same trusts-alg verification as the others, for consistency. It does not
    # actually delete anything — it exists so the destructive-exclusion logic
    # has a real target to skip unless --include-destructive is passed.
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_trusting_alg(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    return jsonify(deleted=True)


# ── Browsable web frontend (session-cookie UI over the same vulnerable verify) ─
# Server-rendered Jinja templates. Identity comes from the `session` cookie's JWT
# via verify_trusting_alg — the SAME trusts-the-alg-header flaw the API uses — so a
# forged token is honoured here too, visibly, which is what makes the browser demo
# work. The token inspector is decode-and-display only (no verification).
def inspect_token(token):
    """Decode-only view of a JWT for the inspector widget — never verifies."""
    if not token:
        return {"present": False}
    try:
        parts = token.split(".")
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {"present": True, "ok": True,
                "alg": header.get("alg", "?"), "typ": header.get("typ", "?"),
                "sub": payload.get("sub", "?"), "role": payload.get("role", "?")}
    except Exception:
        return {"present": True, "ok": False}


def _session_payload():
    """Verify the session-cookie token with the existing trusts-alg routine.
    Returns the payload when the token is 'valid' (including forged alg:none /
    confused HS256 tokens — that is the lab), else None."""
    token = request.cookies.get("session")
    if not token:
        return None
    valid, payload = verify_trusting_alg(token)
    return payload if valid else None


def _is_admin(payload):
    """Admin if the (forged) token claims role=admin or sub=administrator."""
    return bool(payload) and (payload.get("role") == "admin"
                              or payload.get("sub") == "administrator")


@app.context_processor
def _inject_frontend_context():
    # Makes the live token inspector + solved state available to every template.
    return {"inspector": inspect_token(request.cookies.get("session")),
            "lab_state": LAB_STATE}


@app.route("/login-page", methods=["GET", "POST"])
def login_page():
    error = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if WEB_USERS.get(username) == password:
            # issue a normal low-priv RS256 token and carry it in the session cookie
            token = sign_rs256({"sub": username, "role": "user", "iss": "jwt-demo-lab"})
            resp = redirect(url_for("dashboard"))
            resp.set_cookie("session", token, samesite="Lax")
            return resp
        error = "Invalid credentials. Try wiener / peter."
    return render_template("login.html", error=error, username=username)


@app.route("/dashboard")
def dashboard():
    payload = _session_payload()
    if not payload:
        return redirect(url_for("login_page"))
    return render_template("dashboard.html",
                           user=payload.get("sub", "unknown"),
                           role=payload.get("role", "user"),
                           is_admin=_is_admin(payload))


@app.route("/admin-panel")
def admin_panel():
    payload = _session_payload()
    if not payload:
        return redirect(url_for("login_page"))
    if not _is_admin(payload):
        return render_template("forbidden.html",
                               user=payload.get("sub", "unknown"),
                               role=payload.get("role", "user")), 403
    users = [u for u in ADMIN_USERS if u not in LAB_STATE["deleted"]]
    return render_template("admin.html", user=payload.get("sub", "admin"),
                           users=users, win_target=WIN_TARGET)


@app.route("/admin-panel/delete/<username>", methods=["POST"])
def admin_delete(username):
    # Gated by the SAME vulnerable verify — a plain user token can't delete, but a
    # forged admin token can. Deleting the win target flips the solved state.
    payload = _session_payload()
    if not _is_admin(payload):
        return render_template("forbidden.html",
                               user=(payload or {}).get("sub", "anonymous"),
                               role=(payload or {}).get("role", "none")), 403
    if username in ADMIN_USERS and username not in LAB_STATE["deleted"]:
        LAB_STATE["deleted"].append(username)
        if username == WIN_TARGET:
            LAB_STATE["solved"] = True
    return redirect(url_for("admin_panel"))


@app.route("/logout")
def logout():
    resp = redirect(url_for("login_page"))
    resp.delete_cookie("session")
    return resp


@app.route("/_debug/state")
def _debug_state():
    # Test-support (like /_debug/hits): read the lab's solved/deleted state.
    return jsonify(dict(LAB_STATE))


@app.route("/_debug/reset", methods=["POST"])
def _debug_reset():
    # Test-support: reset solved/deleted so web-frontend tests are order-independent.
    LAB_STATE["solved"] = False
    LAB_STATE["deleted"] = []
    return jsonify(ok=True, **LAB_STATE)


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>jwt-demo-lab</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;
      background:#0d1117;color:#c9d1d9;line-height:1.55}
 h1{color:#58a6ff} h2{color:#79c0ff;margin-top:28px;border-bottom:1px solid #21262d;padding-bottom:4px}
 code,pre{background:#161b22;border:1px solid #21262d;border-radius:6px}
 code{padding:2px 6px} pre{padding:12px;overflow-x:auto}
 .vuln{color:#f85149;font-weight:600} .safe{color:#3fb950;font-weight:600}
 table{border-collapse:collapse;width:100%;margin:12px 0}
 td,th{border:1px solid #21262d;padding:8px 10px;text-align:left}
 .warn{background:#2d1a1a;border:1px solid #f85149;padding:10px 14px;border-radius:6px}
</style></head><body>
<h1>jwt-demo-lab</h1>
<p class="warn">⚠ Deliberately vulnerable. Localhost only. Do not deploy.</p>
<p>A target for testing <code>tanuki</code>. Each endpoint demonstrates one JWT
failure mode, plus one correctly-secured control.</p>
<p><a href="/login-page" style="display:inline-block;background:#1f6feb;color:#fff;
   padding:10px 16px;border-radius:8px;font-weight:600;text-decoration:none">
   ▶ Open the browsable web app</a>
   &nbsp;<span style="color:#8b949e">login → dashboard → forge an admin token → admin panel</span></p>

<h2>Get a token</h2>
<pre># low-priv RS256 token (role:user)
curl -s -X POST http://127.0.0.1:5000/login \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}'

# HS256 token (weak secret)
curl -s -X POST http://127.0.0.1:5000/login-hs256 \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}'

# kid-based token
curl -s -X POST http://127.0.0.1:5000/login-kid \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}'</pre>

<h2>Endpoints</h2>
<table>
<tr><th>Endpoint</th><th>Verification</th><th>Breaks via</th></tr>
<tr><td><code>/api/user</code></td><td>trusts alg header</td><td class="vuln">alg:none, key confusion</td></tr>
<tr><td><code>/api/admin</code></td><td>trusts alg header, role:admin gate</td><td class="vuln">access bypass (403→200)</td></tr>
<tr><td><code>/api/hs256</code></td><td>HS256 weak secret</td><td class="vuln">secret cracking</td></tr>
<tr><td><code>/api/kid</code></td><td>kid picks the key</td><td class="vuln">kid path traversal</td></tr>
<tr><td><code>/api/secure</code></td><td>RS256 pinned (PyJWT)</td><td class="safe">nothing — control</td></tr>
</table>

<h2>Attack it</h2>
<pre># grab a token
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/login \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)

# single endpoint — auto-discovers JWKS, forges, replays
python3 tanuki.py "$TOKEN" -u http://127.0.0.1:5000/api/admin --http

# scan every endpoint at once -> attack/endpoint matrix
python3 tanuki.py "$TOKEN" --scan targets.txt --http \\
  --pubkey keys/public.pem</pre>
<p>The public key is served at
<code>/.well-known/jwks.json</code> and written to <code>keys/public.pem</code>.</p>
<script src="/static/app.js"></script>
</body></html>"""


# ── "No exposed key" scenario — a SEPARATE app on its own origin ──────────────
# tanuki's JWKS auto-discovery is origin-wide: it returns the first RSA key it
# finds at the origin, regardless of the token's kid. So an endpoint on the main
# lab (which serves /.well-known/jwks.json) could never force key recovery — the
# tool would just use the exposed main key. To make JWKS discovery genuinely FAIL
# (so derivation runs), this scenario is a distinct Flask app with NO jwks route,
# meant to run on its own port (default 5001). It reuses the SAME vulnerable verify
# pattern, bound to the hidden recovery key.
noexposed_app = Flask(__name__)


@noexposed_app.route("/login-noexposedkey", methods=["POST"])
def login_noexposedkey():
    """Issue an RS256 token signed with the hidden recovery key. Each call embeds a
    fresh iat/exp + nonce, so two sequential logins give two DISTINCT signatures
    over the SAME key — exactly what the GCD-of-signatures recovery needs."""
    data = request.get_json(silent=True) or {}
    user = data.get("user", "wiener")
    role = "admin" if user == "administrator" else "user"
    now = int(time.time())
    token = sign_rs256_recovery({
        "sub": user, "role": role, "iss": "jwt-demo-lab-noexposedkey",
        "iat": now, "exp": now + 3600, "jti": "%08x" % next(_REC_NONCE),
    })
    return jsonify(token=token, user=user, role=role)


@noexposed_app.route("/api/noexposedkey")
def api_noexposedkey():
    token = get_token()
    if not token:
        return jsonify(error="no token"), 401
    valid, payload = verify_trusting_alg_recovery(token)
    if not valid:
        return jsonify(error="invalid token"), 401
    if payload.get("role") != "admin" and payload.get("sub") != "administrator":
        return jsonify(error="forbidden — admin only"), 403
    return jsonify(page="noexposedkey", role="admin",
                   secret="FLAG{no_exposed_key_recovered}")


@noexposed_app.route("/")
def noexposed_index():
    return Response(NOEXPOSED_INDEX_HTML, mimetype="text/html")


NOEXPOSED_INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>jwt-demo-lab — no exposed key</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;
      background:#0d1117;color:#c9d1d9;line-height:1.55}
 h1{color:#58a6ff} code,pre{background:#161b22;border:1px solid #21262d;border-radius:6px}
 code{padding:2px 6px} pre{padding:12px;overflow-x:auto}
 .warn{background:#2d1a1a;border:1px solid #f85149;padding:10px 14px;border-radius:6px}
</style></head><body>
<h1>jwt-demo-lab — algorithm confusion, no exposed key</h1>
<p class="warn">⚠ Deliberately vulnerable. Localhost only. Do not deploy.</p>
<p>This endpoint is signed with an RSA key that is <strong>never served</strong> —
there is no JWKS here. To run RS256→HS256 confusion you must first
<strong>recover</strong> the public key from two signatures.</p>
<pre># two tokens from the hidden key (different each call)
T1=$(curl -s -X POST http://127.0.0.1:5001/login-noexposedkey \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)
T2=$(curl -s -X POST http://127.0.0.1:5001/login-noexposedkey \\
  -H 'Content-Type: application/json' -d '{"user":"wiener"}' | jq -r .token)

# recover the key from the two signatures, forge, bypass
tanuki "$T1" --derive-key "$T2" \\
  -u http://127.0.0.1:5001/api/noexposedkey \\
  --cookie session --claims role=admin --http</pre>
<p>JWKS discovery fails here (by design) → tanuki derives the modulus → forges →
<code>403 → 200</code>.</p>
</body></html>"""


def _print_banner():
    print("=" * 60)
    print(" jwt-demo-lab  —  DELIBERATELY VULNERABLE  —  localhost only")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "noexposedkey":
        # the "no exposed key" scenario on its own port (no JWKS served here)
        _print_banner()
        print(" scenario     : algorithm confusion with NO exposed public key")
        print(f" hidden key   : {REC_PRIV_PATH}  (never served)")
        print(" index        : http://127.0.0.1:5001/")
        print(" login        : POST http://127.0.0.1:5001/login-noexposedkey")
        print(" endpoint     : http://127.0.0.1:5001/api/noexposedkey")
        print("=" * 60)
        noexposed_app.run(host="127.0.0.1", port=5001, debug=False)
    else:
        _print_banner()
        print(f" HS256 secret : {HS256_SECRET}  (crackable)")
        print(f" RSA pubkey   : {PUB_PATH}")
        print(" index        : http://127.0.0.1:5000/")
        print(" web app      : http://127.0.0.1:5000/login-page   (wiener / peter)")
        print(" no-key lab   : run  'python lab/app.py noexposedkey'  (port 5001)")
        print("=" * 60)
        app.run(host="127.0.0.1", port=5000, debug=False)
