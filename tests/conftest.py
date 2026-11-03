"""Shared pytest fixtures for the tanuki test-suite.

The headline fixture is ``lab_server``: it boots the deliberately-vulnerable
Flask lab in a subprocess on a random free port, waits until it answers, yields
the base URL, and tears it down afterwards (session-scoped — one lab per run).
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB_LAUNCHER = Path(__file__).resolve().parent / "_lab_server.py"
WORDLIST = Path(__file__).resolve().parent / "data" / "wordlist.txt"

# The lab's known-weak values (see lab/app.py). Tests assert against these.
KNOWN_HS256_SECRET = "secret123"


# ── helpers available to tests without importing conftest directly ────────────
def _free_port():
    """Ask the OS for an unused TCP port, then release it for the child to bind."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until_up(base_url, timeout=20.0):
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(base_url + "/", timeout=2)
            if r.status_code == 200:
                return True
        except Exception as e:  # not up yet
            last_err = e
        time.sleep(0.15)
    raise RuntimeError(f"lab did not come up at {base_url}: {last_err}")


# ── session-scoped lab servers ────────────────────────────────────────────────
@pytest.fixture(scope="session")
def _lab_keys():
    """Create both lab keypairs on disk (in THIS process) before any server starts.

    The main lab and the no-exposed-key lab run as separate subprocesses that both
    import lab.app; importing it here first means they LOAD identical keys instead
    of racing to create them — so the recovery key the tool recovers matches the
    key on disk."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import lab.app  # noqa: F401  (import triggers load_or_create_* for both keys)
    return True


def _start_lab(app_name="app"):
    """Spawn a lab app subprocess on a free port; return (proc, base_url)."""
    port = _free_port()
    host = "127.0.0.1"
    base_url = f"http://{host}:{port}"
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, str(LAB_LAUNCHER), host, str(port), app_name],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
    )
    try:
        _wait_until_up(base_url)
    except RuntimeError:
        proc.terminate()
        out = ""
        try:
            out = proc.communicate(timeout=5)[0] or ""
        except Exception:
            pass
        raise RuntimeError(f"lab ({app_name}) failed to start.\n--- output ---\n{out}")
    return proc, base_url


def _stop_lab(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def lab_server(_lab_keys):
    """Start the Flask lab on a random free port; yield its base URL."""
    proc, base_url = _start_lab("app")
    try:
        yield base_url
    finally:
        _stop_lab(proc)


@pytest.fixture(scope="session")
def base_url(lab_server):
    return lab_server


@pytest.fixture(scope="session")
def noexposed_server(_lab_keys):
    """Start the 'no exposed key' lab (noexposed_app) on its own free port — it
    serves NO JWKS, so tanuki must recover the key from two signatures."""
    proc, base_url = _start_lab("noexposed_app")
    try:
        yield base_url
    finally:
        _stop_lab(proc)


@pytest.fixture(scope="session")
def noexposed_base_url(noexposed_server):
    return noexposed_server


@pytest.fixture(scope="session")
def public_key_pem_path(lab_server):
    """Path to the RSA public key the lab generated on start-up."""
    pub = REPO_ROOT / "lab" / "keys" / "public.pem"
    assert pub.exists(), f"lab did not generate {pub}"
    return pub


@pytest.fixture(scope="session")
def public_key_pem(public_key_pem_path):
    return public_key_pem_path.read_text()


@pytest.fixture(scope="session")
def wordlist_path():
    """Tiny wordlist fixture; contains the lab's known HS256 secret."""
    assert WORDLIST.exists()
    return str(WORDLIST)


@pytest.fixture(scope="session")
def known_secret():
    return KNOWN_HS256_SECRET


# ── token helpers ─────────────────────────────────────────────────────────────
def _login(base_url, route, user="wiener"):
    r = requests.post(base_url + route, json={"user": user}, timeout=5)
    r.raise_for_status()
    return r.json()["token"]


@pytest.fixture
def rs256_token(base_url):
    """A low-privilege RS256 token (role:user) from /login."""
    return _login(base_url, "/login", "wiener")


@pytest.fixture
def hs256_token(base_url):
    """A low-privilege HS256 token (weak secret) from /login-hs256."""
    return _login(base_url, "/login-hs256", "wiener")


@pytest.fixture
def kid_token(base_url):
    """A low-privilege kid-based HS256 token from /login-kid."""
    return _login(base_url, "/login-kid", "wiener")


@pytest.fixture
def login():
    """Return a callable login(base_url, route, user) for ad-hoc token grabs."""
    return _login
