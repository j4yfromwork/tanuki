"""Passive endpoint discovery (--discover / --import / --discover-only).

Exercises the discovery pipeline against the lab's discoverable surface (a JS
bundle referenced from the index, an OpenAPI spec, a templated route, a
destructive route, and an external reference), plus end-to-end CLI runs.
"""
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

from tanuki import (
    discover_endpoints,
    import_endpoints,
    surface_scan_targets,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(args, timeout=180):
    proc = subprocess.run(
        [sys.executable, "-m", "tanuki", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.stdout + proc.stderr


def _paths(urls):
    return {urlparse(u).path for u in urls}


# ── discovery finds JS-referenced + OpenAPI-listed routes (the union) ──────────
def test_discovery_finds_js_and_openapi_routes(base_url):
    s = discover_endpoints(base_url)
    scan = _paths(s.scan_plain) | _paths(s.scan_templated)
    # from the JS bundle
    assert "/api/user" in scan      # fetch("/api/user")
    assert "/api/admin" in scan     # axios.get("/api/admin")
    assert "/api/kid" in scan       # xhr.open("GET", "/api/kid")
    # from the OpenAPI spec (union)
    for p in ("/api/user", "/api/admin", "/api/hs256", "/api/kid", "/api/secure"):
        assert p in scan, "%s missing from discovered surface" % p


# ── templated route normalised + flagged ──────────────────────────────────────
def test_templated_route_normalised_and_flagged(base_url):
    s = discover_endpoints(base_url)
    assert "/api/users/1" in _paths(s.scan_templated)
    assert (base_url + "/api/users/1") in s.scan_templated
    # the raw ${id} form must not survive anywhere
    allurls = s.scan_plain + s.scan_templated + [u for u, _ in s.destructive]
    assert not any("${" in u or "{id}" in u for u in allurls)


# ── external reference listed, never scanned ──────────────────────────────────
def test_external_reference_not_scanned(base_url):
    s = discover_endpoints(base_url)
    assert any("cdn.example.com" in u for u in s.external)
    scan = s.scan_plain + s.scan_templated
    assert not any("cdn.example.com" in u for u in scan)


# ── destructive route excluded by default, included on request ────────────────
def test_destructive_excluded_by_default(base_url):
    s = discover_endpoints(base_url)
    dest_paths = _paths(u for u, _ in s.destructive)
    assert "/api/account/delete" in dest_paths

    default_targets = surface_scan_targets(s)
    assert not any("/api/account/delete" in u for u in default_targets)

    with_dest = surface_scan_targets(s, include_destructive=True)
    assert any("/api/account/delete" in u for u in with_dest)


# ── --import reuses the same normalise/filter/safety pipeline ──────────────────
def test_import_merges_and_filters(base_url, tmp_path):
    f = tmp_path / "endpoints.txt"
    f.write_text(
        "# exported from some other tool\n"
        "/api/user\n"
        "/api/orders/{id}\n"          # templated -> /api/orders/1
        "/api/session/logout\n"       # destructive keyword
        "https://evil.com/api/x\n"    # off-origin -> external, not scanned
        "/static/bundle.js\n"         # static asset -> dropped
        "\n"
    )
    s = import_endpoints(str(f), base_url)
    scan = s.scan_plain + s.scan_templated

    assert "/api/user" in _paths(scan)
    assert "/api/orders/1" in _paths(s.scan_templated)
    # destructive filtered out of scan, listed under destructive
    assert not any("logout" in u for u in scan)
    assert any("logout" in u for u, _ in s.destructive)
    # external filtered out of scan, listed under external
    assert any("evil.com" in u for u in s.external)
    assert not any("evil.com" in u for u in scan)
    # static asset dropped entirely
    assert not any("bundle.js" in u for u in scan)


# ── end-to-end: --discover yields the normal attack/endpoint matrix ────────────
def test_discover_e2e_scan_matrix(base_url, rs256_token, public_key_pem_path):
    out = _run_cli(
        [
            rs256_token,
            "--discover", base_url,
            "--yes",
            "--pubkey", str(public_key_pem_path),
            "--no-crack", "-q", "--no-color",
        ]
    )
    assert "Passive Endpoint Discovery" in out, out[-3000:]
    assert "Attack / Endpoint Matrix" in out, out[-3000:]
    lines = out.splitlines()
    assert any("/api/user" in ln and "VULN" in ln for ln in lines), out[-3000:]
    assert any("/api/admin" in ln and "VULN" in ln for ln in lines), out[-3000:]
    assert not any("/api/secure" in ln and "VULN" in ln for ln in lines), out[-3000:]
    # the destructive route is surfaced but excluded from the scan
    assert any("/api/account/delete" in ln and "destructive" in ln.lower()
               for ln in lines) or any(
        "/api/account/delete" in ln and "delete'" in ln for ln in lines), out[-3000:]


# ── --discover-only is recon: prints the surface, sends no attack requests ─────
def test_discover_only_sends_no_attack_requests(base_url):
    attack_eps = ("/api/user", "/api/admin", "/api/hs256", "/api/kid",
                  "/api/secure", "/api/account/delete")

    def hits():
        return requests.get(base_url + "/_debug/hits", timeout=5).json()

    before = hits()
    # no token at all — recon mode must not require one
    out = _run_cli(["--discover", base_url, "--discover-only", "-q", "--no-color"])
    after = hits()

    # the grouped surface is printed ...
    assert "Passive Endpoint Discovery" in out
    assert "will scan" in out
    # ... and nothing was forged or scanned
    assert "Attack / Endpoint Matrix" not in out
    assert "Multi-Endpoint Scan" not in out
    for ep in attack_eps:
        assert after.get(ep, 0) == before.get(ep, 0), \
            "recon hit attack endpoint %s" % ep
