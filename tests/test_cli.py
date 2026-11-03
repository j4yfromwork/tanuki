"""End-to-end CLI tests — one per replay mode — driving `python -m tanuki`.

These cover the actual command-line entry point and argument plumbing (not just
the imported functions): single URL (-u), request file (-r), and scan (--scan).
"""
import subprocess
import sys
from pathlib import Path

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


def test_cli_single_url_mode(base_url, rs256_token):
    out = _run_cli(
        [rs256_token, "-u", base_url + "/api/admin", "--http", "--no-crack", "-q", "--no-color"]
    )
    assert "ACCESS BYPASS" in out, out[-2000:]


def test_cli_request_file_mode(base_url, rs256_token, public_key_pem_path, tmp_path):
    host = base_url.split("://", 1)[1]  # 127.0.0.1:PORT
    req = tmp_path / "admin_req.txt"
    req.write_text(
        "GET /api/admin HTTP/1.1\n"
        f"Host: {host}\n"
        f"Authorization: Bearer {rs256_token}\n"
        "Accept: application/json\n"
        "\n"
    )
    out = _run_cli(
        [
            "-r", str(req),
            "--http",
            "--pubkey", str(public_key_pem_path),
            "--no-crack", "-q", "--no-color",
        ]
    )
    # token is auto-extracted from the request file and replayed in place
    assert "extracted JWT" in out
    assert "ACCESS BYPASS" in out, out[-2000:]


def test_cli_scan_mode(base_url, rs256_token, public_key_pem_path, tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "\n".join(
            base_url + "/api/" + ep for ep in ("user", "admin", "hs256", "kid", "secure")
        )
        + "\n"
    )
    out = _run_cli(
        [
            rs256_token,
            "--scan", str(targets),
            "--http",
            "--pubkey", str(public_key_pem_path),
            "--no-crack", "-q", "--no-color",
        ]
    )
    assert "Attack / Endpoint Matrix" in out, out[-3000:]
    lines = out.splitlines()
    # admin row shows a VULN cell
    assert any("/api/admin" in ln and "VULN" in ln for ln in lines), out[-3000:]
    # user row shows a VULN cell
    assert any("/api/user" in ln and "VULN" in ln for ln in lines), out[-3000:]
    # the secure control never shows VULN on any line mentioning it
    assert not any("/api/secure" in ln and "VULN" in ln for ln in lines), out[-3000:]
