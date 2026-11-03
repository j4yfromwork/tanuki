"""Launcher used by the test fixtures to run a lab app in a subprocess.

Run as:  python tests/_lab_server.py <host> <port> [app_name]

<app_name> selects which Flask app object in lab.app to serve (default "app"; use
"noexposed_app" for the no-exposed-key scenario). Uses werkzeug's plain WSGI
server rather than app.run(), so the bind port is parameterised without touching
lab/app.py, and shutdown is a clean process terminate(). The app is imported
unchanged.
"""
import os
import sys

# make the repo root importable so `lab.app` resolves regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.serving import make_server  # noqa: E402

import lab.app as lab_app  # noqa: E402

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    app_name = sys.argv[3] if len(sys.argv) > 3 else "app"
    make_server(host, port, getattr(lab_app, app_name)).serve_forever()
