from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).parent.parent / "lab"
sys.path.insert(0, str(LAB_DIR))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def lab_server():
    """Runs the vulnerable lab Flask app in a background thread on a free local port,
    for fast in-process integration tests (no Docker required).
    """
    import app as lab_app  # the lab's app.py

    port = _free_port()
    server_thread = threading.Thread(
        target=lambda: lab_app.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    import requests
    for _ in range(50):
        try:
            requests.get(f"{base_url}/health", timeout=0.5)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    else:
        pytest.fail("Lab server did not start in time")

    yield base_url


@pytest.fixture()
def lab_tokens(lab_server):
    import requests

    # Reset in-memory lab state before each test that needs fresh tokens, so a
    # successful exploit in one test (e.g. privilege escalation mutating a user's
    # role) can't leak into and skew a later, unrelated test.
    requests.post(f"{lab_server}/debug/reset", timeout=2)

    creds = {
        "victim": ("victim@example.com", "victim-pass"),
        "attacker": ("attacker@example.com", "attacker-pass"),
        "admin": ("admin@example.com", "admin-pass"),
    }
    tokens = {}
    for name, (email, pw) in creds.items():
        r = requests.post(f"{lab_server}/login", json={"username": email, "password": pw})
        r.raise_for_status()
        tokens[name] = r.json()["token"]
    return tokens
