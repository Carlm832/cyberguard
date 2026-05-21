"""
CyberGuard desktop launcher entrypoint for PyInstaller builds.
Starts the FastAPI app and hosts the UI in a native desktop webview window.
"""

import os
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen

import uvicorn
import webview

from api.index import app


def _wait_for_server(url: str, timeout_seconds: float = 15.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1.5):
                return
        except URLError:
            time.sleep(0.2)
    raise RuntimeError(f"CyberGuard server did not start within {timeout_seconds} seconds: {url}")


def _run_server(host: str, port: int) -> None:
    uvicorn.run(app, host=host, port=port, reload=False, log_level="info")


def main() -> None:
    host = os.getenv("CYBERGUARD_HOST", "127.0.0.1")
    port = int(os.getenv("CYBERGUARD_PORT", "8000"))
    url = f"http://{host}:{port}"

    server_thread = threading.Thread(target=_run_server, args=(host, port), daemon=True)
    server_thread.start()
    _wait_for_server(url)

    webview.create_window("CyberGuard", url, min_size=(1100, 760))
    webview.start()


if __name__ == "__main__":
    main()
