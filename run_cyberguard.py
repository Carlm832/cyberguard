"""
CyberGuard desktop launcher entrypoint for PyInstaller builds.
Starts the FastAPI app and opens the web UI in the default browser.
"""

import os
import threading
import time
import webbrowser

import uvicorn

from api.index import app


def _open_browser(url: str, delay_seconds: float = 1.2) -> None:
    time.sleep(delay_seconds)
    webbrowser.open(url)


def main() -> None:
    host = os.getenv("CYBERGUARD_HOST", "127.0.0.1")
    port = int(os.getenv("CYBERGUARD_PORT", "8000"))
    url = f"http://{host}:{port}"

    threading.Thread(target=_open_browser, args=(url,), daemon=True).start()
    uvicorn.run(app, host=host, port=port, reload=False, log_level="info")


if __name__ == "__main__":
    main()

