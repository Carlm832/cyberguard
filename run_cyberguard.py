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
import webbrowser

from api.index import app


class CyberGuardAPI:
    def save_file(self, content: str, default_filename: str, file_type: str = "text") -> bool:
        """
        Native save dialog triggered from JavaScript.
        """
        import base64
        try:
            if file_type == 'html':
                file_types = ('HTML Files (*.html)', 'All files (*.*)')
            elif file_type == 'pdf':
                file_types = ('PDF Files (*.pdf)', 'All files (*.*)')
            else:
                file_types = ('Text Files (*.txt)', 'All files (*.*)')
                
            save_filename = webview.windows[0].create_file_dialog(
                webview.SAVE_DIALOG, directory='', save_filename=default_filename, file_types=file_types
            )
            
            if save_filename:
                if file_type == 'pdf':
                    # Content arrives as raw base64 string from FileReader
                    with open(save_filename[0], 'wb') as f:
                        f.write(base64.b64decode(content))
                else:
                    with open(save_filename[0], 'w', encoding='utf-8') as f:
                        f.write(content)
                return True
            return False
        except Exception as e:
            print(f"Error saving file: {e}")
            return False


    def open_external(self, url: str) -> None:
        """
        Opens a URL in the user's default external browser/client (like mailto links).
        """
        webbrowser.open(url)


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
    app_url = f"http://{host}:{port}/app"

    server_thread = threading.Thread(target=_run_server, args=(host, port), daemon=True)
    server_thread.start()
    _wait_for_server(url)

    api = CyberGuardAPI()
    webview.create_window("CyberGuard", app_url, min_size=(1100, 760), js_api=api)
    webview.start()


if __name__ == "__main__":
    main()
