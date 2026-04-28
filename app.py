import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

from logic import EmailExpert, FuzzyRiskEngine, PasswordExpert, SecurityChatExpert

HOST = "0.0.0.0"
PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

email_expert = EmailExpert()
pwd_expert = PasswordExpert()
fuzzy_engine = FuzzyRiskEngine()
chat_expert = SecurityChatExpert()


class CyberGuardHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path, content_type="text/plain; charset=utf-8"):
        if not file_path.exists() or not file_path.is_file():
            self.send_error(404)
            return

        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _parse_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        if self.path == "/":
            self._send_file(TEMPLATES_DIR / "index.html", "text/html; charset=utf-8")
            return

        if self.path.startswith("/static/"):
            rel = unquote(self.path[len("/static/"):]).replace("..", "")
            file_path = STATIC_DIR / rel

            if file_path.suffix == ".css":
                ctype = "text/css; charset=utf-8"
            elif file_path.suffix == ".js":
                ctype = "application/javascript; charset=utf-8"
            else:
                ctype = "application/octet-stream"

            self._send_file(file_path, ctype)
            return

        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/assess":
            payload = self._parse_json_body()
            email_factors = {
                "unknown_sender": bool(payload.get("unknown_sender", False)),
                "malicious_links": bool(payload.get("malicious_links", False)),
                "urgency": bool(payload.get("urgency", False)),
                "sensitive_info_request": bool(payload.get("sensitive_info_request", False)),
            }

            password = (payload.get("password") or "").strip()
            pwd_strength = pwd_expert.evaluate(password) if password else None
            email_score = email_expert.evaluate(email_factors)
            total_risk_val = fuzzy_engine.compute_total_risk(email_score, pwd_strength)
            risk_label = fuzzy_engine.get_risk_label(total_risk_val)
            recommendations = fuzzy_engine.get_recommendations(email_factors, pwd_strength)

            self._send_json(
                {
                    "email_risk": email_score,
                    "password_strength": pwd_strength,
                    "total_risk": total_risk_val,
                    "risk_label": risk_label,
                    "recommendations": recommendations,
                }
            )
            return

        if self.path == "/api/chat":
            payload = self._parse_json_body()
            question = payload.get("question", "")
            result = chat_expert.answer_question(question)
            self._send_json(result)
            return

        self.send_error(404)


def run_server():
    httpd = HTTPServer((HOST, PORT), CyberGuardHandler)
    print(f"CyberGuard server running at http://localhost:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
