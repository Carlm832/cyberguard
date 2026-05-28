import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

smtp_host = os.getenv("SMTP_HOST")
smtp_port = int(os.getenv("SMTP_PORT", "587"))
smtp_user = os.getenv("SMTP_USER")
smtp_password = os.getenv("SMTP_PASSWORD")
smtp_from = os.getenv("SMTP_FROM")

print(f"SMTP Host: {smtp_host}")
print(f"SMTP Port: {smtp_port}")
print(f"SMTP User: {smtp_user}")
print(f"SMTP From: {smtp_from}")

msg = MIMEText("This is a test email from CyberGuard diagnostics.")
msg["Subject"] = "CyberGuard SMTP Test"
msg["From"] = f"CyberGuard <{smtp_from}>"
msg["To"] = smtp_from  # Send to self

try:
    print("Connecting to server...")
    server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
    print("Sending EHLO...")
    server.ehlo()
    print("Starting TLS...")
    server.starttls()
    print("Sending EHLO again...")
    server.ehlo()
    print("Logging in...")
    server.login(smtp_user, smtp_password)
    print("Sending message...")
    server.send_message(msg)
    print("Quitting server...")
    server.quit()
    print("Email sent successfully!")
except Exception as e:
    print(f"Error during SMTP send: {e}")
