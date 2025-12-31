from flask import Flask, request, jsonify
import subprocess
import datetime
import os
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

# ===================== CONFIG =====================

# Firewall command
IPTABLES_BLOCK_CMD = "iptables -A INPUT -s {} -j DROP"

# Incident reports folder
INCIDENT_DIR = "incident_reports"
os.makedirs(INCIDENT_DIR, exist_ok=True)

# Email configuration (USE APP PASSWORD)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_FROM = "soc.alerts@gmail.com"
EMAIL_TO = "soc.team@gmail.com"
SMTP_USER = "soc.alerts@gmail.com"
SMTP_PASS = "YOUR_APP_PASSWORD"  # Gmail app password

# =================================================


def block_ip(ip):
    """Block attacker IP using iptables"""
    subprocess.run(IPTABLES_BLOCK_CMD.format(ip), shell=True)


def send_email(ip, attack_type, host, count):
    """Send SOC alert email"""
    body = f"""
SECURITY INCIDENT DETECTED

Attack Type : {attack_type}
Source IP  : {ip}
Target Host: {host}
Attempts   : {count}
Action     : IP BLOCKED
Time       : {datetime.datetime.now()}
"""
    msg = MIMEText(body)
    msg["Subject"] = f"[HIGH] {attack_type} Blocked"
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USER, SMTP_PASS)
    server.send_message(msg)
    server.quit()


def create_incident_report(ip, attack_type, host, count):
    """Generate incident report"""
    incident_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{INCIDENT_DIR}/incident_{incident_id}.txt"

    with open(filename, "w") as f:
        f.write("=== INCIDENT REPORT ===\n")
        f.write(f"Incident ID     : {incident_id}\n")
        f.write(f"Attack Type     : {attack_type}\n")
        f.write("MITRE ATT&CK    : T1110 (Brute Force)\n")
        f.write(f"Source IP       : {ip}\n")
        f.write(f"Target Host     : {host}\n")
        f.write(f"Attempts        : {count}\n")
        f.write(f"Detection Time  : {datetime.datetime.now()}\n")
        f.write("Response        : IP Blocked via iptables\n")
        f.write("Status          : Contained\n")

    return filename


# ===================== ROUTES =====================

@app.route("/", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return "SOC Automation is running", 200


@app.route("/splunk-alert", methods=["POST"])
def splunk_alert():
    """Receive Splunk webhook alert"""
    data = request.get_json()

    attack_type = data.get("attack_type", "Unknown Attack")
    src_ip = data.get("src_ip")
    host = data.get("host", "unknown")
    count = data.get("count", "N/A")

    if not src_ip:
        return jsonify({"status": "error", "message": "No IP received"}), 400

    block_ip(src_ip)
    send_email(src_ip, attack_type, host, count)
    report = create_incident_report(src_ip, attack_type, host, count)

    return jsonify({
        "status": "success",
        "blocked_ip": src_ip,
        "incident_report": report
    }), 200


# ===================== MAIN =====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

