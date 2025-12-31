from flask import Flask, request, jsonify
import subprocess
import datetime
import smtplib
from email.message import EmailMessage
import os

app = Flask(__name__)

# ===================== CONFIG =====================

# 🔐 EMAIL CONFIG (USE APP PASSWORD)
EMAIL_SENDER = "subhamsahoo2306@gmail.com"
EMAIL_PASSWORD = "PASTE_YOUR_NEW_APP_PASSWORD_HERE"
EMAIL_RECEIVER = "subhamsahoo2306@gmail.com"

# Incident report file
REPORT_FILE = "/home/kali/Desktop/soc/incident_reports/incident_reports.log"

# =================================================


def block_ip(ip):
    """
    Block attacker IP immediately
    and auto-unblock after 24 hours
    """
    try:
        # 🔒 Block IP (insert at top)
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        print(f"[+] IP BLOCKED: {ip}")

        # ⏱ Auto-unblock after 24 hours
        unblock_cmd = f"iptables -D INPUT -s {ip} -j DROP"
        subprocess.run(
            ["bash", "-c", f"echo '{unblock_cmd}' | at now + 24 hours"],
            check=True
        )
        print(f"[+] Auto-unblock scheduled (24h) for IP: {ip}")

    except subprocess.CalledProcessError as e:
        print(f"[!] Firewall error for IP {ip}: {e}")


def send_email(ip, attack_type, user):
    """Send SOC alert email"""
    try:
        msg = EmailMessage()
        msg["Subject"] = "🚨 SOC ALERT: SSH Brute Force Detected"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER

        msg.set_content(f"""
SOC SECURITY ALERT 🚨

Attack Type : {attack_type}
Attacker IP : {ip}
Target User : {user}
Action Taken: IP BLOCKED (24h)
Time        : {datetime.datetime.now()}
MITRE      : T1110 (Brute Force)
""")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)

        print("[+] Email alert sent successfully")

    except Exception as e:
        print(f"[!] Email error: {e}")


def write_incident_report(ip, attack_type, user):
    """Write incident report to file"""
    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)

    with open(REPORT_FILE, "a") as f:
        f.write(
            f"\n==============================\n"
            f"Time        : {datetime.datetime.now()}\n"
            f"Attack Type : {attack_type}\n"
            f"Attacker IP : {ip}\n"
            f"User        : {user}\n"
            f"Action      : IP BLOCKED (24h)\n"
            f"MITRE       : T1110\n"
            f"==============================\n"
        )

    print("[+] Incident report written")


@app.route("/", methods=["GET"])
def home():
    return "SOC Automation is running", 200


@app.route("/splunk-alert", methods=["POST"])
def splunk_alert():
    """Endpoint triggered by Splunk webhook"""
    data = request.get_json()

    attacker_ip = data.get("attacker_ip")
    attack_type = data.get("attack_type", "SSH Brute Force")
    user = data.get("user", "unknown")

    if not attacker_ip:
        return jsonify({"error": "No attacker IP received"}), 400

    print(f"[+] ALERT RECEIVED | Attacker IP: {attacker_ip}")

    # 1️⃣ Block IP
    block_ip(attacker_ip)

    # 2️⃣ Send Email
    send_email(attacker_ip, attack_type, user)

    # 3️⃣ Write Incident Report
    write_incident_report(attacker_ip, attack_type, user)

    return jsonify({
        "status": "success",
        "blocked_ip": attacker_ip
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

