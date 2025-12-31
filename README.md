# SIEM-Splunk
# 🔐 SOC Automation with Splunk SIEM  
### SSH Brute Force Detection | Geo-IP Mapping | Automated Response


## 📌 Project Overview

This project demonstrates a **real-world Security Operations Center (SOC) workflow** using **Splunk Enterprise (SIEM)** to detect, analyze, visualize, and respond to **SSH brute-force attacks**.

The system ingests Linux authentication logs, detects suspicious activity, enriches attacker IPs with Geo-IP data, visualizes attacks on a SOC dashboard, and automates response actions such as firewall blocking, alerting, and incident reporting.


## 🎯 Key Features

- Real-time SSH brute-force detection  
- Linux log ingestion into Splunk SIEM  
- Attacker IP analysis and aggregation  
- Geo-IP enrichment (Country, City, Latitude, Longitude)  
- SOC Dashboard with:
  - 📊 Top Attacker IPs (Bar Chart)
  - 📈 Attack Timeline (Line Chart)
  - 🌍 Global Attacker Location Map (Geo-IP)
- Severity classification (Low / Medium / High)  
- Automated firewall blocking (iptables)  
- Auto-unblock attacker IP after 24 hours  
- MITRE ATT&CK mapping (T1110 – Brute Force)

## 🛠️ Technologies Used

- Splunk Enterprise (SIEM)
- SPL (Search Processing Language)
- Linux (Kali Linux / Ubuntu)
- Python (Automation & SOAR)
- iptables (Firewall)
- Geo-IP Enrichment
- MITRE ATT&CK Framework

## 📂 Project Structure
soc/
├── log_collector.py # Parses SSH logs and creates SOC events
├── soc_webhook.py # SOAR automation (block IP, email, reports)
├── incident_reports/
└── incident_reports.log

1️⃣ Download Splunk
Download Splunk Enterprise (Free): https://www.splunk.com/en_us/download/splunk-enterprise.html

2️⃣ Install Splunk
sudo dpkg -i splunk-*.deb

3️⃣ Start Splunk
sudo /opt/splunk/bin/splunk start
Access Splunk Web: http://127.0.0.1:8000
Step 2: Configure Splunk (SIEM Setup)

Create Index
Go to Settings → Indexes
Create a new index:
Name: linux
Configure Data Input
Go to Settings → Data Inputs → Files & Directories
Add file to monitor: /var/log/soc_events.log
Set:
Index: linux
Sourcetype: soc_events

Step 3: Generate SOC Events from SSH Logs
(log_collector.py): This script monitors /var/log/auth.log and converts failed SSH logins into SOC events.

Run as root:
# sudo python3 log_collector.py
Example generated event: attack_type=SSH_Brute_Force attacker_ip=192.168.150.146 user=testuser

Step 4: Detection Logic in Splunk (SPL)
🔍 Detect Attacker IPs
index=linux sourcetype=soc_events
| stats count by attacker_ip

🔍 Attack Timeline
index=linux sourcetype=soc_events
| timechart count

Step 5: SOC Dashboard Creation
Go to Dashboards → Create New Dashboard
Choose Dashboard Studio
Panels Included:
Top Attacker IPs (Bar Chart)
Attacks Over Time (Line Chart)
Geo-IP Attack Map
Severity Classification Table
MITRE ATT&CK Panel

Step 6: Geo-IP Mapping
Geo-IP SPL Query
**index=linux sourcetype=soc_events
| iplocation attacker_ip
| stats count as attempts by attacker_ip Country City lat lon**

⚠️ Note:
Private IPs (192.168.x.x) cannot be geolocated.
For lab/demo purposes, public IP mapping is used.

Step 8: Automated Response (SOAR)
soc_webhook.py Capabilities
Receives alert data
Blocks attacker IP using iptables
Sends email alert
Writes incident report
Auto-unblocks IP after 24 hours
Run Automation Server
# sudo python3 soc_webhook.py

🔐 Step 9: Verify Firewall Blocking
# sudo iptables -L INPUT -n
Example:
sql
Copy code
DROP  all  --  192.168.150.146  0.0.0.0/0



