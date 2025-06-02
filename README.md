![SharkLysis Banner](https://github.com/Saadmaliikk/SharkLysis/blob/main/assests/banner.png)
SharkLysis - Advanced Network Forensic Analysis Toolkit


# 🔍 Overview
SharkLysis is an advanced PCAP/PCAPNG analysis toolkit designed for cybersecurity professionals, incident responders, and network administrators. It offers robust features for:

Network Traffic Analysis: Deep packet-level insights.
Threat Detection: Automated identification of malicious activities.
Security Reporting: Professional, actionable reports.
Threat Intelligence Integration: Customizable IoC feeds.

Ideal Use Cases:  

Incident response  
Threat hunting  
Malware analysis  
Network forensics

graph LR
  A[PCAP/PCAPNG] --> B[Traffic Analysis]
  B --> C[Threat Detection]
  C --> D[Security Reporting]
  D --> E[Incident Response]
  D --> F[Threat Hunting]
  D --> G[Forensic Analysis]


# ✨ Key Features
## 🕵️‍♂️ Advanced Threat DetectionKey Features

Malicious Patterns: Detect SQL injection, XSS, and C2 communications.
Anomaly Detection: Identify DNS tunneling, unusual ports, and beaconing.
IoC Matching: Integrate custom threat intelligence feeds.
Certificate Analysis: Detect suspicious SSL/TLS certificates.

## 📊 Comprehensive Analysis

Protocol distribution statistics
Top talker identification (highest traffic sources/destinations)
Traffic timeline visualization
Network communication graphs

## 📈Professional Reporting

Interactive console reports for quick insights
HTML reports with embedded visualizations
Prioritized findings (High/Medium/Low severity)
Exportable graphs and charts

## ⚙️Flexible Configuration

Customizable threat intelligence feeds
Adjustable detection thresholds
Extensible plugin architecture


# 🚀 Getting Started
### Prerequisites
Ensure the following are installed before running SharkLysis:

Python: Version 3.8 or higher
libpcap Libraries: Required for packet processing
Memory: 4GB+ RAM (recommended for large PCAP files)
GeoIP Databases (optional, for IP geolocation):
Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind.
Place them in the project root (excluded from Git tracking per .gitignore).



### Installation
Follow these steps to set up SharkLysis:

Clone the Repository:
git clone https://github.com/Saadmaliikk/SharkLysis.git
cd SharkLysis


Install Dependencies:
pip install -r requirements.txt



### Basic Usage
Run SharkLysis on a PCAP/PCAPNG file:
python sharklysis.py <path_to_pcap_file>

Example:
python sharklysis.py toolsmith.pcap


# 📂 Project Structure
### Directory Layout
SharkLysis/
├── assests/                  # Static assets (e.g., banner.png)
├── graphs/                   # Generated network graphs
├── reports/                  # HTML reports
├── temp/                     # Temporary files
├── iocs.txt                 # Custom indicators of compromise
├── malware_domains.txt      # Known malicious domains
├── suspicious_ips.txt       # Suspicious IP addresses
├── LICENSE                  # MIT License
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
├── sharklysis.py            # Main analysis script

### Sample PCAP Files
The repository includes sample PCAP files for testing:

toolsmith.pcap: General network traffic for analysis.
hao123-com_packet-injection.pcap: Contains potential packet injection activity.
MyFile.png.pcapng: Example of a PCAPNG file with embedded image data.

Note: These files are for demonstration. Use your own captured traffic for real-world analysis.

# 📊 Sample Analysis Output
### Console Report Preview
------------------------------ SECURITY FINDINGS -------------------------------

Suspicious IPs Detected (3):
  - 192.168.1.105 (Known malicious)
  - 10.0.34.22 (Suspicious activity)
  - 185.239.242.84 (Malware C2)

Possible C2 Domains Detected (2):
  - malware-domain.com
  - c2-server.net

SQL Injection Patterns Detected (12):
  - /products.php?id=1' OR '1'='1
  - /search.php?q=1 UNION SELECT...
  - /admin/login.php?username=admin'--

Weak Protocols Detected:
  - TLS 1.0

### Generated Files
SharkLysis generates the following during analysis:

Reports: HTML reports saved in reports/.
Graphs: Visualizations in graphs/.
Temporary Files: Data in temp/.


# 🛠Configuration
### Threat Intelligence Feeds

iocs.txt: Add custom indicators of compromise (IoCs).
malware_domains.txt: List known malicious domains.
suspicious_ips.txt: List known malicious IP addresses.

### GeoIP Databases

Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the project root for geolocation (excluded from Git).

### Detection Rules

Modify the detect_malicious_patterns() function in sharklysis.py to add custom rules.


# 🤝Contributing
### How to Contribute
We welcome contributions from the security community! Here’s how:

Report Issues: Open an issue.
Feature Requests: Suggest new features.
Pull Requests: Submit code improvements.
Documentation: Enhance docs and examples.

### Development Setup

Create a Virtual Environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt




# 📜License
Distributed under the MIT License. See LICENSE for details.
