# SharkLysis
Advanced PCAP/PCAPNG Analyzer for network traffic analysis and security detection.

🔍 Overview
SharkLysis is an advanced PCAP/PCAPNG analysis tool designed for cybersecurity professionals, incident responders, and network administrators. It provides:

Comprehensive network traffic analysis
Automated threat detection
Behavioral anomaly identification
Professional security reporting
Threat intelligence integration

Ideal for: Incident response, threat hunting, malware analysis, and network forensics.
graph LR
A[PCAP/PCAPNG] --> B[Traffic Analysis]
B --> C[Threat Detection]
C --> D[Security Reporting]
D --> E[Incident Response]
D --> F[Threat Hunting]
D --> G[Forensic Analysis]

✨ Key Features
🕵️‍♂️ Advanced Threat Detection

Malicious Pattern Recognition: SQL injection, XSS, command-and-control (C2) communications
Anomaly Detection: DNS tunneling, unusual port usage, beaconing behavior
IoC Matching: Integrates with custom threat intelligence feeds
Certificate Analysis: Identifies potentially malicious SSL/TLS certificates

📊 Comprehensive Analysis

Protocol distribution statistics
Identification of top talkers (highest traffic sources/destinations)
Traffic timeline visualization
Network communication graphs

📈 Professional Reporting

Interactive console reports
HTML reports with embedded visualizations
Prioritized security findings (High/Medium/Low severity)
Exportable graphs and charts

⚙️ Flexible Configuration

Customizable threat intelligence feeds
Adjustable detection thresholds
Extensible plugin architecture

🚀 Getting Started
Prerequisites

Python 3.8 or higher
libpcap libraries (required for packet capture processing)
4GB+ RAM (recommended for large PCAP analysis)
GeoIP databases (optional, for IP geolocation):
Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind and place them in the project root.



Installation
# Clone the repository
git clone https://github.com/Saadmaliikk/SharkLysis.git
cd SharkLysis

# Install dependencies
pip install -r requirements.txt

Basic Usage
# Analyze a PCAP/PCAPNG file
python sharklysis.py <path_to_pcap_file>

Example:
python sharklysis.py toolsmith.pcap

Sample PCAP Files
The repository includes sample PCAP files for testing:

toolsmith.pcap: General network traffic for analysis.
hao123-com_packet-injection.pcap: Contains potential packet injection activity.
MyFile.png.pcapng: Example of a PCAPNG file with embedded image data.

Note: These files are for demonstration purposes. For real-world analysis, use your own captured network traffic.
📊 Sample Analysis Output
Console Report Preview
------------------------------ SECURITY FINDINGS -------------------------------

Suspicious IPs detected (3):
  - 192.168.1.105 (Known malicious)
  - 10.0.34.22 (Suspicious activity)
  - 185.239.242.84 (Malware C2)

Possible C2 domains detected (2):
  - malware-domain.com
  - c2-server.net

SQL injection patterns detected (12):
  - /products.php?id=1' OR '1'='1
  - /search.php?q=1 UNION SELECT...
  - /admin/login.php?username=admin'--

Weak protocols detected (TLS 1.0)

Generated Files
SharkLysis generates the following during analysis:

Reports: HTML reports saved in reports/.
Graphs: Visualizations (e.g., network graphs) saved in graphs/.
Temporary Files: Intermediate data stored in temp/.

🛠 Configuration
Customize SharkLysis by editing these configuration files:

Threat Intelligence Feeds:

iocs.txt: Add custom indicators of compromise (IoCs).
malware_domains.txt: List known malicious domains.
suspicious_ips.txt: List known malicious IP addresses.


GeoIP Databases:

Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the project root for IP geolocation (excluded from Git tracking per .gitignore).


Detection Rules:

Modify the detect_malicious_patterns() function in sharklysis.py to add custom detection rules.



📂 Project Structure
SharkLysis/
├── assests/                  # Static assets (e.g., banner.png)
├── graphs/                   # Generated network graphs
├── reports/                  # HTML reports
├── temp/                     # Temporary files
├── iocs.txt                 # Custom IoCs
├── malware_domains.txt      # Malicious domains
├── suspicious_ips.txt       # Suspicious IPs
├── LICENSE                  # MIT License
├── README.md                # Project documentation
├── requirements.txt         # Python dependencies
├── sharklysis.py            # Main script

🤝 Contributing
We welcome contributions from the security community! Here's how to get involved:

Report Issues: Found a bug? Open an issue
Feature Requests: Suggest new features or enhancements
Pull Requests: Submit code improvements
Documentation: Help improve documentation and examples

Development Setup:
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

📜 License
Distributed under the MIT License. See LICENSE for more information.
