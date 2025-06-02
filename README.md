
  


SharkLysis - Advanced Network Forensic Analysis Toolkit

  
  



🔍 Overview
SharkLysis is a powerful PCAP/PCAPNG analysis tool tailored for cybersecurity professionals, incident responders, and network administrators. It provides advanced features for:

Network Traffic Analysis: Deep insights into packet-level data.
Threat Detection: Identify malicious patterns and anomalies.
Security Reporting: Generate professional, actionable reports.
Threat Intelligence: Integrate custom IoCs for enhanced detection.

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


✨ Key Features
🕵️‍♂️ Advanced Threat Detection

Malicious Patterns: Detect SQL injection, XSS, and C2 communications.
Anomaly Detection: Identify DNS tunneling, unusual ports, and beaconing.
IoC Matching: Leverage custom threat intelligence feeds.
Certificate Analysis: Spot suspicious SSL/TLS certificates.

📊 Comprehensive Analysis

Protocol distribution statistics
Top talker identification (highest traffic sources/destinations)
Traffic timeline visualization
Network communication graphs

📈 Professional Reporting

Interactive console reports for quick insights
HTML reports with embedded visualizations
Prioritized findings (High/Medium/Low severity)
Exportable graphs and charts for sharing

⚙️ Flexible Configuration

Custom threat intelligence feeds
Adjustable detection thresholds
Extensible plugin architecture for adding new features


🚀 Getting Started
Prerequisites
Before running SharkLysis, ensure you have the following:

Python: Version 3.8 or higher
libpcap Libraries: Required for packet processing
Memory: 4GB+ RAM (for large PCAP files)
GeoIP Databases (optional, for IP geolocation):
Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind.
Place them in the project root (they are excluded from Git tracking per .gitignore).



Installation
Follow these steps to set up SharkLysis:

Clone the Repository:
git clone https://github.com/Saadmaliikk/SharkLysis.git
cd SharkLysis


Install Dependencies:
pip install -r requirements.txt



Basic Usage
Run SharkLysis on a PCAP/PCAPNG file:
python sharklysis.py <path_to_pcap_file>

Example:
python sharklysis.py toolsmith.pcap


📂 Project Structure
Below is the directory structure of the SharkLysis project:
SharkLysis/
├── assets/                  # Static assets (e.g., banner.png)
├── graphs/                  # Generated network graphs
├── reports/                 # HTML reports
├── temp/                    # Temporary files
├── iocs.txt                # Custom indicators of compromise
├── malware_domains.txt     # Known malicious domains
├── suspicious_ips.txt      # Suspicious IP addresses
├── LICENSE                 # MIT License
├── README.md               # Project documentation
├── requirements.txt        # Python dependencies
├── sharklysis.py           # Main analysis script

Sample PCAP Files
The repository includes the following sample PCAP files for testing:

toolsmith.pcap: General network traffic for analysis.
hao123-com_packet-injection.pcap: Contains potential packet injection activity.
MyFile.png.pcapng: Example of a PCAPNG file with embedded image data.

Note: These files are for demonstration purposes. For real-world analysis, use your own captured network traffic.

📊 Sample Analysis Output
Console Report Preview
Here’s what a typical SharkLysis console report looks like:
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

Generated Files
SharkLysis generates the following during analysis:

Reports: HTML reports saved in the reports/ directory.
Graphs: Visualizations (e.g., network graphs) saved in the graphs/ directory.
Temporary Files: Intermediate data stored in the temp/ directory.


🛠 Configuration
Customize SharkLysis by editing the following files:
Threat Intelligence Feeds

iocs.txt: Add custom indicators of compromise (IoCs).
malware_domains.txt: List known malicious domains.
suspicious_ips.txt: List known malicious IP addresses.

GeoIP Databases

Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the project root for IP geolocation (excluded from Git tracking).

Detection Rules

Modify the detect_malicious_patterns() function in sharklysis.py to add custom detection rules.


🤝 Contributing
We welcome contributions from the security community! Here’s how you can get involved:

Report Issues: Found a bug? Open an issue.
Feature Requests: Suggest new features or enhancements.
Pull Requests: Submit code improvements.
Documentation: Help improve documentation and examples.

Development Setup
Set up your development environment with these steps:

Create a Virtual Environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt




📜 License
Distributed under the MIT License. See the LICENSE file for more information.
