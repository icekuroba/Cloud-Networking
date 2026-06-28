# Cloud Network Guardian

Cloud Network Guardian is a Python-based Azure network security audit tool designed to detect risky cloud networking configurations, especially insecure Network Security Group (NSG) rules.

The goal of this project is to practice cloud networking, Azure security, Python automation, and technical documentation.

## Project Objective

This project analyzes simulated Azure NSG rules and generates a security report with findings, severity levels, and remediation recommendations.

Future versions will connect directly to Azure using Azure CLI to audit real NSG configurations.

## What This Project Detects

- SSH exposed to the internet
- RDP exposed to the internet
- Public database ports
- Overly permissive inbound rules
- Public web traffic
- Potential cloud network exposure risks

## Technologies Used

- Python 3
- JSON
- Markdown
- CSV
- Azure Networking concepts
- Network Security Groups
- Git and GitHub

## Project Structure

```text
cloud-network-guardian/
├── README.md
├── requirements.txt
├── data/
│   └── sample_nsg_rules.json
├── docs/
│   ├── remediation.md
│   └── risks.md
├── reports/
│   └── security_report.md
└── src/
    ├── analyzer.py
    ├── guardian.py
    └── report.py
