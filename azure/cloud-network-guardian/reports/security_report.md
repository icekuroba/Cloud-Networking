# Cloud Network Guardian - Security Report

Generated at: `2026-06-28 00:10:59`

## Executive Summary

This report identifies potentially risky public inbound network rules based on simulated Azure NSG configurations.

Total findings: **6**

## Severity Summary

| Severity | Count |
|---|---:|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 2 |

## Findings

| Severity | Rule | Service | Port | Protocol | Source | Finding | Recommendation |
|---|---|---|---|---|---|---|---|
| HIGH | AllowSSHFromInternet | SSH | 22 | TCP | 0.0.0.0/0 | SSH is exposed to the internet. | Restrict SSH to a trusted admin IP, use VPN, or use Azure Bastion. |
| INFO | AllowHTTP | HTTP | 80 | TCP | Internet | Public web traffic is allowed. | Ensure the web service is patched, monitored, and protected with TLS and secure headers. |
| INFO | AllowHTTPS | HTTPS | 443 | TCP | Internet | Public web traffic is allowed. | Ensure the web service is patched, monitored, and protected with TLS and secure headers. |
| CRITICAL | AllowRDPFromInternet | RDP | 3389 | TCP | 0.0.0.0/0 | RDP is exposed to the internet. | Do not expose RDP publicly. Use Azure Bastion, VPN, or a jump host. |
| HIGH | AllowPostgreSQLPublic | PostgreSQL | 5432 | TCP | 0.0.0.0/0 | PostgreSQL database port is publicly exposed. | Restrict database access to private subnets or trusted application servers only. |
| HIGH | AllowMySQLPublic | MySQL | 3306 | TCP | Any | MySQL database port is publicly exposed. | Restrict database access to private subnets or trusted application servers only. |

## Notes

- This report is generated from simulated NSG rules.
- Future versions will support real Azure NSG exports using Azure CLI.
- Findings should be validated before applying changes in production environments.