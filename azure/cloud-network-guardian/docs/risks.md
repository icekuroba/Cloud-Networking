# Cloud Networking Risks

This document describes common risks related to cloud network security misconfigurations.

## Public SSH

Port: `22`

Risk: Attackers can attempt brute-force attacks or exploit weak SSH configurations.

Recommended mitigation:

- Restrict SSH to a trusted IP address.
- Use VPN or Azure Bastion.
- Disable password authentication when possible.
- Use SSH keys.

## Public RDP

Port: `3389`

Risk: RDP exposed to the internet is a common target for brute-force attacks and exploitation.

Recommended mitigation:

- Do not expose RDP publicly.
- Use Azure Bastion.
- Use VPN or a secure jump host.
- Enable MFA where possible.

## Public Database Ports

Common ports:

- MySQL: `3306`
- PostgreSQL: `5432`
- SQL Server: `1433`

Risk: Databases should not be directly reachable from the internet.

Recommended mitigation:

- Place databases in private subnets.
- Allow access only from application servers.
- Use private endpoints when available.
- Apply least privilege access.

## Overly Permissive Rules

Examples:

```text
Source: 0.0.0.0/0
Port: *
Action: Allow
Direction: Inbound
