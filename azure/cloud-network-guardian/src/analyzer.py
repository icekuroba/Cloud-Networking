RISKY_PORTS = {
    "22": {
        "severity": "HIGH",
        "service": "SSH",
        "message": "SSH is exposed to the internet.",
        "recommendation": "Restrict SSH to a trusted admin IP, use VPN, or use Azure Bastion."
    },
    "3389": {
        "severity": "CRITICAL",
        "service": "RDP",
        "message": "RDP is exposed to the internet.",
        "recommendation": "Do not expose RDP publicly. Use Azure Bastion, VPN, or a jump host."
    },
    "3306": {
        "severity": "HIGH",
        "service": "MySQL",
        "message": "MySQL database port is publicly exposed.",
        "recommendation": "Restrict database access to private subnets or trusted application servers only."
    },
    "5432": {
        "severity": "HIGH",
        "service": "PostgreSQL",
        "message": "PostgreSQL database port is publicly exposed.",
        "recommendation": "Restrict database access to private subnets or trusted application servers only."
    },
    "1433": {
        "severity": "HIGH",
        "service": "SQL Server",
        "message": "SQL Server database port is publicly exposed.",
        "recommendation": "Restrict SQL Server access to private networks only."
    },
    "6379": {
        "severity": "HIGH",
        "service": "Redis",
        "message": "Redis port is publicly exposed.",
        "recommendation": "Do not expose Redis to the internet. Use private networking."
    }
}

PUBLIC_SOURCES = {
    "0.0.0.0/0",
    "*",
    "Internet",
    "Any",
    "any",
    "internet"
}

WEB_PORTS = {
    "80": "HTTP",
    "443": "HTTPS"
}


def is_public_source(source):
    return str(source).strip() in PUBLIC_SOURCES


def is_allow_inbound(rule):
    action = str(rule.get("action", "")).lower()
    direction = str(rule.get("direction", "")).lower()

    return action == "allow" and direction == "inbound"


def analyze_rules(rules):
    findings = []

    for rule in rules:
        rule_name = rule.get("name", "UnnamedRule")
        source = rule.get("source", "")
        port = str(rule.get("port", ""))
        protocol = rule.get("protocol", "Unknown")

        if not is_allow_inbound(rule):
            continue

        if not is_public_source(source):
            continue

        if port in RISKY_PORTS:
            risk = RISKY_PORTS[port]

            findings.append({
                "severity": risk["severity"],
                "rule_name": rule_name,
                "service": risk["service"],
                "port": port,
                "protocol": protocol,
                "source": source,
                "message": risk["message"],
                "recommendation": risk["recommendation"]
            })

        elif port in WEB_PORTS:
            findings.append({
                "severity": "INFO",
                "rule_name": rule_name,
                "service": WEB_PORTS[port],
                "port": port,
                "protocol": protocol,
                "source": source,
                "message": "Public web traffic is allowed.",
                "recommendation": "Ensure the web service is patched, monitored, and protected with TLS and secure headers."
            })

        elif port == "*":
            findings.append({
                "severity": "CRITICAL",
                "rule_name": rule_name,
                "service": "Any",
                "port": port,
                "protocol": protocol,
                "source": source,
                "message": "All ports are exposed to the internet.",
                "recommendation": "Avoid wildcard inbound rules. Allow only the minimum required ports."
            })

        else:
            findings.append({
                "severity": "MEDIUM",
                "rule_name": rule_name,
                "service": "Unknown",
                "port": port,
                "protocol": protocol,
                "source": source,
                "message": "A public inbound rule was detected for a non-standard port.",
                "recommendation": "Review this rule and confirm whether public access is required."
            })

    return findings


def count_by_severity(findings):
    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")
        summary[severity] = summary.get(severity, 0) + 1

    return summary
