import csv
from datetime import datetime
from analyzer import count_by_severity


def generate_markdown_report(findings, output_path):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = count_by_severity(findings)

    lines = []
    lines.append("# Cloud Network Guardian - Security Report")
    lines.append("")
    lines.append(f"Generated at: `{now}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This report identifies potentially risky public inbound network rules based on simulated Azure NSG configurations.")
    lines.append("")
    lines.append(f"Total findings: **{len(findings)}**")
    lines.append("")
    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {severity} | {summary.get(severity, 0)} |")

    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not findings:
        lines.append("No risky public inbound rules were detected.")
    else:
        lines.append("| Severity | Rule | Service | Port | Protocol | Source | Finding | Recommendation |")
        lines.append("|---|---|---|---|---|---|---|---|")

        for finding in findings:
            lines.append(
                f"| {finding['severity']} "
                f"| {finding['rule_name']} "
                f"| {finding['service']} "
                f"| {finding['port']} "
                f"| {finding['protocol']} "
                f"| {finding['source']} "
                f"| {finding['message']} "
                f"| {finding['recommendation']} |"
            )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This report is generated from simulated NSG rules.")
    lines.append("- Future versions will support real Azure NSG exports using Azure CLI.")
    lines.append("- Findings should be validated before applying changes in production environments.")

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))


def generate_csv_report(findings, output_path):
    fieldnames = [
        "severity",
        "rule_name",
        "service",
        "port",
        "protocol",
        "source",
        "message",
        "recommendation"
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding)
EOF
