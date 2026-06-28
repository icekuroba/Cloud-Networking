import json
import sys
from io import StringIO
from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
DATA_FILE = BASE_DIR / "data" / "sample_nsg_rules.json"

sys.path.append(str(SRC_DIR))

from analyzer import analyze_rules, count_by_severity


st.set_page_config(
    page_title="Cloud Network Guardian",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cloud Network Guardian")
st.subheader("Azure NSG Security Audit Dashboard")

st.write(
    "This dashboard analyzes Azure Network Security Group rules and detects risky public inbound configurations."
)

uploaded_file = st.file_uploader(
    "Upload a NSG rules JSON file",
    type=["json"]
)

if uploaded_file is not None:
    rules = json.load(uploaded_file)
    st.success("Custom JSON file loaded successfully.")
else:
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        rules = json.load(file)
    st.info("Using default sample NSG rules.")

findings = analyze_rules(rules)
summary = count_by_severity(findings)

st.divider()

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Rules Analyzed", len(rules))
col2.metric("Findings", len(findings))
col3.metric("Critical", summary.get("CRITICAL", 0))
col4.metric("High", summary.get("HIGH", 0))
col5.metric("Info", summary.get("INFO", 0))

st.divider()

st.subheader("Findings")

if findings:
    df = pd.DataFrame(findings)

    severity_filter = st.multiselect(
        "Filter by severity",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    filtered_df = df[df["severity"].isin(severity_filter)]

    st.dataframe(filtered_df, width="stretch")

    csv_buffer = StringIO()
    filtered_df.to_csv(csv_buffer, index=False)

    st.download_button(
        label="Download CSV Report",
        data=csv_buffer.getvalue(),
        file_name="cloud_network_guardian_report.csv",
        mime="text/csv"
    )

    markdown_lines = []
    markdown_lines.append("# Cloud Network Guardian - Security Report")
    markdown_lines.append("")
    markdown_lines.append(f"Total rules analyzed: **{len(rules)}**")
    markdown_lines.append(f"Total findings: **{len(findings)}**")
    markdown_lines.append("")
    markdown_lines.append("## Findings")
    markdown_lines.append("")
    markdown_lines.append("| Severity | Rule | Service | Port | Source | Finding | Recommendation |")
    markdown_lines.append("|---|---|---|---|---|---|---|")

    for finding in findings:
        markdown_lines.append(
            f"| {finding['severity']} "
            f"| {finding['rule_name']} "
            f"| {finding['service']} "
            f"| {finding['port']} "
            f"| {finding['source']} "
            f"| {finding['message']} "
            f"| {finding['recommendation']} |"
        )

    markdown_report = "\n".join(markdown_lines)

    st.download_button(
        label="Download Markdown Report",
        data=markdown_report,
        file_name="cloud_network_guardian_report.md",
        mime="text/markdown"
    )

else:
    st.success("No risky public inbound rules were detected.")

st.divider()

st.subheader("Project Notes")

st.write(
    """
    This dashboard is part of the Cloud Network Guardian project.

    The goal is to practice Azure networking, cloud security,
    Python automation, and security reporting.
    """
)
