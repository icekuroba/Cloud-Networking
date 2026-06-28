import argparse
import json
from pathlib import Path

from analyzer import analyze_rules
from report import generate_markdown_report, generate_csv_report


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "data" / "sample_nsg_rules.json"
DEFAULT_MARKDOWN_REPORT = BASE_DIR / "reports" / "security_report.md"
DEFAULT_CSV_REPORT = BASE_DIR / "reports" / "security_report.csv"


def load_rules(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cloud Network Guardian - Azure NSG security audit tool"
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
        help="Path to the NSG rules JSON file"
    )

    parser.add_argument(
        "--markdown",
        default=str(DEFAULT_MARKDOWN_REPORT),
        help="Path to the Markdown report output"
    )

    parser.add_argument(
        "--csv",
        default=str(DEFAULT_CSV_REPORT),
        help="Path to the CSV report output"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    rules = load_rules(args.input)
    findings = analyze_rules(rules)

    generate_markdown_report(findings, args.markdown)
    generate_csv_report(findings, args.csv)

    print("Cloud Network Guardian scan completed.")
    print(f"Rules analyzed: {len(rules)}")
    print(f"Findings detected: {len(findings)}")
    print(f"Markdown report: {args.markdown}")
    print(f"CSV report: {args.csv}")


if __name__ == "__main__":
    main()
