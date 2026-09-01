#!/usr/bin/env python3
"""
Report generation: Markdown (HackerOne-compatible) and JSON output.
"""

import json
from dataclasses import asdict
from datetime import datetime
from typing import List

from .constants import __version__
from .models import Finding, Severity


class ReportGenerator:
    """Generate HackerOne-compatible reports"""

    @staticmethod
    def generate_markdown(findings: List[Finding], target: str) -> str:
        """Generate HackerOne report"""
        report = []
        report.append(f"# PhantomProbe Scan Report")
        report.append(f"")
        report.append(f"**Target:** {target}")
        report.append(f"**Scan Date:** {datetime.now().isoformat()}")
        report.append(f"**Scanner:** PhantomProbe v{__version__}")
        report.append(f"")

        # Severity summary
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

        report.append("## Summary")
        report.append(f"")
        report.append(f"**Total Findings:** {len(findings)}")
        report.append(f"")

        for severity in severity_order:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                report.append(f"- **{severity.value.upper()}:** {count}")

        report.append(f"")

        # Detailed findings
        for severity in severity_order:
            severity_findings = [f for f in findings if f.severity == severity]
            if severity_findings:
                report.append(f"## {severity.value.upper()} Severity")
                report.append(f"")

                for finding in severity_findings:
                    report.append(f"### {finding.id}: {finding.title}")
                    report.append(f"")
                    report.append(f"**Category:** {finding.category}")
                    report.append(f"")
                    report.append(f"**Description:**")
                    report.append(f"{finding.description}")
                    report.append(f"")
                    report.append(f"**Evidence:**")
                    report.append(f"```")
                    report.append(f"{finding.evidence}")
                    report.append(f"```")
                    report.append(f"")
                    report.append(f"**Remediation:**")
                    report.append(f"{finding.remediation}")
                    report.append(f"")
                    if finding.references:
                        report.append(f"**References:**")
                        for ref in finding.references:
                            report.append(f"- {ref}")
                        report.append(f"")
                    report.append(f"---")
                    report.append(f"")

        return "\n".join(report)

    @staticmethod
    def generate_json(findings: List[Finding], target: str) -> str:
        """Generate JSON report"""
        report = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "scanner": f"PhantomProbe v{__version__}",
            "findings_count": len(findings),
            "findings": [
                {
                    **{k: v for k, v in asdict(f).items() if k != 'severity'},
                    "severity": f.severity.value
                }
                for f in findings
            ]
        }
        return json.dumps(report, indent=2)

