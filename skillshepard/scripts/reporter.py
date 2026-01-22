#!/usr/bin/env python3
"""Report generators for SkillShepard scan results"""

import json
from typing import TYPE_CHECKING, Optional

from i18n import I18n

if TYPE_CHECKING:
    from scanner import ScanReport, ScanResult


class JsonReporter:
    def __init__(self, i18n: Optional[I18n] = None):
        self.i18n = i18n or I18n('en')

    def generate(self, report: "ScanReport") -> str:
        data = {
            "scan_date": report.scan_date,
            "skills_scanned": report.skills_scanned,
            "issues_found": report.issues_found,
            "results": [{
                "skill_name": r.skill_name, "path": r.path, "status": r.status,
                "issues": [{
                    "severity": i.severity,
                    "severity_label": self.i18n.t(f'severity_{i.severity}'),
                    "type": i.type,
                    "type_label": self.i18n.t(self.i18n.get_type_key(i.type)),
                    "file": i.file,
                    "line": i.line,
                    "message": i.message,
                    "code_snippet": i.code_snippet,
                    "recommendation": self.i18n.t(self.i18n.get_rec_key(i.type)) if i.recommendation else None
                } for i in r.issues]
            } for r in report.results]
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


class MarkdownReporter:
    SEVERITY_EMOJI = {'high': '🔴', 'medium': '🟡', 'low': '🔵'}
    STATUS_EMOJI = {'ok': '✅', 'warning': '⚠️', 'blocked': '🚫'}

    def __init__(self, i18n: Optional[I18n] = None):
        self.i18n = i18n or I18n('en')

    def generate(self, result: "ScanResult") -> str:
        t = self.i18n.t

        # Status label with emoji
        status_emoji = self.STATUS_EMOJI.get(result.status, '')
        status_key = {'ok': 'status_passed', 'warning': 'status_warning', 'blocked': 'status_blocked'}
        status_label = f"{status_emoji} {t(status_key.get(result.status, result.status))}"

        lines = [
            f"# {t('report_title')}", "",
            f"## {t('report_summary')}", "",
            f"- **{t('report_skill')}**: `{result.skill_name}`",
            f"- **{t('report_path')}**: `{result.path}`",
            f"- **{t('report_status')}**: {status_label}",
            f"- **{t('report_issues_found')}**: {len(result.issues)}", ""
        ]

        if not result.issues:
            lines.append(t('report_no_issues'))
            return '\n'.join(lines)

        high = sum(1 for i in result.issues if i.severity == 'high')
        med = sum(1 for i in result.issues if i.severity == 'medium')
        low = sum(1 for i in result.issues if i.severity == 'low')

        lines += [
            f"### {t('report_issue_breakdown')}", "",
            f"| {t('report_severity')} | {t('report_count')} |",
            "|----------|-------|",
            f"| {self.SEVERITY_EMOJI['high']} {t('report_high')} | {high} |",
            f"| {self.SEVERITY_EMOJI['medium']} {t('report_medium')} | {med} |",
            f"| {self.SEVERITY_EMOJI['low']} {t('report_low')} | {low} |",
            "", "---", "", f"## {t('report_issues')}", ""
        ]

        sorted_issues = sorted(result.issues, key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x.severity, 3))

        for i, issue in enumerate(sorted_issues, 1):
            emoji = self.SEVERITY_EMOJI.get(issue.severity, '⚪')
            severity_label = t(f'severity_{issue.severity}')
            type_label = t(self.i18n.get_type_key(issue.type))

            line_info = f" ({t('report_line')} {issue.line})" if issue.line else ""
            lines += [
                f"### {i}. [{emoji} {severity_label}] {type_label}", "",
                f"**{t('report_file')}**: `{issue.file}`{line_info}", "",
                f"**{t('report_issue')}**: {issue.message}", ""
            ]

            if issue.code_snippet:
                lines += [f"**{t('report_code')}**:", "```", issue.code_snippet, "```", ""]
            if issue.recommendation:
                rec_text = t(self.i18n.get_rec_key(issue.type))
                lines += [f"**{t('report_recommendation')}**: {rec_text}", ""]
            lines += ["---", ""]

        if result.status == 'blocked':
            lines += [f"## {t('report_action_required')}", "",
                     t('report_action_blocked'), ""]
        elif result.status == 'warning':
            lines += [f"## {t('report_recommendation_title')}", "",
                     t('report_review_warnings'), ""]

        lines += ["---", f"*{t('report_generated_by')}*"]
        return '\n'.join(lines)
