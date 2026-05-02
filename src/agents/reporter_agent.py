"""Reporter Agent - 负责生成扫描报告"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReporterAgent:
    """报告 Agent，将分析结果格式化为可读报告。"""

    def __init__(self, config: dict):
        self.config = config
        report_cfg = config.get("report", {})
        self.format = report_cfg.get("format", "markdown")
        self.output_dir = Path(report_cfg.get("output_dir", "./reports"))
        self.include_fixes = report_cfg.get("include_fix_suggestions", True)

    def generate(self, findings: list[dict], target: Path) -> dict:
        """生成报告并写入文件"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 统计
        stats = self._compute_stats(findings)

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        report_data = {
            "target": str(target),
            "timestamp": timestamp,
            "stats": stats,
            "findings": findings,
        }

        if self.format == "markdown":
            content = self._to_markdown(report_data)
            ext = "md"
        elif self.format == "json":
            content = json.dumps(report_data, indent=2, ensure_ascii=False)
            ext = "json"
        else:
            content = self._to_markdown(report_data)
            ext = "md"

        output_file = self.output_dir / f"vulnscan_{timestamp}.{ext}"
        output_file.write_text(content, encoding="utf-8")
        print(f"[Reporter] 报告已生成: {output_file}")

        report_data["output_file"] = str(output_file)
        return report_data

    def _compute_stats(self, findings: list[dict]) -> dict:
        """计算统计信息"""
        stats = {"total": len(findings), "by_severity": {}, "by_language": {}}
        for f in findings:
            sev = f.get("severity", "info")
            lang = f.get("language", "unknown")
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            stats["by_language"][lang] = stats["by_language"].get(lang, 0) + 1
        return stats

    def _to_markdown(self, data: dict) -> str:
        """生成 Markdown 格式报告"""
        lines = []
        lines.append("# VulnScan Agent 扫描报告\n")
        lines.append(f"**扫描目标**: `{data['target']}`")
        lines.append(f"**扫描时间**: {data['timestamp']}")
        lines.append("")

        stats = data["stats"]
        lines.append("## 统计概览\n")
        lines.append(f"| 指标 | 数量 |")
        lines.append(f"|------|------|")
        lines.append(f"| 总发现 | {stats['total']} |")
        for sev, count in sorted(stats.get("by_severity", {}).items()):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
            lines.append(f"| {icon} {sev} | {count} |")
        lines.append("")

        lines.append("## 漏洞详情\n")
        for i, f in enumerate(data["findings"], 1):
            sev = f.get("severity", "info").upper()
            lines.append(f"### {i}. [{sev}] {f.get('rule_id', 'UNKNOWN')}\n")
            lines.append(f"- **文件**: `{f.get('file', 'N/A')}:{f.get('line', '?')}`")
            lines.append(f"- **语言**: {f.get('language', 'N/A')}")
            lines.append(f"- **描述**: {f.get('description', 'N/A')}")
            if f.get("ai_analysis"):
                lines.append(f"- **AI 分析**: {f['ai_analysis']}")
            if self.include_fixes and f.get("fix_suggestion"):
                lines.append(f"- **修复建议**: {f['fix_suggestion']}")
            if f.get("code_snippet"):
                lines.append(f"\n```{f.get('language', '')}")
                lines.append(f["code_snippet"])
                lines.append("```")
            lines.append("")

        return "\n".join(lines)
