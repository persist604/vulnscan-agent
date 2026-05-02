"""Analyzer Agent - 负责 AI 深度分析和去重"""
import asyncio
from pathlib import Path
from typing import Optional

from ..analyzers import AIAnalyzer


class AnalyzerAgent:
    """分析 Agent，对扫描结果进行 AI 深度分析。

    职责:
    - 读取漏洞上下文代码
    - 调用 LLM 判断是否为真实漏洞
    - 评估严重程度
    - 生成修复建议
    - 去重和合并相似发现
    """

    def __init__(self, ai_analyzer: AIAnalyzer):
        self.ai = ai_analyzer

    async def analyze_batch(self, findings: list[dict], root: Path) -> list[dict]:
        """批量分析漏洞发现"""
        # 先按文件+行号去重
        unique = self._deduplicate(findings)

        # 分批调用 AI 分析（每批最多 5 个，控制 token 消耗）
        batch_size = 5
        analyzed = []
        for i in range(0, len(unique), batch_size):
            batch = unique[i:i + batch_size]
            tasks = [self._analyze_one(f, root) for f in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    analyzed.append(r)

        # 过滤掉 AI 判定为误报的
        confirmed = [f for f in analyzed if not f.get("false_positive", False)]
        return confirmed

    async def _analyze_one(self, finding: dict, root: Path) -> dict:
        """分析单个漏洞发现"""
        filepath = finding.get("file", "")
        line = finding.get("line", 0)

        # 读取上下文代码（漏洞行前后各 10 行）
        context_code = self._read_context(filepath, line, context_lines=10)

        # 调用 AI 分析
        result = await self.ai.analyze_vulnerability(
            code=context_code,
            language=finding.get("language", "unknown"),
            rule_id=finding.get("rule_id", ""),
            rule_description=finding.get("description", ""),
            file_path=filepath,
            line_number=line,
        )

        # 合并原始信息和 AI 分析结果
        finding.update(result)
        return finding

    def _read_context(self, filepath: str, line: int, context_lines: int = 10) -> str:
        """读取漏洞行周围的代码上下文"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = max(0, line - context_lines - 1)
            end = min(len(lines), line + context_lines)
            return "".join(lines[start:end])
        except Exception:
            return ""

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """按文件+行号+规则去重"""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("file", ""), f.get("line", 0), f.get("rule_id", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
