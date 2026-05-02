"""Scanner Agent - 负责单文件的规则扫描"""
import re
from pathlib import Path
from typing import Optional

from ..scanners import get_scanner_for_file


class ScannerAgent:
    """扫描 Agent，对单个文件执行规则匹配。

    每个 Agent 实例绑定一种语言，加载对应的规则集。
    """

    def __init__(self, language: str, config: dict):
        self.language = language
        self.config = config
        self.depth = config.get("scan", {}).get("depth", "standard")

    async def scan(self, filepath: Path) -> list[dict]:
        """扫描单个文件，返回原始漏洞发现列表"""
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        scanner = get_scanner_for_file(filepath, self.language)
        if not scanner:
            return []

        findings = scanner.scan(content, str(filepath), self.depth)
        return findings
