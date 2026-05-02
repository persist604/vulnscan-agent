"""扫描器基类"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VulnRule:
    """漏洞规则定义"""
    rule_id: str
    description: str
    pattern: str  # 正则表达式
    severity: str  # critical, high, medium, low, info
    cwe_id: str = ""  # CWE 编号
    owasp: str = ""  # OWASP 分类
    fix_hint: str = ""  # 修复提示


class BaseScanner(ABC):
    """扫描器基类，所有语言扫描器继承此类"""

    def __init__(self):
        self.rules = self._load_rules()

    @abstractmethod
    def _load_rules(self) -> list[VulnRule]:
        """加载该语言的漏洞规则"""
        ...

    def scan(self, content: str, filepath: str, depth: str = "standard") -> list[dict]:
        """扫描文件内容，返回漏洞发现列表"""
        findings = []
        lines = content.split("\n")

        for rule in self.rules:
            # quick 模式只扫 critical/high
            if depth == "quick" and rule.severity not in ("critical", "high"):
                continue

            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    # 排除注释行
                    if self._is_comment(line.strip()):
                        continue
                    findings.append({
                        "rule_id": rule.rule_id,
                        "description": rule.description,
                        "severity": rule.severity,
                        "cwe_id": rule.cwe_id,
                        "owasp": rule.owasp,
                        "fix_hint": rule.fix_hint,
                        "file": filepath,
                        "line": i,
                        "code_snippet": line.strip(),
                        "language": self._language_name(),
                    })

        return findings

    @abstractmethod
    def _is_comment(self, line: str) -> bool:
        """判断是否为注释行"""
        ...

    @abstractmethod
    def _language_name(self) -> str:
        """返回语言名称"""
        ...
