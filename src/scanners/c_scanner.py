"""C/C++ 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class CScanner(BaseScanner):
    """C/C++ 代码安全扫描器"""

    def _language_name(self) -> str:
        return "c"

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # 缓冲区溢出
            VulnRule(
                rule_id="C-BUF-001",
                description="缓冲区溢出：使用不安全的字符串函数",
                pattern=r"""\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\(""",
                severity="critical",
                cwe_id="CWE-120",
                owasp="A06:2021-Vulnerable and Outdated Components",
                fix_hint="使用 strncpy/strncat/snprintf/fgets 替代",
            ),
            # 格式化字符串
            VulnRule(
                rule_id="C-FMT-001",
                description="格式化字符串漏洞",
                pattern=r"""printf\s*\(\s*[a-zA-Z_]|fprintf\s*\(\s*(?:stdout|stderr)\s*,\s*[a-zA-Z_]""",
                severity="high",
                cwe_id="CWE-134",
                fix_hint="使用格式化字符串常量: printf(\"%s\", var)",
            ),
            # 整数溢出
            VulnRule(
                rule_id="C-INT-001",
                description="整数溢出：未检查的算术运算",
                pattern=r"""malloc\s*\(\s*\w+\s*\*\s*\w+|calloc\s*\(\s*\w+\s*,\s*\w+""",
                severity="high",
                cwe_id="CWE-190",
                fix_hint="检查乘法运算是否溢出",
            ),
            # Use After Free
            VulnRule(
                rule_id="C-UAF-001",
                description="Use After Free：释放后使用",
                pattern=r"""\bfree\s*\(\s*\w+\s*\)""",
                severity="critical",
                cwe_id="CWE-416",
                fix_hint="释放后置 NULL，检查使用前是否为 NULL",
            ),
            # 空指针解引用
            VulnRule(
                rule_id="C-NULL-001",
                description="空指针解引用风险：未检查 malloc 返回值",
                pattern=r"""malloc\s*\([^)]+\)\s*;(?!(?:if|\/\/|\/\*))""",
                severity="high",
                cwe_id="CWE-476",
                fix_hint="检查 malloc 返回值是否为 NULL",
            ),
            # 命令注入
            VulnRule(
                rule_id="C-CMD-001",
                description="命令注入：使用 system/popen",
                pattern=r"""\b(?:system|popen)\s*\(""",
                severity="critical",
                cwe_id="CWE-78",
                fix_hint="使用 execve 系列函数替代 system()",
            ),
            # 竞态条件
            VulnRule(
                rule_id="C-RACE-001",
                description="竞态条件：TOCTOU",
                pattern=r"""\baccess\s*\(.*\).*\bopen\s*\(|\bstat\s*\(.*\).*\bopen\s*\(""",
                severity="medium",
                cwe_id="CWE-367",
                fix_hint="直接使用 open() 并检查返回值，避免先检查再使用",
            ),
        ]