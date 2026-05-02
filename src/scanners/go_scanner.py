"""Go 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class GoScanner(BaseScanner):
    """Go 代码安全扫描器"""

    def _language_name(self) -> str:
        return "go"

    def _is_comment(self, line: str) -> bool:
        return line.strip().startswith("//")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # SQL 注入
            VulnRule(
                rule_id="GO-SQL-001",
                description="SQL 注入：使用 fmt.Sprintf 构造 SQL",
                pattern=r"""(?:db\.Exec|db\.Query|db\.QueryRow)\s*\(\s*(?:fmt\.Sprintf|.*\+)""",
                severity="critical",
                cwe_id="CWE-89",
                owasp="A03:2021-Injection",
                fix_hint="使用 db.Exec(\"... WHERE id = ?\", id) 参数化查询",
            ),
            # 命令注入
            VulnRule(
                rule_id="GO-CMD-001",
                description="命令注入：使用 exec.Command 且拼接输入",
                pattern=r"""exec\.Command\s*\(""",
                severity="high",
                cwe_id="CWE-78",
                fix_hint="避免将用户输入直接传入命令",
            ),
            # 路径遍历
            VulnRule(
                rule_id="GO-PATH-001",
                description="路径遍历",
                pattern=r"""os\.Open\s*\(.*\+|ioutil\.ReadFile\s*\(.*\+""",
                severity="high",
                cwe_id="CWE-22",
                fix_hint="使用 filepath.Clean 和验证路径前缀",
            ),
            # SSRF
            VulnRule(
                rule_id="GO-SSRF-001",
                description="SSRF",
                pattern=r"""http\.(?:Get|Post|NewRequest)\s*\(""",
                severity="medium",
                cwe_id="CWE-918",
                fix_hint="验证请求目标 URL",
            ),
            # 硬编码密钥
            VulnRule(
                rule_id="GO-SECRET-001",
                description="硬编码密钥",
                pattern=r"""(?:password|secret|apiKey|token)\s*[:=]\s*\"[^\"]{8,}\" """,
                severity="high",
                cwe_id="CWE-798",
                fix_hint="使用环境变量存储敏感信息",
            ),
            # 弱加密
            VulnRule(
                rule_id="GO-CRYPTO-001",
                description="弱加密算法",
                pattern=r"""crypto\/(?:des|rc4|md5|sha1)""",
                severity="medium",
                cwe_id="CWE-327",
                fix_hint="使用 crypto/aes 和 crypto/sha256",
            ),
        ]
