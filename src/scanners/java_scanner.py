"""Java 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class JavaScanner(BaseScanner):
    """Java 代码安全扫描器"""

    def _language_name(self) -> str:
        return "java"

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # SQL 注入
            VulnRule(
                rule_id="JAVA-SQL-001",
                description="SQL 注入：使用 Statement 拼接 SQL",
                pattern=r"""(?:createStatement|executeQuery|executeUpdate)\s*\(.*\+|Statement\.execute\s*\(.*\+""",
                severity="critical",
                cwe_id="CWE-89",
                owasp="A03:2021-Injection",
                fix_hint="使用 PreparedStatement 参数化查询",
            ),
            # 命令注入
            VulnRule(
                rule_id="JAVA-CMD-001",
                description="命令注入：Runtime.exec 或 ProcessBuilder",
                pattern=r"""Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(""",
                severity="critical",
                cwe_id="CWE-78",
                owasp="A03:2021-Injection",
                fix_hint="避免执行用户输入，使用白名单验证",
            ),
            # XXE
            VulnRule(
                rule_id="JAVA-XXE-001",
                description="XXE：未禁用外部实体的 XML 解析",
                pattern=r"""DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLReaderFactory""",
                severity="high",
                cwe_id="CWE-611",
                owasp="A05:2021-Security Misconfiguration",
                fix_hint="禁用外部实体: setFeature(\"http://xml.org/sax/features/external-general-entities\", false)",
            ),
            # 反序列化
            VulnRule(
                rule_id="JAVA-DESER-001",
                description="不安全的反序列化",
                pattern=r"""ObjectInputStream\s*\(|\.readObject\s*\(\)|readUnshared\s*\(\)""",
                severity="critical",
                cwe_id="CWE-502",
                owasp="A08:2021-Software and Data Integrity Failures",
                fix_hint="避免反序列化不可信数据，使用白名单过滤",
            ),
            # SSRF
            VulnRule(
                rule_id="JAVA-SSRF-001",
                description="SSRF：使用用户输入构造 URL",
                pattern=r"""new\s+URL\s*\(.*request\.|HttpURLConnection.*request\.|openConnection\s*\(\)""",
                severity="high",
                cwe_id="CWE-918",
                owasp="A10:2021-Server-Side Request Forgery",
                fix_hint="验证和限制请求目标",
            ),
            # 硬编码密钥
            VulnRule(
                rule_id="JAVA-SECRET-001",
                description="硬编码密钥/密码",
                pattern=r"""(?:password|secret|apiKey|token)\s*=\s*"[^"]{8,}" """,
                severity="high",
                cwe_id="CWE-798",
                fix_hint="使用环境变量或密钥管理服务",
            ),
            # 路径遍历
            VulnRule(
                rule_id="JAVA-PATH-001",
                description="路径遍历",
                pattern=r"""new\s+File\s*\(.*request\.|new\s+FileInputStream\s*\(.*request\.""",
                severity="high",
                cwe_id="CWE-22",
                owasp="A01:2021-Broken Access Control",
                fix_hint="验证并规范化文件路径",
            ),
            # 弱加密
            VulnRule(
                rule_id="JAVA-CRYPTO-001",
                description="弱加密算法：使用 DES/3DES/RC4",
                pattern=r"""Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|Blowfish)""",
                severity="medium",
                cwe_id="CWE-327",
                owasp="A02:2021-Cryptographic Failures",
                fix_hint="使用 AES-256-GCM 替代",
            ),
        ]
