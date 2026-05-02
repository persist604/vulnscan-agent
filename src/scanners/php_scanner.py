"""PHP 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class PHPScanner(BaseScanner):
    """PHP 代码安全扫描器"""

    def _language_name(self) -> str:
        return "php"

    def _is_comment(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # SQL 注入
            VulnRule(
                rule_id="PHP-SQL-001",
                description="SQL 注入：使用 mysql_query 拼接",
                pattern=r"""(?:mysql_query|mysqli_query|->query)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)""",
                severity="critical",
                cwe_id="CWE-89",
                fix_hint="使用 PDO prepared statements",
            ),
            # 命令注入
            VulnRule(
                rule_id="PHP-CMD-001",
                description="命令注入：使用 system/exec/passthru",
                pattern=r"""\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(""",
                severity="critical",
                cwe_id="CWE-78",
                fix_hint="使用 escapeshellarg() 转义参数",
            ),
            # 文件包含
            VulnRule(
                rule_id="PHP-LFI-001",
                description="文件包含：动态 include/require",
                pattern=r"""(?:include|require|include_once|require_once)\s*\(\s*\$_""",
                severity="critical",
                cwe_id="CWE-98",
                fix_hint="使用白名单限制可包含的文件",
            ),
            # XSS
            VulnRule(
                rule_id="PHP-XSS-001",
                description="XSS：直接输出用户输入",
                pattern=r"""echo\s+\$_(?:GET|POST|REQUEST|COOKIE)|print\s+\$_""",
                severity="high",
                cwe_id="CWE-79",
                fix_hint="使用 htmlspecialchars() 转义输出",
            ),
            # 反序列化
            VulnRule(
                rule_id="PHP-DESER-001",
                description="不安全的反序列化",
                pattern=r"""\bunserialize\s*\(""",
                severity="critical",
                cwe_id="CWE-502",
                fix_hint="避免 unserialize 不可信数据，使用 JSON",
            ),
            # SSRF
            VulnRule(
                rule_id="PHP-SSRF-001",
                description="SSRF：使用用户输入构造 URL",
                pattern=r"""(?:file_get_contents|curl_setopt)\s*\(.*\$_""",
                severity="high",
                cwe_id="CWE-918",
                fix_hint="验证请求目标 URL",
            ),
        ]
