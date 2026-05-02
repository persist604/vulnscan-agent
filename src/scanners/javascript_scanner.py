"""JavaScript/TypeScript 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class JavaScriptScanner(BaseScanner):
    """JavaScript/TypeScript 代码安全扫描器"""

    def _language_name(self) -> str:
        return "javascript"

    def _is_comment(self, line: str) -> bool:
        return line.startswith("//") or line.startswith("/*") or line.startswith("*")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # XSS
            VulnRule(
                rule_id="JS-XSS-001",
                description="XSS：使用 innerHTML 或 dangerouslySetInnerHTML 插入未转义内容",
                pattern=r"""\.innerHTML\s*=|dangerouslySetInnerHTML""",
                severity="high",
                cwe_id="CWE-79",
                owasp="A03:2021-Injection",
                fix_hint="使用 textContent 或对输入进行 HTML 转义",
            ),
            # SQL 注入
            VulnRule(
                rule_id="JS-SQL-001",
                description="SQL 注入：字符串拼接构造 SQL",
                pattern=r"""(?:query|execute|raw)\s*\(\s*(?:`.*\$\{|['""].*\+|.*\.format)""",
                severity="critical",
                cwe_id="CWE-89",
                owasp="A03:2021-Injection",
                fix_hint="使用参数化查询",
            ),
            # 命令注入
            VulnRule(
                rule_id="JS-CMD-001",
                description="命令注入：使用 exec 或 spawn 且拼接用户输入",
                pattern=r"""(?:child_process\.exec|execSync|spawn)\s*\(""",
                severity="critical",
                cwe_id="CWE-78",
                owasp="A03:2021-Injection",
                fix_hint="使用 execFile 替代 exec，避免 shell 解释",
            ),
            # 原型污染
            VulnRule(
                rule_id="JS-PROTO-001",
                description="原型污染：动态设置对象属性",
                pattern=r"""\[(?:key|prop|attr|name)\]\s*=|Object\.assign\s*\(.*\[|__proto__""",
                severity="high",
                cwe_id="CWE-1321",
                fix_hint="使用 Object.create(null) 或 Map，验证属性名",
            ),
            # 不安全的正则
            VulnRule(
                rule_id="JS-REDO-001",
                description="ReDoS：可能存在回溯爆炸的正则表达式",
                pattern=r"""new\s+RegExp\s*\(.*\+|\/.*\(\.\*\)\+|\/.*\(\.\+\)\*""",
                severity="medium",
                cwe_id="CWE-1333",
                fix_hint="限制输入长度，使用安全的正则库",
            ),
            # 硬编码密钥
            VulnRule(
                rule_id="JS-SECRET-001",
                description="硬编码密钥/Token",
                pattern=r"""(?:password|secret|apiKey|token|api_key)\s*[:=]\s*['""][^'""]{8,}['""]""",
                severity="high",
                cwe_id="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                fix_hint="使用环境变量存储敏感信息",
            ),
            # eval
            VulnRule(
                rule_id="JS-EVAL-001",
                description="代码注入：使用 eval() 或 Function() 执行动态代码",
                pattern=r"""\beval\s*\(|new\s+Function\s*\(""",
                severity="high",
                cwe_id="CWE-94",
                owasp="A03:2021-Injection",
                fix_hint="避免 eval，使用 JSON.parse 或安全的解析方式",
            ),
            # 不安全的随机数
            VulnRule(
                rule_id="JS-RANDOM-001",
                description="弱随机数：使用 Math.random() 生成安全相关值",
                pattern=r"""Math\.random\s*\(\)""",
                severity="medium",
                cwe_id="CWE-330",
                fix_hint="安全场景请使用 crypto.getRandomValues()",
            ),
            # 路径遍历
            VulnRule(
                rule_id="JS-PATH-001",
                description="路径遍历：未验证的文件路径",
                pattern=r"""(?:readFile|readFileSync|createReadStream)\s*\(.*req\.|path\.join\s*\(.*req\.""",
                severity="high",
                cwe_id="CWE-22",
                owasp="A01:2021-Broken Access Control",
                fix_hint="验证并规范化文件路径",
            ),
            # SSRF
            VulnRule(
                rule_id="JS-SSRF-001",
                description="SSRF：使用用户输入构造请求",
                pattern=r"""(?:fetch|axios\.(?:get|post)|request)\s*\(.*req\.""",
                severity="high",
                cwe_id="CWE-918",
                owasp="A10:2021-Server-Side Request Forgery",
                fix_hint="验证请求目标 URL",
            ),
        ]
