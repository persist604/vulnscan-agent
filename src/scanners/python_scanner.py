"""Python 漏洞扫描器"""
from .base_scanner import BaseScanner, VulnRule


class PythonScanner(BaseScanner):
    """Python 代码安全扫描器"""

    def _language_name(self) -> str:
        return "python"

    def _is_comment(self, line: str) -> bool:
        return line.startswith("#")

    def _load_rules(self) -> list[VulnRule]:
        return [
            # SQL 注入
            VulnRule(
                rule_id="PY-SQL-001",
                description="SQL 注入：使用字符串拼接构造 SQL 语句",
                pattern=r"""(?:execute|cursor\.execute|raw|query)\s*\(\s*(?:f['""]|['""].*%s|['""].*\+|\.format\()""",
                severity="critical",
                cwe_id="CWE-89",
                owasp="A03:2021-Injection",
                fix_hint="使用参数化查询替代字符串拼接",
            ),
            # 命令注入
            VulnRule(
                rule_id="PY-CMD-001",
                description="命令注入：使用 os.system 或 subprocess.call 且 shell=True",
                pattern=r"""os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True""",
                severity="critical",
                cwe_id="CWE-78",
                owasp="A03:2021-Injection",
                fix_hint="避免 shell=True，使用参数列表传递",
            ),
            # 代码注入
            VulnRule(
                rule_id="PY-EVAL-001",
                description="代码注入：使用 eval() 或 exec() 执行动态代码",
                pattern=r"""\b(?:eval|exec)\s*\(""",
                severity="high",
                cwe_id="CWE-94",
                owasp="A03:2021-Injection",
                fix_hint="避免使用 eval/exec，改用 ast.literal_eval 或安全的解析方式",
            ),
            # 路径遍历
            VulnRule(
                rule_id="PY-PATH-001",
                description="路径遍历：未验证的文件路径拼接",
                pattern=r"""open\s*\(.*\+|os\.path\.join\s*\(.*request|pathlib.*\/.*\+""",
                severity="high",
                cwe_id="CWE-22",
                owasp="A01:2021-Broken Access Control",
                fix_hint="验证并规范化文件路径，防止 ../ 遍历",
            ),
            # 硬编码密钥
            VulnRule(
                rule_id="PY-SECRET-001",
                description="硬编码密钥/密码",
                pattern=r"""(?:password|secret|api_key|token|apikey)\s*=\s*['""][^'""]{8,}['""]""",
                severity="high",
                cwe_id="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                fix_hint="使用环境变量或密钥管理服务存储敏感信息",
            ),
            # 不安全的反序列化
            VulnRule(
                rule_id="PY-DESER-001",
                description="不安全的反序列化：使用 pickle.loads 加载不可信数据",
                pattern=r"""pickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader)""",
                severity="critical",
                cwe_id="CWE-502",
                owasp="A08:2021-Software and Data Integrity Failures",
                fix_hint="避免 pickle 反序列化不可信数据；yaml.load 使用 SafeLoader",
            ),
            # SSRF
            VulnRule(
                rule_id="PY-SSRF-001",
                description="SSRF：使用用户输入构造请求 URL",
                pattern=r"""requests\.(?:get|post|put|delete)\s*\(.*request\.|urllib\.request\.urlopen\s*\(.*request\.""",
                severity="high",
                cwe_id="CWE-918",
                owasp="A10:2021-Server-Side Request Forgery",
                fix_hint="验证和限制请求目标 URL，禁止内网地址",
            ),
            # 弱随机数
            VulnRule(
                rule_id="PY-RANDOM-001",
                description="弱随机数：使用 random 模块生成安全相关值",
                pattern=r"""random\.(?:random|randint|choice|randrange)\s*\(""",
                severity="medium",
                cwe_id="CWE-330",
                owasp="A02:2021-Cryptographic Failures",
                fix_hint="安全场景请使用 secrets 模块",
            ),
            # 调试代码残留
            VulnRule(
                rule_id="PY-DEBUG-001",
                description="调试代码残留：生产代码中包含 breakpoint/pdb",
                pattern=r"""\bbreakpoint\s*\(\)|import\s+pdb|pdb\.set_trace\s*\(""",
                severity="medium",
                cwe_id="CWE-489",
                fix_hint="移除调试代码",
            ),
            # 不安全的临时文件
            VulnRule(
                rule_id="PY-TEMP-001",
                description="不安全的临时文件创建",
                pattern=r"""(?:tempfile\.mktemp|open\s*\(\s*['""]\/tmp\/)""",
                severity="medium",
                cwe_id="CWE-377",
                fix_hint="使用 tempfile.mkstemp 或 tempfile.NamedTemporaryFile",
            ),
        ]
