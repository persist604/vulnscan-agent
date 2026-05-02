"""AI 分析器 - 调用 LLM 对漏洞进行深度分析"""
import os
import json
from typing import Optional


class AIAnalyzer:
    """AI 驱动的漏洞分析器。

    职责:
    - 接收规则扫描的原始结果
    - 调用 LLM 分析代码上下文
    - 判断是否为真实漏洞（排除误报）
    - 评估实际严重程度
    - 生成针对性修复建议
    """

    def __init__(self, config: dict):
        self.provider = config.get("provider", "openai")
        self.model = config.get("model", "gpt-4o")
        self.api_key = config.get("api_key", "") or os.environ.get("OPENAI_API_KEY", "")
        self.max_tokens = config.get("max_tokens", 4096)
        self.temperature = config.get("temperature", 0.1)
        self._client = None

    def _get_client(self):
        """延迟初始化 API 客户端"""
        if self._client is None:
            if self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            else:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
        return self._client

    async def analyze_vulnerability(
        self,
        code: str,
        language: str,
        rule_id: str,
        rule_description: str,
        file_path: str,
        line_number: int,
    ) -> dict:
        """调用 LLM 分析单个漏洞"""
        prompt = self._build_analysis_prompt(
            code, language, rule_id, rule_description, file_path, line_number
        )

        try:
            response = await self._call_llm(prompt)
            return self._parse_response(response)
        except Exception as e:
            # API 调用失败时，保留规则引擎的原始判断
            return {
                "ai_analysis": f"AI 分析失败: {str(e)}",
                "false_positive": False,
            }

    def _build_analysis_prompt(
        self, code: str, language: str, rule_id: str,
        rule_description: str, file_path: str, line_number: int
    ) -> str:
        """构建分析提示词"""
        return f"""你是一个资深安全工程师，请分析以下代码中报告的潜在漏洞。

## 漏洞报告
- 规则ID: {rule_id}
- 描述: {rule_description}
- 文件: {file_path}
- 行号: {line_number}
- 语言: {language}

## 代码上下文
```{language}
{code}
```

## 请分析并返回 JSON 格式结果
{{
    "is_real_vulnerability": true/false,
    "false_positive": true/false,
    "severity": "critical/high/medium/low/info",
    "ai_analysis": "详细分析为什么是/不是真实漏洞",
    "fix_suggestion": "具体的修复建议和代码示例",
    "confidence": 0.0-1.0
}}

注意:
1. 如果代码上下文中存在有效的防护措施（如输入验证、参数化查询等），应判定为误报
2. 如果只是规则匹配但实际不可利用，应判定为低风险
3. 修复建议要具体到代码级别"""

    async def _call_llm(self, prompt: str) -> str:
        """调用 LLM API"""
        client = self._get_client()

        if self.provider == "anthropic":
            message = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        else:
            response = client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {"role": "system", "content": "你是一个代码安全分析专家，只返回 JSON 格式的分析结果。"},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
            )
            return response.choices[0].message.content

    def _parse_response(self, response: str) -> dict:
        """解析 LLM 返回的 JSON"""
        try:
            data = json.loads(response)
            return {
                "ai_analysis": data.get("ai_analysis", ""),
                "false_positive": data.get("false_positive", False),
                "severity": data.get("severity", "medium"),
                "fix_suggestion": data.get("fix_suggestion", ""),
                "confidence": data.get("confidence", 0.5),
            }
        except json.JSONDecodeError:
            return {
                "ai_analysis": response[:500],
                "false_positive": False,
            }
