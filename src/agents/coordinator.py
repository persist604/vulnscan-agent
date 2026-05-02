"""协调器 Agent - 负责任务编排、分发和汇总"""
import os
import asyncio
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

from .scanner_agent import ScannerAgent
from .analyzer_agent import AnalyzerAgent
from .reporter_agent import ReporterAgent
from ..scanners import get_scanner_for_file
from ..analyzers import AIAnalyzer


class CoordinatorAgent:
    """主导 Agent，协调整个扫描流程。

    工作流:
    1. 遍历目标目录，按语言分组文件
    2. 分发给多个 ScannerAgent 并行扫描
    3. 收集原始漏洞结果，交给 AnalyzerAgent 做 AI 深度分析
    4. 汇总结果，交给 ReporterAgent 生成报告
    """

    def __init__(self, config: dict):
        self.config = config
        self.max_agents = config.get("scan", {}).get("max_agents", 4)
        self.ignore_dirs = set(config.get("scan", {}).get("ignore_dirs", []))
        self.ignore_patterns = config.get("scan", {}).get("ignore_patterns", [])
        self.ai_analyzer = AIAnalyzer(config.get("ai", {}))

    async def run(self, target_path: str) -> dict:
        """执行完整扫描流程"""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"目标路径不存在: {target}")

        # Phase 1: 文件发现与分组
        file_groups = self._discover_files(target)
        total_files = sum(len(files) for files in file_groups.values())
        print(f"[Coordinator] 发现 {total_files} 个文件，涵盖 {len(file_groups)} 种语言")

        # Phase 2: 并行扫描
        raw_findings = await self._parallel_scan(file_groups)
        print(f"[Coordinator] 原始扫描发现 {len(raw_findings)} 个潜在问题")

        # Phase 3: AI 深度分析
        analyzed = await self._ai_analyze(raw_findings, target)
        print(f"[Coordinator] AI 分析完成，确认 {len(analyzed)} 个漏洞")

        # Phase 4: 生成报告
        report = ReporterAgent(self.config).generate(analyzed, target)
        return report

    def _discover_files(self, root: Path) -> dict[str, list[Path]]:
        """遍历目录或单文件，按语言分组"""
        groups: dict[str, list[Path]] = {}

        # 如果是单个文件，直接处理
        if root.is_file():
            lang = self._detect_language(root)
            if lang:
                groups[lang] = [root]
            return groups

        # 目录则递归遍历
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if self._should_ignore(path, root):
                continue
            lang = self._detect_language(path)
            if lang:
                groups.setdefault(lang, []).append(path)
        return groups

    def _should_ignore(self, path: Path, root: Path) -> bool:
        """检查文件是否应被忽略"""
        rel = path.relative_to(root)
        for part in rel.parts:
            if part in self.ignore_dirs:
                return True
        for pattern in self.ignore_patterns:
            if path.match(pattern):
                return True
        return False

    def _detect_language(self, path: Path) -> Optional[str]:
        """根据扩展名检测语言"""
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
            ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
            ".hpp": "cpp", ".go": "go", ".rs": "rust",
            ".php": "php", ".rb": "ruby",
        }
        return ext_map.get(path.suffix.lower())

    async def _parallel_scan(self, file_groups: dict[str, list[Path]]) -> list[dict]:
        """分发文件给多个 ScannerAgent 并行扫描"""
        all_findings = []
        semaphore = asyncio.Semaphore(self.max_agents)

        async def scan_file(lang: str, filepath: Path):
            async with semaphore:
                scanner = ScannerAgent(lang, self.config)
                return await scanner.scan(filepath)

        tasks = []
        for lang, files in file_groups.items():
            for f in files:
                tasks.append(scan_file(lang, f))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                print(f"[Coordinator] 扫描异常: {result}")

        return all_findings

    async def _ai_analyze(self, findings: list[dict], root: Path) -> list[dict]:
        """用 AI 对原始发现进行深度分析和去重"""
        if not findings:
            return []
        analyzer = AnalyzerAgent(self.ai_analyzer)
        return await analyzer.analyze_batch(findings, root)
