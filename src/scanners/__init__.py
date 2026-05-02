"""扫描器模块 - 基于规则的漏洞检测"""
from pathlib import Path
from typing import Optional

from .base_scanner import BaseScanner
from .python_scanner import PythonScanner
from .javascript_scanner import JavaScriptScanner
from .java_scanner import JavaScanner
from .c_scanner import CScanner
from .go_scanner import GoScanner
from .php_scanner import PHPScanner

_SCANNERS = {
    "python": PythonScanner,
    "javascript": JavaScriptScanner,
    "typescript": JavaScriptScanner,
    "java": JavaScanner,
    "c": CScanner,
    "cpp": CScanner,
    "go": GoScanner,
    "php": PHPScanner,
}


def get_scanner_for_file(filepath: Path, language: str) -> Optional[BaseScanner]:
    """根据语言获取对应的扫描器实例"""
    scanner_cls = _SCANNERS.get(language)
    if scanner_cls:
        return scanner_cls()
    return None
