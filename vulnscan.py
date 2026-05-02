#!/usr/bin/env python3
"""VulnScan Agent - AI 驱动的多 Agent 代码漏洞扫描系统

用法:
    python vulnscan.py <目标路径> [选项]

示例:
    python vulnscan.py ./my-project
    python vulnscan.py ./src --depth deep --format html
    python vulnscan.py . --config config/custom.yaml
"""
import sys
import os
import asyncio
import argparse
from pathlib import Path

import yaml

# 确保 src 在路径中
sys.path.insert(0, str(Path(__file__).parent))

from src.agents.coordinator import CoordinatorAgent


def load_config(config_path: str = None) -> dict:
    """加载配置文件"""
    default_config = Path(__file__).parent / "config" / "default.yaml"
    config_file = Path(config_path) if config_path else default_config

    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    # 环境变量替换
    def resolve_env(obj):
        if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            env_key = obj[2:-1]
            return os.environ.get(env_key, obj)
        elif isinstance(obj, dict):
            return {k: resolve_env(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [resolve_env(i) for i in obj]
        return obj

    return resolve_env(config)


def print_banner():
    """打印启动横幅"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║           VulnScan Agent v0.1.0                           ║
║           AI 驱动的多 Agent 代码漏洞扫描系统               ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_stats(report: dict):
    """打印扫描统计"""
    stats = report.get("stats", {})
    print("\n" + "=" * 50)
    print("扫描完成!")
    print("=" * 50)
    print(f"总发现: {stats.get('total', 0)}")

    severity_icons = {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🔵", "info": "⚪"
    }
    for sev, count in stats.get("by_severity", {}).items():
        icon = severity_icons.get(sev, "")
        print(f"  {icon} {sev}: {count}")

    if report.get("output_file"):
        print(f"\n报告已保存: {report['output_file']}")
    print("=" * 50)


async def main():
    parser = argparse.ArgumentParser(
        description="VulnScan Agent - AI 驱动的代码漏洞扫描系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="要扫描的目标路径")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument(
        "-d", "--depth",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="扫描深度 (默认: standard)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="报告格式 (默认: markdown)"
    )
    parser.add_argument(
        "-o", "--output",
        default="./reports",
        help="报告输出目录 (默认: ./reports)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="禁用 AI 分析（仅使用规则引擎）"
    )

    args = parser.parse_args()

    print_banner()

    # 加载配置
    config = load_config(args.config)

    # 命令行参数覆盖配置
    config.setdefault("scan", {})["depth"] = args.depth
    config.setdefault("report", {})["format"] = args.format
    config.setdefault("report", {})["output_dir"] = args.output

    if args.no_ai:
        config["ai"] = {"provider": "none"}

    # 执行扫描
    coordinator = CoordinatorAgent(config)
    try:
        report = await coordinator.run(args.target)
        print_stats(report)
    except FileNotFoundError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n扫描已取消")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
