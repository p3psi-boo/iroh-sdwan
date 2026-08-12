#!/usr/bin/env python3
"""检查仓库 Markdown 文件中的本地相对链接。"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")


def markdown_files() -> list[Path]:
    return sorted([*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md")])


def local_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split("#", maxsplit=1)[0].strip()
    if not target or "://" in target or target.startswith("mailto:"):
        return None
    return source.parent / target


def main() -> int:
    errors: list[str] = []
    sources = markdown_files()
    for source in sources:
        content = source.read_text(encoding="utf-8")
        for raw_target in LINK_PATTERN.findall(content):
            target = local_target(source, raw_target)
            if target is not None and not target.exists():
                errors.append(
                    f"{source.relative_to(ROOT)}: {raw_target} 指向不存在的 {target.relative_to(ROOT)}"
                )

    if errors:
        print("文档链接检查失败：", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(f"文档链接检查通过：{len(sources)} 个 Markdown 文件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
