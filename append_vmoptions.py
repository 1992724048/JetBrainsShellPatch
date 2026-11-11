# -*- coding: utf-8 -*-
"""
遍历 JetBrains 安装目录，向所有 *.vmoptions 文件末尾追加 ja-netfilter 配置
- 用户目录自动获取（不硬编码 A1992）
- ja-netfilter 路径 = 本脚本所在目录下的 ./ja-netfilter/
"""
import os
import sys
from pathlib import Path

# 1. 自动获取用户目录，例如 C:\Users\A1992
user_home = Path(os.path.expanduser("~"))

paths = [
    Path(r"C:/Program Files/JetBrains/"),
    user_home / "AppData" / "Local" / "JetBrains" / "Installations",
]

# 2. 脚本所在目录，即 ./ 路径；ja-netfilter 放在脚本同级的 ja-netfilter 子目录
script_dir = Path(os.path.dirname(os.path.abspath(__file__))).resolve()
ja_netfilter_dir = script_dir / "ja-netfilter"

APPEND_LINES = [
    "-javaagent:{}".format(str(ja_netfilter_dir / "ja-netfilter.jar")),
    "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED",
    "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED",
]


def read_text_smart(file_path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "gbk"):
        try:
            return file_path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return file_path.read_text(encoding="utf-8", errors="replace")


def process_vmoptions(file_path: Path):
    content = read_text_smart(file_path)

    # 3. 已配置过则跳过，避免重复追加
    if "ja-netfilter.jar" in content:
        print("[跳过-已配置] {}".format(file_path))
        return

    # 保证原文件末尾有换行后再追加
    if content and not content.endswith("\n"):
        content += "\n"

    content += "\n".join(APPEND_LINES) + "\n"
    file_path.write_text(content, encoding="utf-8")
    print("[已追加] {}".format(file_path))


def main():
    if not ja_netfilter_dir.exists():
        print("[警告] 未找到 ja-netfilter 目录: {}".format(ja_netfilter_dir), file=sys.stderr)

    found = 0
    for base in paths:
        if not base.exists():
            print("[目录不存在] {}".format(base))
            continue
        for vm in sorted(base.rglob("*.vmoptions")):
            found += 1
            process_vmoptions(vm)

    if found == 0:
        print("未找到任何 .vmoptions 文件。")
    else:
        print("处理完成，共扫描 {} 个 .vmoptions 文件。".format(found))

    input("\n按回车键退出...")


if __name__ == "__main__":
    main()