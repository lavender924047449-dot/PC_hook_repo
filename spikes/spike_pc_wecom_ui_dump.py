"""
手工抓取 PC 企业微信 UI 树快照。

用途：
- 升级企微版本后快速比对控件变化；
- locator 失效时提供现场诊断材料。
"""

from __future__ import annotations

from app.pc_wecom.pc_navigator import PCWeComNavigator


def main() -> int:
    nav = PCWeComNavigator()
    nav.ensure_running()
    fp = nav.dump_ui_tree("manual")
    print(f"UI dump -> {fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
