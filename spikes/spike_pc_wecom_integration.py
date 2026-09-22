"""
PC 企微半自动集成验证脚本。

目的：逐动作验证导航链路是否可用，并在失败时自动落 UI dump。

用法：
  python spikes/spike_pc_wecom_integration.py --contact 张三 --message "测试编码"
  python spikes/spike_pc_wecom_integration.py --backend null
"""

from __future__ import annotations

import argparse

from app.pc_wecom.locators import default_locators
from app.pc_wecom.pc_navigator import BubbleAnchor, NullBackend, PCWeComNavigator


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PC 企微半自动集成验证")
    p.add_argument("--backend", choices=["real", "null"], default="real")
    p.add_argument("--contact", default="文件传输助手")
    p.add_argument("--message", default="voice-3f8a2c9d1b47")
    return p


def main() -> int:
    args = build_parser().parse_args()
    backend = NullBackend() if args.backend == "null" else None
    nav = PCWeComNavigator(locators=default_locators(), backend=backend)

    print("[1/6] ensure_running")
    nav.ensure_running()
    print("[2/6] open_fta")
    nav.open_fta()
    print("[3/6] send_text")
    nav.send_text(args.message)
    print("[4/6] long_press_bubble")
    nav.long_press_bubble(BubbleAnchor(material_code=args.message, fingerprint_snippet=args.message[-6:]))
    print("[5/6] pick_forward_menu + search_contact")
    nav.pick_forward_menu()
    nav.search_and_pick_contact(args.contact)
    print("[6/6] confirm_send")
    nav.confirm_send()
    print("OK: 全部动作执行完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
