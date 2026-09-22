# diff_sendchain.py — A/B 差分 sendchain ndjson，定位 dest_conv_id 偏移
# ================================================================
#
# 用法：
#   & Python311 runtime/wecom_re/diff_sendchain.py \
#         sendchain_<TS_A>_A.ndjson sendchain_<TS_B>_B.ndjson
#
# 原理：
#   两轮转发的 this / stack 字段大量重合（发送方 con_id、发送人昵称、
#   client_msg_id 生成逻辑等相同）。真正**随目标会话变化的字段**才是
#   我们要的 dest_conv_id / recv_uid / msg_ids 数组指针。
#
# 输出：
#   1. 每个 hookedAddr 的 (round, hit#) → 关键字段快照
#   2. 只出现在 B 侧的字符串（外部联系人特征）
#   3. this+offset 处 deref string 的 A/B 差异表
# ================================================================

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)


def load(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def collect_strings(hit: dict[str, Any]) -> dict[str, str]:
    """从 this_dw / stack 中提取 offset → 可读字符串（cstr 优先，否则 u16）。"""
    out = {}
    for e in hit.get("this_dw", []) or []:
        d = e.get("deref") or {}
        s = d.get("cstr") or d.get("u16")
        if s and 3 <= len(s) <= 400:
            out[f"this+0x{e['off']:02x}"] = s
    for e in hit.get("stack", []) or []:
        d = e.get("deref") or {}
        s = d.get("cstr") or d.get("u16")
        if s and 3 <= len(s) <= 400:
            out[f"stk[{e['slot']:02d}]"] = s
    return out


def collect_raw(hit: dict[str, Any]) -> dict[str, str]:
    """收集 this / stack 各 offset 的 raw uint32 值。"""
    out = {}
    for e in hit.get("this_dw", []) or []:
        v = e.get("raw_hex")
        if v:
            out[f"this+0x{e['off']:02x}"] = v
    for e in hit.get("stack", []) or []:
        v = e.get("raw_hex")
        if v:
            out[f"stk[{e['slot']:02d}]"] = v
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file_a", type=Path, help="round A 的 ndjson")
    ap.add_argument("file_b", type=Path, help="round B 的 ndjson")
    args = ap.parse_args()

    a_hits = load(args.file_a)
    b_hits = load(args.file_b)
    print(f"[*] A: {len(a_hits)} hits from {args.file_a.name}")
    print(f"[*] B: {len(b_hits)} hits from {args.file_b.name}")

    # 按 hookedAddr 分组
    by_addr_a: dict[str, list[dict]] = defaultdict(list)
    by_addr_b: dict[str, list[dict]] = defaultdict(list)
    for h in a_hits:
        by_addr_a[h["hookedAddr"]].append(h)
    for h in b_hits:
        by_addr_b[h["hookedAddr"]].append(h)

    all_addrs = sorted(set(by_addr_a) | set(by_addr_b),
                       key=lambda x: int(x, 16))
    print(f"[*] hooked addrs = {len(all_addrs)}")
    print()

    for addr in all_addrs:
        la, lb = by_addr_a[addr], by_addr_b[addr]
        if not la and not lb:
            continue
        print("=" * 70)
        print(f"  addr = {addr}   |  A:{len(la)} hits    B:{len(lb)} hits")
        print("=" * 70)

        # 1) A 所有 hit 的字符串并集
        a_strs = defaultdict(set)   # offset → {str values across A hits}
        b_strs = defaultdict(set)
        for h in la:
            for k, v in collect_strings(h).items():
                a_strs[k].add(v)
        for h in lb:
            for k, v in collect_strings(h).items():
                b_strs[k].add(v)

        # 2) 各 offset 分类
        stable_shared: list[tuple[str, str]] = []   # A/B 都出现且相同
        varies_within_a: list[tuple[str, list[str]]] = []  # A 内部就变化
        differs_ab: list[tuple[str, str, str]] = []  # A/B 差异（关键！）
        only_b: list[tuple[str, list[str]]] = []
        only_a: list[tuple[str, list[str]]] = []

        all_off = sorted(set(a_strs) | set(b_strs),
                         key=lambda k: (k[:5], k))
        for off in all_off:
            av = a_strs.get(off, set())
            bv = b_strs.get(off, set())
            if av and not bv:
                only_a.append((off, sorted(av)))
            elif bv and not av:
                only_b.append((off, sorted(bv)))
            elif av == bv and len(av) == 1:
                stable_shared.append((off, next(iter(av))))
            elif av == bv:
                pass  # 同集合但多值 → 大概率通用字段
            else:
                # A 有 x, B 有 y, x != y → 关键差异
                differs_ab.append((off, "|".join(sorted(av))[:80],
                                   "|".join(sorted(bv))[:80]))

        # 3) 打印顺序：differs_ab（重点）→ only_b → only_a → stable
        if differs_ab:
            print("  [★ A/B 差异字段（候选 dest_conv_id / recv_uid）]")
            for off, av, bv in differs_ab:
                print(f"    {off:20s}  A = {av!r}")
                print(f"    {' '*20}  B = {bv!r}")
        if only_b:
            print("  [B-only 字段（可能仅外部会话才有的成员）]")
            for off, vs in only_b:
                print(f"    {off:20s}  B = {vs[0][:80]!r}"
                      + (f" ...(+{len(vs)-1})" if len(vs) > 1 else ""))
        if only_a:
            print("  [A-only 字段]")
            for off, vs in only_a:
                print(f"    {off:20s}  A = {vs[0][:80]!r}"
                      + (f" ...(+{len(vs)-1})" if len(vs) > 1 else ""))
        if stable_shared:
            print(f"  [稳定共享字段 = {len(stable_shared)} 项（发送方/自己相关）]")
            for off, v in stable_shared[:5]:
                print(f"    {off:20s}  = {v[:80]!r}")
            if len(stable_shared) > 5:
                print(f"    ... 另 {len(stable_shared) - 5} 项省略")
        print()

    print()
    print("=" * 70)
    print("  🎯 下一步：')A/B 差异字段' 中形如 'S:xxx_yyy'、long 数字串、")
    print("     或联系人 UID 的 offset —— 就是 dest_conv_id 的位置。")
    print("     然后可用 NativeFunction(ptr(<PostSendMessageTask2>), ...) 直调。")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
