# diff_package_layout.py — M1 · 对比不同消息类型 package dump 找差异字段
# =============================================================================
#
# 输入：runtime/wecom_re/pkg_layout_<type>_<ts>.json  （由 dump_package_layout.py 产生）
# 输出：
#   1) 每个 offset 上 dword 在各类型间的值分布（找 content_type 这类"每种类型固定不同值"）
#   2) 每个类型独有的 std::string 字段（找 resource_url / media_id 这类"仅某类型才有"）
#   3) 稳定指针字段的分布（找 payload_ptr 这类"每类型都有但指向不同结构"）
#
# 用法：python runtime/wecom_re/diff_package_layout.py
#      （默认扫描 OUT_DIR 里所有 pkg_layout_*.json，按类型分组）
# =============================================================================

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"


def _pick_conv(rec: dict) -> str:
    for s in rec.get("pkg_strings") or []:
        if s.get("off") == "0x28":
            return s.get("str_utf8") or ""
    return ""


def _load_by_type(pattern: str) -> dict[str, list[dict]]:
    """按 msg_type 分组，只保留 conv_id 有效的 task。"""
    by_type: dict[str, list[dict]] = defaultdict(list)
    for f in sorted(OUT_DIR.glob(pattern)):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] skip {f.name}: {e}")
            continue
        mt = data.get("msg_type") or f.stem.split("_")[2] if len(f.stem.split("_")) > 2 else "?"
        for t in data.get("tasks") or []:
            if _pick_conv(t):
                by_type[mt].append(t)
    return by_type


def _dword_at(task: dict, off: str) -> int | None:
    for d in task.get("pkg_dwords") or []:
        if d.get("off") == off:
            return d.get("u32")
    return None


def _string_at(task: dict, off: str) -> dict | None:
    for s in task.get("pkg_strings") or []:
        if s.get("off") == off:
            return s
    return None


def _all_dword_offsets(by_type: dict[str, list[dict]]) -> list[str]:
    offs: set[str] = set()
    for tasks in by_type.values():
        for t in tasks:
            for d in t.get("pkg_dwords") or []:
                offs.add(d.get("off"))
    def _key(o):
        try: return int(o, 16)
        except: return 1 << 30
    return sorted(offs, key=_key)


def _all_string_offsets(by_type: dict[str, list[dict]]) -> list[str]:
    offs: set[str] = set()
    for tasks in by_type.values():
        for t in tasks:
            for s in t.get("pkg_strings") or []:
                offs.add(s.get("off"))
    def _key(o):
        try: return int(o, 16)
        except: return 1 << 30
    return sorted(offs, key=_key)


def print_dword_distribution(by_type: dict[str, list[dict]]) -> None:
    print()
    print("=" * 90)
    print("① package 各 offset 处 dword(u32) 分布（找 content_type 这类每类型固定的字段）")
    print("=" * 90)
    print(f"{'off':<8}", end="")
    types = sorted(by_type.keys())
    for mt in types: print(f"| {mt:<24}", end="")
    print()
    print("-" * (8 + 26 * len(types)))
    for off in _all_dword_offsets(by_type):
        vals_per_type: dict[str, list[int]] = {}
        for mt in types:
            vs = []
            for t in by_type[mt]:
                v = _dword_at(t, off)
                if v is not None: vs.append(v)
            vals_per_type[mt] = vs
        # 只显示"每类型内部值稳定"且"跨类型有差异"的行
        stable = all(len(set(vs)) <= 2 for vs in vals_per_type.values())
        differs = len(set(tuple(sorted(set(vs))) for vs in vals_per_type.values() if vs)) > 1
        if not (stable and differs): continue
        # 排除全 0 / 全指针（用第一个任务的 hint 大致判断）
        hint = "int"
        for mt in types:
            if by_type[mt]:
                for d in by_type[mt][0].get("pkg_dwords") or []:
                    if d.get("off") == off:
                        hint = d.get("hint") or "int"
                        break
                break
        if hint == "ptr": continue  # 指针值本身跨会话就变，不算 content_type 候选
        print(f"{off:<8}", end="")
        for mt in types:
            vs = vals_per_type[mt]
            if not vs:
                print(f"| {'-':<24}", end="")
            else:
                uniq = sorted(set(vs))
                s = ",".join(hex(v) if v > 9 else str(v) for v in uniq[:3])
                print(f"| {s:<24}", end="")
        print()


def print_string_uniqueness(by_type: dict[str, list[dict]]) -> None:
    print()
    print("=" * 90)
    print("② 各 offset 处 std::string 分布（找 resource_url / media_id / silk_md5 类）")
    print("=" * 90)
    print(f"{'off':<8}", end="")
    types = sorted(by_type.keys())
    for mt in types: print(f"| {mt:<24}", end="")
    print()
    print("-" * (8 + 26 * len(types)))
    for off in _all_string_offsets(by_type):
        row: dict[str, list[str]] = {}
        any_present = False
        for mt in types:
            samples = []
            for t in by_type[mt]:
                s = _string_at(t, off)
                if s and s.get("size", 0) >= 1:
                    txt = s.get("str_utf8") or ""
                    samples.append(f"{s.get('size')}B:{txt[:16]}")
                    any_present = True
            row[mt] = samples
        if not any_present: continue
        # 只显示"某些类型有、某些类型没有"的（真差异）
        has = [mt for mt in types if row[mt]]
        if len(has) == len(types): continue
        print(f"{off:<8}", end="")
        for mt in types:
            if not row[mt]:
                print(f"| {'-':<24}", end="")
            else:
                one = row[mt][0]
                print(f"| {one[:24]:<24}", end="")
        print()


def print_summary(by_type: dict[str, list[dict]]) -> None:
    print()
    print("=" * 90)
    print("③ 汇总")
    print("=" * 90)
    for mt in sorted(by_type.keys()):
        tasks = by_type[mt]
        conv_ids = {_pick_conv(t) for t in tasks}
        n_strings = [len(t.get("pkg_strings") or []) for t in tasks]
        print(f"  {mt:<12} tasks={len(tasks):<3}  conv_ids={len(conv_ids):<3}  "
              f"pkg_strings/task={min(n_strings) if n_strings else 0}-"
              f"{max(n_strings) if n_strings else 0}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", default="pkg_layout_*.json")
    args = ap.parse_args(argv)

    by_type = _load_by_type(args.pattern)
    if not by_type:
        print(f"[!] no dump files matched '{args.pattern}' in {OUT_DIR}")
        print(f"[i] 先跑：python runtime/wecom_re/dump_package_layout.py --type text 等")
        return 1

    print(f"[*] loaded {sum(len(v) for v in by_type.values())} tasks across "
          f"{len(by_type)} type(s): {sorted(by_type.keys())}")

    print_summary(by_type)
    print_dword_distribution(by_type)
    print_string_uniqueness(by_type)
    return 0


if __name__ == "__main__":
    sys.exit(main())
