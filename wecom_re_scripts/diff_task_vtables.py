# diff_task_vtables.py — M1 补丁 · diff 每种消息类型独有的 vtable
# =============================================================================
#
# 用法：先跑 hunt_task_vtables.py --type <text|image|voice|video|file> ...
#      至少 2 种类型，越多越准
#      然后 python diff_task_vtables.py
#
# 输出：
#   1) 每种类型"独占"的 vtable（仅该类型出现，其他类型 0 次）
#   2) 每种类型"高峰远超其他"的 vtable（该类型 max_count 明显大于其他）
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


def _load(pattern: str) -> dict[str, dict]:
    """
    return { msg_type: { rva: {'max_count':n, 'seen_in':n, 'total_hits':n} } }
    如果同类型多个文件 → 取每 rva 的 max。
    """
    by_type: dict[str, dict] = {}
    for f in sorted(OUT_DIR.glob(pattern)):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] skip {f.name}: {e}")
            continue
        mt = data.get("msg_type", "?")
        summary = data.get("summary") or {}
        if mt not in by_type:
            by_type[mt] = {}
        for rva, s in summary.items():
            prev = by_type[mt].get(rva, {"max_count": 0, "seen_in": 0, "total_hits": 0})
            by_type[mt][rva] = {
                "max_count": max(prev["max_count"], s["max_count"]),
                "seen_in":   max(prev["seen_in"],   s["seen_in"]),
                "total_hits": prev["total_hits"] + s["total_hits"],
            }
    return by_type


def print_exclusive(by_type: dict[str, dict], min_max_count: int = 2) -> None:
    """每种类型独占：仅该类型出现的 vtable（其他类型完全没见过）。"""
    print()
    print("=" * 80)
    print(f"① 每种类型独占 vtable（其他类型完全没见过，且 max_count>={min_max_count}）")
    print("=" * 80)
    types = sorted(by_type.keys())
    for mt in types:
        others = [t for t in types if t != mt]
        exclusive = []
        for rva, s in by_type[mt].items():
            if s["max_count"] < min_max_count:
                continue
            in_others = any(rva in by_type[t] for t in others)
            if not in_others:
                exclusive.append((rva, s))
        exclusive.sort(key=lambda x: -x[1]["max_count"])
        print(f"\n  [{mt}]  {len(exclusive)} exclusive vtables")
        for rva, s in exclusive[:30]:
            print(f"    RVA {rva:<12}  max={s['max_count']:<3}  "
                  f"seen_in={s['seen_in']}  total={s['total_hits']}")


def print_dominant(by_type: dict[str, dict], ratio: float = 3.0) -> None:
    """每种类型"高峰远超其他"：max_count 比其他类型的最大值高 `ratio` 倍。"""
    print()
    print("=" * 80)
    print(f"② 每种类型 max_count >= 其他类型 {ratio}倍 的 vtable")
    print("=" * 80)
    types = sorted(by_type.keys())
    all_rvas: set[str] = set()
    for mt in types:
        all_rvas.update(by_type[mt].keys())

    for mt in types:
        others = [t for t in types if t != mt]
        dominant = []
        for rva in all_rvas:
            my = by_type[mt].get(rva, {}).get("max_count", 0)
            if my < 2:
                continue
            other_max = max(
                (by_type[t].get(rva, {}).get("max_count", 0) for t in others),
                default=0,
            )
            if other_max == 0 and my >= 2:
                # 已在 ① 里
                continue
            if my >= other_max * ratio:
                dominant.append((rva, my, other_max))
        dominant.sort(key=lambda x: -x[1])
        print(f"\n  [{mt}]  {len(dominant)} dominant vtables")
        for rva, my, other_max in dominant[:20]:
            print(f"    RVA {rva:<12}  {mt}_max={my:<3}  others_max={other_max}")


def print_summary(by_type: dict[str, dict]) -> None:
    print()
    print("=" * 80)
    print("③ 汇总")
    print("=" * 80)
    for mt, m in sorted(by_type.items()):
        n = len(m)
        total = sum(v["total_hits"] for v in m.values())
        print(f"  {mt:<12}  unique_vtables={n:<5}  total_hits_sum={total}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pattern", default="vtable_hunt_*.json")
    ap.add_argument("--min-max-count", type=int, default=2)
    ap.add_argument("--ratio", type=float, default=3.0)
    args = ap.parse_args(argv)

    by_type = _load(args.pattern)
    if not by_type:
        print(f"[!] no files matched '{args.pattern}' in {OUT_DIR}")
        return 1

    print(f"[*] loaded types: {sorted(by_type.keys())}")
    print_summary(by_type)
    print_exclusive(by_type, args.min_max_count)
    print_dominant(by_type, args.ratio)
    return 0


if __name__ == "__main__":
    sys.exit(main())
