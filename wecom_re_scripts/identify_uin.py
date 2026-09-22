# identify_uin.py — 扫 uin 邻近字符串，识别联系人
# =============================================================================
# 企微堆里 Contact/User 对象中 uin 附近会有 name/nickname/wxid 字符串。
# 直接扫每个 uin 出现的位置 → dump 前后 256 字节 → 提取可读字符串。
# =============================================================================

from __future__ import annotations
import argparse
import re
import subprocess
import sys
import time
from collections import defaultdict


def extract_strings_from_hex(hex_str: str, min_len: int = 3) -> list[str]:
    """从 hex bytes 中提取可打印/UTF-8 字符串。"""
    if not hex_str:
        return []
    try:
        data = bytes.fromhex(hex_str)
    except Exception:
        return []
    strs = []
    i = 0
    n = len(data)
    while i < n:
        # 从 i 开始，尝试解码尽可能长的合法 UTF-8 序列
        start = i
        cur = bytearray()
        while i < n:
            b = data[i]
            if b == 0:
                break
            # 简单启发：ASCII 可见字符 或 UTF-8 高位字节
            if b == 0x0a or b == 0x0d or b == 0x09 or (0x20 <= b <= 0x7e) or b >= 0x80:
                cur.append(b)
                i += 1
            else:
                break
        if len(cur) >= min_len:
            try:
                s = cur.decode("utf-8", errors="ignore").strip()
                if s and len(s) >= min_len:
                    strs.append(s)
            except Exception:
                pass
        # 跳过 0
        while i < n and data[i] == 0:
            i += 1
        if i == start:
            i += 1
    return strs

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', msg: 'wx base=' + wx.base});

function bytesToHex(bytes){
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

rpc.exports = {
    findUin: function(uinStr, contextBefore, contextAfter){
        const results = [];
        const uinBytes = [];
        for (let i = 0; i < uinStr.length; i++) uinBytes.push(uinStr.charCodeAt(i));
        const pattern = uinBytes.map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ');

        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        let hitCount = 0;
        const MAX_HITS = 200;
        for (let i = 0; i < ranges.length && hitCount < MAX_HITS; i++){
            const r = ranges[i];
            try {
                const ms = Memory.scanSync(r.base, r.size, pattern);
                for (let j = 0; j < ms.length && hitCount < MAX_HITS; j++){
                    const p = ms[j].address;
                    // 检查前一个字节：如果是 0-9 或 _，说明这是更长数字的一部分，跳过
                    let prevOk = true;
                    try {
                        const prev = p.sub(1).readU8();
                        if (prev >= 0x30 && prev <= 0x39) prevOk = false;
                    } catch(e){}
                    if (!prevOk) continue;
                    // 检查后一个字节：同样，如果是数字，跳过（不是完整 uin）
                    try {
                        const next = p.add(uinStr.length).readU8();
                        if (next >= 0x30 && next <= 0x39) continue;
                    } catch(e){}

                    // 读前后（原始 hex，Python 端解码）
                    let beforeHex = '';
                    let afterHex = '';
                    try {
                        beforeHex = bytesToHex(new Uint8Array(p.sub(contextBefore).readByteArray(contextBefore)));
                    } catch(e){}
                    try {
                        afterHex = bytesToHex(new Uint8Array(p.add(uinStr.length).readByteArray(contextAfter)));
                    } catch(e){}
                    results.push({
                        addr: p.toString(),
                        before_hex: beforeHex,
                        after_hex: afterHex
                    });
                    hitCount++;
                }
            } catch(e){}
        }
        return results;
    }
};
send({t:'ready'});
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("uins", nargs="+", help="要识别的 uin 列表")
    ap.add_argument("--context-before", type=int, default=128)
    ap.add_argument("--context-after", type=int, default=128)
    args = ap.parse_args()

    if args.pid:
        pid = args.pid
    else:
        r = subprocess.run(["powershell", "-Command",
                            "Get-Process WXWork -ErrorAction SilentlyContinue | "
                            "Sort-Object WorkingSet64 -Descending | "
                            "Select-Object -First 1 -ExpandProperty Id"],
                           capture_output=True, text=True, encoding="utf-8")
        pid = int(r.stdout.strip())
    print(f"[*] target PID={pid}")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}
    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready": ready["v"] = True
            elif p.get("t") == "info": print(f"    [D] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")
    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    for uin in args.uins:
        print(f"\n{'='*80}")
        print(f"[+] uin = {uin}")
        print(f"{'='*80}")
        hits = script.exports_sync.find_uin(uin, args.context_before, args.context_after)
        print(f"[+] {len(hits)} 命中")

        # 聚合所有邻居字符串（Python 端从 hex 解码）
        neighbor_counter: dict = defaultdict(int)
        for h in hits:
            for hex_field in ("before_hex", "after_hex"):
                strs = extract_strings_from_hex(h.get(hex_field, ""), min_len=3)
                for s in strs:
                    s = s.strip()
                    if not s: continue
                    if s.isdigit() and len(s) <= 20: continue
                    if len(s) < 2: continue
                    # 过滤明显的 SQL / 系统关键字
                    if s.upper() in ("SELECT", "FROM", "WHERE", "AND", "OR", "NULL", "INT", "TEXT"): continue
                    neighbor_counter[s] += 1

        # 排序：优先中文（含非 ASCII）、长度合理
        sorted_neighbors = sorted(neighbor_counter.items(), key=lambda x: (-x[1], len(x[0])))
        print(f"\n[+] uin={uin} 附近出现频率最高的字符串 (top 30)：")
        shown = 0
        for s, cnt in sorted_neighbors:
            if shown >= 30: break
            # 过滤明显的路径/系统字符串
            if s.startswith("C:\\") or s.startswith("/"): continue
            # 显示中文优先
            has_cn = any(ord(ch) > 0x7f for ch in s)
            marker = "🀄" if has_cn else "  "
            print(f"    ×{cnt:3d} {marker} {s!r}")
            shown += 1

    try: script.unload(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
