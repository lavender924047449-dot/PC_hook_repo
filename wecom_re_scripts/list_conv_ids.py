# list_conv_ids.py — 扫堆列出所有 conv_id 候选
# =============================================================================
# 从企微 heap 里扫所有 std::string 结构，筛出 conv_id 格式：
#   - S:{16}_{16}  单聊 (35 chars)
#   - R:{17+}      群/room (18+ chars)
#   - FILEASSIST   FTA
#
# 用户拿到这个列表后挑一个愿意作为 hijack v2 测试目标的 uin。
# =============================================================================

from __future__ import annotations
import argparse
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', msg: 'wx base=' + wx.base});

rpc.exports = {
    findConvIds: function(){
        const results = {S: [], R: [], FILEASSIST: 0};
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});

        // 扫 'S:' 开头 (0x53 0x3a)，然后校验是否 std::string
        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            try {
                // 找 "S:" + digit
                const hits = Memory.scanSync(r.base, r.size, '53 3a 3?');
                for (let j = 0; j < hits.length; j++){
                    const p = hits[j].address;
                    // 尝试读 35 字节，看是否符合 S:xxx_yyy pattern
                    let bytes;
                    try { bytes = new Uint8Array(p.readByteArray(36)); }
                    catch(e){ continue; }
                    let s = '';
                    for (let k = 0; k < 35 && k < bytes.length; k++){
                        const b = bytes[k];
                        if (b < 0x20 || b > 0x7e) { s = ''; break; }
                        s += String.fromCharCode(b);
                    }
                    if (!s) continue;
                    // 严格 pattern: S:16digit_16digit
                    if (/^S:\d{16}_\d{16}$/.test(s)){
                        results.S.push(s);
                    }
                }
            } catch(e){}

            // R: 群
            try {
                const hits = Memory.scanSync(r.base, r.size, '52 3a 3?');
                for (let j = 0; j < hits.length; j++){
                    const p = hits[j].address;
                    let bytes;
                    try { bytes = new Uint8Array(p.readByteArray(24)); }
                    catch(e){ continue; }
                    let s = '';
                    let terminated = false;
                    for (let k = 0; k < 24 && k < bytes.length; k++){
                        const b = bytes[k];
                        if (b >= 0x30 && b <= 0x39){ s += String.fromCharCode(b); }
                        else if (k >= 3 && (b === 0 || b < 0x20 || b > 0x7e)){ terminated = true; break; }
                        else if (k >= 2 && (b < 0x30 || b > 0x39)){ break; }
                        else if (k === 0){ s = 'R'; }
                        else if (k === 1){ s = 'R:'; }
                    }
                    // 简化：直接检查前 3 字节 R:数字，然后读 pure digits until non-digit
                    if (bytes[0] === 0x52 && bytes[1] === 0x3a && bytes[2] >= 0x30 && bytes[2] <= 0x39){
                        let full = 'R:';
                        for (let k = 2; k < 24; k++){
                            const b = bytes[k];
                            if (b >= 0x30 && b <= 0x39) full += String.fromCharCode(b);
                            else break;
                        }
                        if (full.length >= 15 && full.length <= 22){
                            results.R.push(full);
                        }
                    }
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

    print(f"[*] scanning heap for conv_id patterns...")
    t0 = time.monotonic()
    res = script.exports_sync.find_conv_ids()
    print(f"[*] scan done in {time.monotonic()-t0:.1f}s")

    single = Counter(res.get("S", []))
    room = Counter(res.get("R", []))

    print(f"\n{'='*80}")
    print(f"[+] 单聊 conv_id (S:xxx_yyy)，共 {sum(single.values())} 命中 / {len(single)} 唯一：")
    for s, cnt in single.most_common(30):
        # 从 S:selfuin_peeruin 提取 peer_uin
        parts = s.split("_")
        peer = parts[1] if len(parts) == 2 else "?"
        print(f"    ×{cnt:3d}  {s}   → peer_uin={peer}")

    print(f"\n[+] 群 conv_id (R:xxx)，共 {sum(room.values())} 命中 / {len(room)} 唯一：")
    for s, cnt in room.most_common(20):
        print(f"    ×{cnt:3d}  {s}")

    try: script.unload(); session.detach()
    except Exception: pass


if __name__ == "__main__":
    main()
