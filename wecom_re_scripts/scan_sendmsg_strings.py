# scan_sendmsg_strings.py — P2 · 静态扫 SendMessage 相关字符串（第二十四轮起步）
# =============================================================================
#
# 前置结论（第二十三轮）：
#   RtlAllocateHeap 反查失败，buffer 来自 slab pool → 动态反查此路不通
#
# 本脚本目标：换静态路径
#   1. 扫 wxwork.exe 所有段找 SendMessage/PostSendMessage/logic:: 相关字符串
#   2. 对每个位置检查是不是 vtable 里的类名（RTTI 特征）
#   3. 输出候选 anchor 列表，供下一步 imm32 xref
#
# 用法（无需用户操作）：
#   & Python311 runtime/wecom_re/scan_sendmsg_strings.py
# =============================================================================

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', msg: 'wx base=' + wx.base + ' size=0x' + wx.size.toString(16)});

// 关键字候选 —— 覆盖 C++ 名称重整 (mangled) 和 raw class name
const KEYWORDS = [
    'PostSendMessageTask',
    'PostSendMessageTask2',
    'SendMessageTask',
    'logic::PostSendMessage',
    'logic::SendMessage',
    'CSendMessageTask',
    'CSendMessage',
    'MessageSendTask',
    'wework::logic::PostSend',
    'wework::logic::SendMessage',
    'CPostSendMessage',
    'PostSendMessage2',
    // 命名格式变体
    'class wework::logic::PostSendMessage',
    'class wework::logic::SendMessage',
];

function bytesToAscii(bytes){
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '\x01';
    }
    return s;
}

function stringToBytes(s){
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
}

// 手写 pattern：把 keyword 转成 Frida scan pattern (hex bytes)
function kwToPattern(kw){
    let p = '';
    for (let i = 0; i < kw.length; i++){
        const c = kw.charCodeAt(i).toString(16).padStart(2, '0');
        p += (i ? ' ' : '') + c;
    }
    return p;
}

// 扫单个 keyword，跨所有 wxwork.exe 段
function scanKeyword(kw){
    const results = [];
    const pattern = kwToPattern(kw);
    try {
        const matches = Memory.scanSync(wx.base, wx.size, pattern);
        for (let i = 0; i < matches.length; i++){
            const addr = matches[i].address;
            const off = addr.sub(wx.base).toUInt32();
            // 尝试读完整字符串（末尾 nul）
            let full = '';
            try {
                const bytes = new Uint8Array(addr.readByteArray(256));
                for (let j = 0; j < bytes.length; j++){
                    const b = bytes[j];
                    if (b === 0) break;
                    if (b >= 0x20 && b <= 0x7e) full += String.fromCharCode(b);
                    else { full += '<0x' + b.toString(16) + '>'; break; }
                }
            } catch(e){}
            results.push({
                offset: '0x' + off.toString(16),
                va: '0x' + addr.toUInt32().toString(16),
                keyword: kw,
                full: full
            });
        }
    } catch(e){
        send({t:'error', msg: 'scan(' + kw + ') failed: ' + e.message});
    }
    return results;
}

rpc.exports = {
    scan: function(){
        const all = [];
        for (let i = 0; i < KEYWORDS.length; i++){
            const kw = KEYWORDS[i];
            const r = scanKeyword(kw);
            send({t:'progress', kw: kw, hits: r.length});
            for (let j = 0; j < r.length; j++) all.push(r[j]);
        }
        return all;
    }
};

send({t:'ready'});
"""


def get_wxwork_pid() -> int:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.split()[-1])
    raise RuntimeError("WXWork.exe :9882 not listening")


def main() -> int:
    pid = get_wxwork_pid()
    print(f"[*] attaching PID={pid}")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] {p['msg']}")
            elif t == "progress":
                print(f"    - {p['kw']:50s}  {p['hits']} hit(s)")
            elif t == "error":
                print(f"[!] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print("[*] scanning...")
    t0 = time.monotonic()
    results = script.exports_sync.scan()
    print(f"[+] scan done in {time.monotonic()-t0:.1f}s, {len(results)} total hits")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"sendmsg_strings_{ts}.json"
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {out_path.name}")

    print()
    print("=" * 60)
    print("命中详情：")
    for r in results:
        print(f"  offset={r['offset']:10s}  va={r['va']:10s}  kw={r['keyword']!r}")
        print(f"    full={r['full']!r}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
