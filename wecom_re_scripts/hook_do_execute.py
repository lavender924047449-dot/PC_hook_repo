# hook_do_execute.py — P2 · Hook PostSendMessageTask2 成员方法找 conv_id 字段
# =============================================================================
# 第二十四轮 · find_do_execute.py 输出的 4 个候选函数入口全部 hook：
#   0x34eea12 (DoExecute) / 0x34fab12 (need upload resource)
#   0x350f772 (upload resource) / 0x35034e2 (SendMessage)
# onEnter dump `this` (ecx) 前 0x100 字节，遍历每个 dword 看是不是 char* 指向
# S:/R:/G: conv_id。如命中 → 拿到独立 conv_id 字段偏移 → hijack 立即可用。
#
# 用户配合：90 秒窗口内做 2-3 次 FTA→外部联系人 转发
# 用法：& Python311 runtime/wecom_re/hook_do_execute.py --duration 90
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

# 4 个 PostSendMessageTask2 成员方法候选入口（RELATIVE offset 到 wxwork.exe base）
# + wwdb worker 作为控制组（已知一定 hit）
# 原第二十四轮 base=0x970000 得到的绝对 VA - 0x970000 = 下面这些偏移
CANDIDATES_OFFSETS = [
    ("0x2b7ea12", "DoExecute (execte, conversationId = )"),
    ("0x2b8ab12", "need upload resource conversationId ="),
    ("0x2b9f772", "upload resource conversationId ="),
    ("0x2b934e2", "SendMessage tmp_task_key"),
    ("0x846820e", "[CONTROL] wwdb worker (0x8dd8202 - 0x970000)"),
]

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg: 'wx base=' + wx.base});

const CONV_RE_ANCHORED = /^(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;
const CONV_RE_LOOSE    = /(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;

let COUNT = 0;

function bytesToPrintable(bytes){
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '\x01';
    }
    return s;
}

function readCStr(p, cap){
    try { return p.readCString(cap || 128); } catch(e){ return null; }
}

// 直接扫 this 内存块找 S:xxx_yyy 明文子串（inline）
function scanInlineConvIds(base, size){
    let bytes = null;
    try { bytes = new Uint8Array(base.readByteArray(size)); }
    catch(e) { return []; }
    if (!bytes) return [];
    const s = bytesToPrintable(bytes);
    const results = [];
    let searchFrom = 0;
    while (true){
        const m = CONV_RE_LOOSE.exec(s.substring(searchFrom));
        if (!m) break;
        const absAt = searchFrom + m.index;
        results.push({at: absAt, conv: m[0]});
        searchFrom = absAt + m[0].length;
    }
    return results;
}

// 对每个 dword 指针，间接读一段找 S:xxx_yyy
function scanIndirectConvIds(base, maxOff){
    const results = [];
    for (let off = 0; off <= maxOff; off += 4){
        let raw = 0;
        try { raw = base.add(off).readU32(); } catch(e){ continue; }
        if (raw < 0x10000) continue;
        // 直接 char* 首字节起
        const cs = readCStr(ptr(raw), 128);
        if (cs){
            const m = CONV_RE_ANCHORED.exec(cs);
            if (m){
                results.push({
                    field_offset: '0x' + off.toString(16),
                    ptr: '0x' + raw.toString(16),
                    kind: 'char*_direct',
                    conv_id: m[0]
                });
                continue;
            }
        }
        // 间接 buffer 前 256 字节找子串（例如指向一个包含 conv_id 的结构）
        let bytes = null;
        try { bytes = new Uint8Array(ptr(raw).readByteArray(256)); }
        catch(e){}
        if (bytes){
            const s = bytesToPrintable(bytes);
            const m = CONV_RE_LOOSE.exec(s);
            if (m){
                results.push({
                    field_offset: '0x' + off.toString(16),
                    ptr: '0x' + raw.toString(16),
                    kind: 'indirect_buf',
                    at: m.index,
                    conv_id: m[0]
                });
            }
        }
    }
    return results;
}

function scanThis(ecx, inlineSize, indirectMax){
    const inline_hits = scanInlineConvIds(ecx, inlineSize);
    const indirect_hits = scanIndirectConvIds(ecx, indirectMax);
    return {inline_hits: inline_hits, indirect_hits: indirect_hits};
}

let TOTAL_ENTRY = {};

rpc.exports = {
    installAll: function(addrList){
        for (let i = 0; i < addrList.length; i++){
            const item = addrList[i];
            // 支持 addr='0x2b7ea12' 相对偏移，或 addr='+0x2b7ea12' 明确相对
            const off = parseInt(item.addr, 16);
            const t = WXBASE.add(off);
            const label = item.label + '  [wxbase+' + item.addr + ' = ' + t + ']';
            const key = item.addr;
            TOTAL_ENTRY[key] = 0;
            Interceptor.attach(t, {
                onEnter: function(){
                    TOTAL_ENTRY[key] = (TOTAL_ENTRY[key] || 0) + 1;
                    const ecx = this.context.ecx;
                    const esp = this.context.esp;
                    // 每个候选只报前 2 次（避免刷屏）
                    if (TOTAL_ENTRY[key] > 2) return;
                    const info = scanThis(ecx, 0x1000 /* 4KB inline */, 0x100 /* first 256B indirect */);
                    COUNT++;
                    // dump this 前 0x80 diagnostic
                    const dw = [];
                    for (let off = 0; off <= 0x80; off += 4){
                        let v = 0;
                        try { v = ecx.add(off).readU32(); } catch(e){}
                        dw.push('0x' + v.toString(16));
                    }
                    // esp 参数区
                    const args = [];
                    for (let off = 0; off <= 0x20; off += 4){
                        let v = 0;
                        try { v = esp.add(off).readU32(); } catch(e){}
                        args.push('0x' + v.toString(16));
                    }
                    send({t:'hit',
                          seq: COUNT,
                          addr: key,
                          abs: t.toString(),
                          label: label,
                          this_addr: ecx.toString(),
                          esp: esp.toString(),
                          tid: this.threadId,
                          entry_count: TOTAL_ENTRY[key],
                          this_dw: dw,
                          args: args,
                          inline_hits: info.inline_hits,
                          indirect_hits: info.indirect_hits});
                }
            });
            send({t:'installed', addr: key, abs: t.toString(), label: label});
        }
    },
    stats: function(){ return {count: COUNT, entry: TOTAL_ENTRY}; }
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=90)
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID={pid}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"do_execute_hits_{ts}.ndjson"

    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    hits: list = []
    ready = {"v": False}
    fp = ndjson_path.open("a", encoding="utf-8")

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] {p['msg']}")
            elif t == "installed":
                print(f"[+] hook @ {p['addr']}  ({p['label']})")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                print(f"\n[HIT #{p['seq']}] {p['addr']}  ({p['label']})")
                print(f"    this={p['this_addr']}  tid={p['tid']}  entry={p['entry_count']}")
                inline = p.get("inline_hits", [])
                indirect = p.get("indirect_hits", [])
                if inline:
                    print(f"    ★ INLINE conv_id in this-object:")
                    for h in inline:
                        print(f"        [this+0x{h['at']:x}]  {h['conv']!r}")
                if indirect:
                    print(f"    ★ INDIRECT (通过 dword ptr) conv_id:")
                    for h in indirect:
                        extra = f"  at buf+0x{h.get('at', 0):x}" if h.get('kind') == 'indirect_buf' else ""
                        print(f"        [this+{h['field_offset']}] → {h['ptr']}  kind={h['kind']}{extra}  conv={h['conv_id']!r}")
                if not inline and not indirect:
                    print(f"    ❌ 无 conv_id 明文（可能加密/编码/在 sub-object 更深处）")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    script.exports_sync.install_all([{"addr": a, "label": l} for a, l in CANDIDATES_OFFSETS])
    print(f"\n[*] armed for {args.duration}s. 现在做 2-3 次 FTA→外部联系人 转发\n")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)

    fp.close()

    # 分析：每个函数入口的 conv_id 字段偏移分布（inline + indirect 合并）
    offset_by_addr: dict[str, Counter] = {}
    for h in hits:
        addr = h["addr"]
        if addr not in offset_by_addr:
            offset_by_addr[addr] = Counter()
        for hh in h.get("inline_hits", []):
            offset_by_addr[addr][f"inline+0x{hh['at']:x}"] += 1
        for hh in h.get("indirect_hits", []):
            key = f"deref[{hh['field_offset']}]:{hh['kind']}"
            offset_by_addr[addr][key] += 1

    st = script.exports_sync.stats()
    print()
    print("=" * 80)
    print(f"[+] final: total conv-hit reports = {len(hits)}")
    print(f"[+] entry counts: {json.dumps(st.get('entry', {}), indent=2)}")
    for addr, label in CANDIDATES_OFFSETS:
        oc = offset_by_addr.get(addr, Counter())
        entry = st.get("entry", {}).get(addr, 0)
        print(f"\n  {addr}  ({label})  entered={entry}x")
        if not oc:
            print(f"    ❌ 无 conv_id 字段命中")
        else:
            for off, n in oc.most_common(10):
                print(f"    ★ [this+{off}]  seen={n}x")

    print(f"\n[+] → {ndjson_path.name}")
    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
