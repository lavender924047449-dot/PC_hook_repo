# spike_native_hijack.py — P2 · Native hijack PoC (v2 · buffer patching)
# ================================================================
#
# 更新（第二十轮）：
#   dryrun 证实 [ecx+0x64] 是**序列化 payload buffer**，conv_id 是里面
#   的子串（形如 "S:1688xxx_7881yyy"）。因此 hijack 策略调整为：
#     1. 在 payload buffer 头 4KB 内 Memory.scan 找 orig conv_id 子串
#     2. 长度一致时原地覆写（Memory.protect + writeByteArray）
#     3. 长度不一致时拒绝（避免破坏后续字段）
#
# 用法：
#   # dry：不改写，只报告"会覆写的位置和长度"
#   & Python311 spikes/spike_native_hijack.py \
#         --orig "S:1688855042791155_7881300363276969" \
#         --target "S:1688855042791155_XXXXXXXXXXXXXXXX" \
#         --dry --duration 60
#
#   # 真跑，一次自毁
#   & Python311 spikes/spike_native_hijack.py \
#         --orig "S:1688855042791155_7881300363276969" \
#         --target "S:1688855042791155_XXXXXXXXXXXXXXXX" \
#         --once --duration 180
#
# 注意事项：
#   · orig 必须来自 dryrun 里实际打印过的 conv_id（否则一定 miss）
#   · target 长度必须等于 orig 长度（否则脚本拒绝）
#   · S: 格式的 my_uin 是你自己的（1688855042791155），修改 peer_uin 部分即可
# ================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGET_ADDR = "0x8dd8202"

# 会扫描的 offset 集合（dryrun 已确认 conv_id 常出现在其中之一）
SCAN_OFFSETS = [0x64, 0x6c, 0x70, 0x48, 0x50, 0x58, 0x74, 0x7c, 0x80]

FRIDA_JS_TEMPLATE = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', base: wx.base.toString()});

const OFFSETS = __OFFSETS__;
let CFG = {
    orig: null,          // 原 conv_id 字符串
    orig_bytes: null,    // Uint8Array
    target: null,        // 目标 conv_id 字符串
    target_bytes: null,
    dry: true,
    once: false,
};
let STATS = {total: 0, matched: 0, patched: 0, len_mismatch: 0};

function toBytes(s){
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
    return b;
}
function bytesEqual(a, b, off, len){
    for (let i = 0; i < len; i++){
        if (a[off + i] !== b[i]) return false;
    }
    return true;
}
// 在 buffer 头 4KB 内找 orig_bytes 出现位置
function findOrig(bufPtr){
    if (bufPtr === 0) return -1;
    let bytes;
    try {
        bytes = new Uint8Array(ptr(bufPtr).readByteArray(4096));
    } catch(e){ return -1; }
    const N = bytes.length - CFG.orig_bytes.length;
    for (let i = 0; i <= N; i++){
        if (bytes[i] !== CFG.orig_bytes[0]) continue;
        if (bytesEqual(bytes, CFG.orig_bytes, i, CFG.orig_bytes.length)){
            return i;
        }
    }
    return -1;
}

rpc.exports = {
    configure: function(cfg){
        CFG.orig = cfg.orig;
        CFG.target = cfg.target;
        CFG.dry = !!cfg.dry;
        CFG.once = !!cfg.once;
        if (CFG.orig.length !== CFG.target.length){
            send({t:'err', msg:'orig length='+CFG.orig.length
                  +' but target length='+CFG.target.length
                  +'; must match'});
            return false;
        }
        CFG.orig_bytes = toBytes(CFG.orig);
        CFG.target_bytes = toBytes(CFG.target);
        send({t:'cfg_ok', orig: CFG.orig, target: CFG.target,
              len: CFG.orig.length, dry: CFG.dry, once: CFG.once});
        return true;
    },
    install: function(){
        Interceptor.attach(ptr('""" + TARGET_ADDR + r"""'), {
            onEnter: function(args){
                STATS.total++;
                if (CFG.once && STATS.patched >= 1) return;
                const ecx = this.context.ecx;
                for (let i = 0; i < OFFSETS.length; i++){
                    const off = OFFSETS[i];
                    let raw = 0;
                    try { raw = ecx.add(off).readU32(); } catch(e){ continue; }
                    if (!raw) continue;
                    const pos = findOrig(raw);
                    if (pos < 0) continue;

                    STATS.matched++;
                    const absAddr = ptr(raw).add(pos);
                    if (CFG.dry){
                        send({t:'would_patch',
                              seq: STATS.total,
                              this_addr: ecx.toString(),
                              buf_ptr: '0x' + raw.toString(16),
                              buf_off_within_this: '0x' + off.toString(16),
                              conv_off_in_buf: pos,
                              patch_addr: absAddr.toString(),
                              orig: CFG.orig, target: CFG.target,
                              len: CFG.orig.length});
                        return;   // 只处理第一个命中的 offset
                    }
                    // 真写：writeByteArray 会自动处理权限
                    try {
                        absAddr.writeByteArray(Array.from(CFG.target_bytes));
                        STATS.patched++;
                        send({t:'patched',
                              seq: STATS.total,
                              patch_addr: absAddr.toString(),
                              orig: CFG.orig, target: CFG.target,
                              len: CFG.orig.length});
                    } catch(e){
                        send({t:'err', msg:'writeByteArray failed: '+e.message,
                              addr: absAddr.toString()});
                    }
                    return;
                }
            }
        });
        send({t:'installed'});
    },
    stats: function(){ return STATS; },
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


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", type=str, required=True,
                    help="原 conv_id（必须是 dryrun 里实际出现过的）")
    ap.add_argument("--target", type=str, required=True,
                    help="目标 conv_id（长度必须等于 orig 长度）")
    ap.add_argument("--dry", action="store_true",
                    help="仅报告不改写")
    ap.add_argument("--once", action="store_true",
                    help="只 patch 第一次匹配")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=180)
    args = ap.parse_args(argv)

    if len(args.orig) != len(args.target):
        print(f"[!] orig len={len(args.orig)}  target len={len(args.target)}")
        print(f"[!] 必须长度一致；建议只改 S: 后面的 peer_uin 部分")
        return 2

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}, target = {TARGET_ADDR}")
    mode = "DRY" if args.dry else ("PATCH-ONCE" if args.once else "PATCH-ALL")
    print(f"[*] mode = {mode}")
    print(f"[*] orig   = {args.orig!r}  (len={len(args.orig)})")
    print(f"[*] target = {args.target!r}  (len={len(args.target)})")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"hijack_{ts}.ndjson"

    session = frida.get_local_device().attach(pid)
    js = FRIDA_JS_TEMPLATE.replace("__OFFSETS__",
                                    json.dumps(SCAN_OFFSETS))
    script = session.create_script(js)

    events: list[dict[str, Any]] = []
    ready = {"v": False}
    cfg_result: dict[str, Any] = {}
    fp = ndjson_path.open("a", encoding="utf-8")

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] wx base={p['base']}")
            elif t == "cfg_ok":
                cfg_result.update(p)
                print(f"[+] cfg ok: {p['orig']!r} → {p['target']!r} (len {p['len']})")
            elif t == "installed":
                print(f"[+] hook installed on {TARGET_ADDR}")
            elif t == "would_patch":
                events.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n"); fp.flush()
                print(f"[DRY seq={p['seq']}] would patch @ {p['patch_addr']}  "
                      f"(this={p['this_addr']} buf={p['buf_ptr']} "
                      f"[this+{p['buf_off_within_this']}] "
                      f"conv_at_buf_off=0x{p['conv_off_in_buf']:x})")
                print(f"           orig={p['orig']!r}")
                print(f"         target={p['target']!r}")
            elif t == "patched":
                events.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n"); fp.flush()
                print(f"[★ PATCHED seq={p['seq']}] @ {p['patch_addr']}  "
                      f"{p['orig']!r} → {p['target']!r}")
            elif t == "err":
                print(f"[!] {p.get('msg')}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    ok = script.exports_sync.configure({
        "orig": args.orig, "target": args.target,
        "dry": args.dry, "once": args.once,
    })
    if not ok:
        try: script.unload(); session.detach()
        except Exception: pass
        return 3
    script.exports_sync.install()
    print()
    print(f"[*] armed for {args.duration}s. 现在从企微手动做转发操作")
    print(f"    最好的验证方式：从 FTA 转发给原联系人（会话就是 orig），")
    print(f"    但 hijack 后消息会实际发到 target。")
    print()

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)
        if args.once and not args.dry:
            try:
                st = script.exports_sync.stats()
                if st.get("patched", 0) >= 1:
                    print("[*] --once satisfied, wait 3s and unload")
                    time.sleep(3)
                    break
            except Exception:
                pass

    fp.close()
    try:
        st = script.exports_sync.stats()
        print()
        print(f"[+] final: total 0x8dd8202 hits = {st['total']}")
        print(f"          matched (orig found in buf) = {st['matched']}")
        print(f"          patched (actually overwrote) = {st['patched']}")
    except Exception:
        pass
    print(f"[+] events logged → {ndjson_path.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
