"""
forward_xref.py
1. 扫描 WXWork.exe 内 "ForwardMessageToWeChatInternal" 字符串地址
2. 对每个字符串地址，在代码段中查找引用（xref）
3. 对找到的 xref 地址反推函数起始，hook 之

用法: python -u forward_xref.py
     运行后手动在企微执行转发操作
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── 确定主进程 PID (监听 9882 端口的那个) ──────────────────────────────────
def get_main_pid():
    out = subprocess.check_output(
        "netstat -ano 2>&1 | findstr :9882", shell=True).decode(errors="replace")
    for line in out.splitlines():
        if "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("找不到监听 9882 的进程，企微是否运行？")

main_pid = get_main_pid()
print(f"[*] 主进程 PID = {main_pid}")

dev = frida.get_local_device()

# ── Frida JS ─────────────────────────────────────────────────────────────────
SCAN_JS = r"""
'use strict';

var TARGET_STR = "ForwardMessageToWeChatInternal";

// ASCII bytes for the string
function strToPattern(s) {
    var bytes = [];
    for (var i = 0; i < s.length; i++) {
        var h = s.charCodeAt(i).toString(16);
        bytes.push(h.length === 1 ? '0'+h : h);
    }
    return bytes.join(' ');
}

send({type:'start', pid: Process.id});

var wxmod = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxmod = mods[i];
        break;
    }
}
if (!wxmod) {
    send({type:'error', msg:'未找到 WXWork.exe 模块'});
} else {
    send({type:'module', name: wxmod.name, base: wxmod.base.toString(), size: wxmod.size});
}

// Step 1: 找字符串地址
var pattern = strToPattern(TARGET_STR);
var strAddrs = [];
if (wxmod) {
    try {
        var matches = Memory.scanSync(wxmod.base, wxmod.size, pattern);
        for (var j = 0; j < matches.length; j++) {
            strAddrs.push(matches[j].address);
        }
    } catch(e) {
        send({type:'scan_err', msg: e.message});
    }
}
send({type:'str_scan', count: strAddrs.length,
      addrs: strAddrs.map(function(a){ return a.toString(); })});

// Step 2: 对每个字符串地址，扫描代码段找 xref (4-byte LE encoding)
var xrefs = {};
if (wxmod && strAddrs.length > 0) {
    for (var si = 0; si < strAddrs.length; si++) {
        var sa = strAddrs[si];
        // 构造 4-byte LE pattern
        var addrVal = sa.toUInt32();
        var b0 = (addrVal & 0xFF).toString(16).padStart(2,'0');
        var b1 = ((addrVal >> 8) & 0xFF).toString(16).padStart(2,'0');
        var b2 = ((addrVal >> 16) & 0xFF).toString(16).padStart(2,'0');
        var b3 = ((addrVal >> 24) & 0xFF).toString(16).padStart(2,'0');
        var xpat = b0 + ' ' + b1 + ' ' + b2 + ' ' + b3;
        try {
            var xmatches = Memory.scanSync(wxmod.base, wxmod.size, xpat);
            if (xmatches.length > 0) {
                xrefs[sa.toString()] = xmatches.map(function(m){ return m.address.toString(); });
            }
        } catch(e) {}
    }
}
send({type:'xrefs', data: xrefs});

// Step 3: 对每个 xref，尝试向上找函数起始 (扫描 PUSH EBP / MOV EDI,EDI 等 prologue)
// 简单策略：向上扫 0x200 字节，找 55 8B EC (push ebp; mov ebp,esp) 或 56 57 55 等
function findFuncStart(xrefAddr) {
    var p = xrefAddr;
    // 向上最多扫 512 字节
    for (var back = 4; back <= 512; back += 4) {
        try {
            var candidate = p.sub(back);
            var b = candidate.readByteArray(3);
            var bytes = new Uint8Array(b);
            // push ebp; mov ebp, esp
            if (bytes[0] === 0x55 && bytes[1] === 0x8B && bytes[2] === 0xEC) {
                return candidate;
            }
            // 55 89 e5 (push ebp; mov ebp, esp in AT&T)
            if (bytes[0] === 0x55 && bytes[1] === 0x89 && bytes[2] === 0xE5) {
                return candidate;
            }
        } catch(e) {}
    }
    return null;
}

var hookedAddrs = {};
var callCount = 0;
var xrefKeys = Object.keys(xrefs);
for (var ki = 0; ki < xrefKeys.length; ki++) {
    var refs = xrefs[xrefKeys[ki]];
    for (var ri = 0; ri < refs.length; ri++) {
        var xref = ptr(refs[ri]);
        var funcStart = findFuncStart(xref);
        var hookTarget = funcStart || xref;
        var hookKey = hookTarget.toString();
        if (hookedAddrs[hookKey]) continue;
        hookedAddrs[hookKey] = true;
        (function(ht, xs, fs) {
            try {
                Interceptor.attach(ht, {
                    onEnter: function(args) {
                        callCount++;
                        var dump = [];
                        for (var k = 0; k < 12; k++) {
                            try { dump.push(args[k].toString()); } catch(e){ dump.push('?'); }
                        }
                        var strs = [];
                        for (var k = 0; k < 12; k++) {
                            try {
                                var s = args[k].readUtf16String(200);
                                if (s && s.length > 2) strs.push({idx:k, utf16:s});
                            } catch(e) {}
                            try {
                                var s = args[k].readUtf8String(200);
                                if (s && s.length > 2 && /[\x20-\x7e]{3,}/.test(s))
                                    strs.push({idx:k, utf8:s});
                            } catch(e) {}
                        }
                        var ctx = {
                            eax: this.context.eax ? this.context.eax.toString() : '?',
                            ecx: this.context.ecx ? this.context.ecx.toString() : '?',
                            edx: this.context.edx ? this.context.edx.toString() : '?',
                        };
                        send({type:'call',
                              hook_at: ht.toString(),
                              xref_at: xs.toString(),
                              func_start: fs ? fs.toString() : null,
                              tid: this.threadId,
                              ctx: ctx,
                              args: dump,
                              strs: strs});
                    }
                });
                send({type:'hooked', addr: ht.toString(), xref: xs.toString(),
                      has_func_start: fs !== null});
            } catch(e) {
                send({type:'hook_err', addr: ht.toString(), err: e.message});
            }
        })(hookTarget, xref, funcStart);
    }
}

send({type:'setup_done', hooked_count: Object.keys(hookedAddrs).length});
"""

all_events = []
hooked_count = 0
call_events = []

def on_msg(msg, data):
    global hooked_count
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    all_events.append(p)
    t = p.get("type","")

    if t == "start":
        print(f"  [JS] attached pid={p.get('pid')}")
    elif t == "module":
        print(f"  [module] {p['name']} base={p['base']} size={p['size']}")
    elif t == "str_scan":
        print(f"  [str_scan] 找到 {p['count']} 个字符串地址:")
        for a in p.get("addrs",[]):
            print(f"    {a}")
    elif t == "xrefs":
        total = sum(len(v) for v in p["data"].values())
        print(f"  [xrefs] 字符串->代码引用 共 {total} 处:")
        for k, vs in p["data"].items():
            for v in vs[:3]:
                print(f"    str@{k} <- code@{v}")
    elif t == "hooked":
        print(f"  [hooked] {p['addr']}  xref={p['xref']}  func_start={p['has_func_start']}")
    elif t == "setup_done":
        hooked_count = p.get("hooked_count", 0)
        print(f"\n[*] Hook 设置完毕，共 {hooked_count} 个地址")
        print("🔴 请在企微执行：右键消息 -> 转发 -> 选人 -> 发送\n")
        (OUT_DIR / "forward_hook_ready.flag").write_text("ready")
    elif t == "call":
        call_events.append(p)
        print(f"\n🎯 调用命中！hook={p['hook_at']} xref={p['xref_at']}")
        print(f"   ctx: eax={p['ctx'].get('eax')} ecx={p['ctx'].get('ecx')} edx={p['ctx'].get('edx')}")
        print(f"   args: {p['args']}")
        for s in p.get("strs",[]):
            tag = "utf16" if "utf16" in s else "utf8"
            print(f"   arg[{s['idx']}] {tag} = {s.get('utf16') or s.get('utf8','')!r}")
    elif t == "hook_err":
        print(f"  [hook_err] {p['addr']}: {p['err']}")
    elif t == "error":
        print(f"  [ERR] {p.get('msg','')}")
    elif t == "scan_err":
        print(f"  [scan_err] {p.get('msg','')}")

sess = dev.attach(main_pid)
sc = sess.create_script(SCAN_JS)
sc.on("message", on_msg)
sc.load()
print("[*] JS 已加载，等待扫描完成...")

DURATION = 180
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_xref_{ts}.json"
out.write_text(json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 保存 {len(all_events)} 事件 -> {out}")
if call_events:
    print(f"[*] 共捕获 {len(call_events)} 次调用！")
else:
    print("[*] 未捕获到调用（未执行转发或 hook 地址不正确）")
