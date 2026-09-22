"""
forward_hook.py — Step 1
hook ForwardMessageToWeChatInternal 捕获调用参数

用法:
  python -u forward_hook.py
  → 注入后手动在企微执行一次「转发」操作
  → 脚本打印函数地址 + 所有参数
"""
import sys, time, json, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── 找主进程 ────────────────────────────────────────────────────────────────
dev = frida.get_local_device()
procs = dev.enumerate_processes()
wx_procs = [(p.pid, p.name) for p in procs if p.name.lower().startswith("wxwork")]
wx_procs.sort(key=lambda x: x[0])
print(f"[*] 企微进程: {wx_procs}")

# 主进程 = pid 最大的 WXWork.exe（不是 WXWorkWeb.exe）
main_procs = [(p, n) for p, n in wx_procs if n.lower() == "wxwork.exe"]
main_pid, main_name = max(main_procs, key=lambda x: x[0])
print(f"[*] 主进程: pid={main_pid} {main_name}")

# ── Frida JS ─────────────────────────────────────────────────────────────────
HOOK_JS = r"""
'use strict';

// Step-1: 用 DebugSymbol 尝试直接按名查找
function tryDebugSymbol(name) {
    try {
        var sym = DebugSymbol.fromName(name);
        if (sym && !sym.address.isNull()) {
            send({type:'found', method:'DebugSymbol', name:name, addr: sym.address.toString()});
            return sym.address;
        }
    } catch(e) {}
    return null;
}

// Step-2: 枚举 WXWork.exe 导出 (内部函数通常不导出，但可以试)
function tryExport(modName, funcName) {
    try {
        var addr = Module.findExportByName(modName, funcName);
        if (addr) {
            send({type:'found', method:'export', name:funcName, addr: addr.toString()});
            return addr;
        }
    } catch(e) {}
    return null;
}

// Step-3: 扫描内存中包含 "ForwardMessageToWeChatInternal" 的字符串引用
function scanStringRefs(needle) {
    var results = [];
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        if (m.name.toLowerCase().indexOf('wxwork') < 0 &&
            m.name.toLowerCase().indexOf('wework') < 0) continue;
        try {
            var matches = Memory.scanSync(m.base, m.size, needle);
            for (var j = 0; j < matches.length; j++) {
                results.push({mod: m.name, addr: matches[j].address.toString()});
            }
        } catch(e) {}
    }
    return results;
}

// Step-4: 枚举模块所有符号 (如果有 PDB)
function enumSymbols(modName, keyword) {
    var results = [];
    try {
        var mod = Process.getModuleByName(modName);
        mod.enumerateSymbols().forEach(function(sym) {
            if (sym.name && sym.name.toLowerCase().indexOf(keyword) >= 0) {
                results.push({name: sym.name, addr: sym.address.toString()});
            }
        });
    } catch(e) {}
    return results;
}

send({type:'start', pid: Process.id});

// 尝试各种方法定位函数
var targetAddr = null;

// 方法1: DebugSymbol
var names = [
    'ForwardMessageToWeChatInternal',
    '?ForwardMessageToWeChatInternal',
];
for (var i = 0; i < names.length; i++) {
    targetAddr = tryDebugSymbol(names[i]);
    if (targetAddr) break;
}

// 方法2: 枚举符号
if (!targetAddr) {
    var syms = enumSymbols('WXWork.exe', 'forwardmessage');
    if (syms.length === 0) syms = enumSymbols('WXWork.exe', 'forward');
    send({type:'symbols', count: syms.length, samples: syms.slice(0,20)});
    if (syms.length > 0) {
        targetAddr = ptr(syms[0].addr);
    }
}

// 方法3: 字符串扫描 (ASCII + UTF-16LE needle)
if (!targetAddr) {
    var ascii_needle  = '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 54 6f 57 65 43 68 61 74 49 6e 74 65 72 6e 61 6c';
    var refs = scanStringRefs(ascii_needle);
    send({type:'string_refs', count: refs.length, refs: refs.slice(0,10)});
}

// 如果找到了地址，立刻 hook
if (targetAddr) {
    send({type:'hooking', addr: targetAddr.toString()});
    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            // 32-bit: args[0]=ecx(this), args[0..N] 从栈上
            // 先读 16 个指针大小的参数
            var dump = [];
            for (var k = 0; k < 16; k++) {
                try { dump.push(args[k].toString()); } catch(e) { dump.push('?'); }
            }
            // 尝试把每个参数解读为 UTF-16/UTF-8 字符串
            var strs = [];
            for (var k = 0; k < 16; k++) {
                try {
                    var p = args[k];
                    if (!p.isNull()) {
                        var s = p.readUtf16String(128);
                        if (s && s.length > 1) strs.push({idx:k, s:s});
                    }
                } catch(e) {}
                try {
                    var p = args[k];
                    if (!p.isNull()) {
                        var s = p.readUtf8String(128);
                        if (s && s.length > 1 && /[\x20-\x7e]{3,}/.test(s)) strs.push({idx:k, s8:s});
                    }
                } catch(e) {}
            }
            send({type:'call', tid: this.threadId, args: dump, strs: strs,
                  bt: Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(' | ')});
        },
        onLeave: function(retval) {
            send({type:'ret', tid: this.threadId, retval: retval.toString()});
        }
    });
    send({type:'hook_ready', addr: targetAddr.toString()});
} else {
    send({type:'not_found', msg:'无法定位函数，将改用 Qt signal 扫描'});
}
"""

# ── 附加 & 运行 ──────────────────────────────────────────────────────────────
all_events = []
found_addr = None

def on_message(msg, data):
    global found_addr
    payload = msg.get("payload", {}) if msg.get("type") == "send" else {}
    all_events.append(payload)

    t = payload.get("type", "")
    if t == "start":
        print(f"  [JS] attached pid={payload.get('pid')}")
    elif t == "found":
        found_addr = payload.get("addr")
        print(f"  [FOUND] method={payload['method']}  addr={found_addr}  name={payload.get('name','')}")
    elif t == "symbols":
        print(f"  [symbols] count={payload['count']}")
        for s in payload.get("samples", []):
            print(f"    {s['addr']}  {s['name'][:120]}")
    elif t == "string_refs":
        print(f"  [string_refs] count={payload['count']}")
        for r in payload.get("refs", []):
            print(f"    {r['mod']}  {r['addr']}")
    elif t == "hooking":
        print(f"  [hooking] addr={payload['addr']}")
    elif t == "hook_ready":
        print(f"\n✅ Hook 就绪！addr={payload['addr']}")
        print("🔴 请立刻在企微执行：右键消息 → 转发 → 选人 → 发送\n")
        # 写就绪信号
        (OUT_DIR / "forward_hook_ready.flag").write_text(payload['addr'])
    elif t == "not_found":
        print(f"\n⚠ {payload['msg']}")
    elif t == "call":
        print(f"\n🎯 ForwardMessageToWeChatInternal 被调用！tid={payload['tid']}")
        print(f"   args: {payload['args']}")
        for s in payload.get("strs", []):
            print(f"   arg[{s.get('idx')}] str = {s.get('s') or s.get('s8','')!r}")
        bt = payload.get("bt","")
        if bt:
            print(f"   backtrace: {bt[:300]}")
    elif t == "ret":
        print(f"   retval={payload['retval']}")
    elif t == "error":
        print(f"  [ERR] {payload.get('description','')[:200]}")

sess = dev.attach(main_pid)
sc = sess.create_script(HOOK_JS)
sc.on("message", on_message)
sc.load()

print("[*] 等待 hook 就绪（最多 15s 扫描）...")
time.sleep(15)

if not found_addr:
    print("[*] 函数未通过 DebugSymbol/export/symbol 找到，等待 120s 观察其他输出...")

DURATION = 180
print(f"[*] 监听 {DURATION}s，请在企微执行转发操作...")
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# 保存
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_hook_{ts}.json"
out.write_text(json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 已保存 {len(all_events)} 事件 → {out}")
