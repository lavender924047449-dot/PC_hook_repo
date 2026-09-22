"""
forward_find.py
多策略定位 ForwardMessageToWeChatInternal 函数地址并 hook

策略:
  1. 枚举所有已加载模块, 搜索包含目标字符串的模块
  2. 在每个命中模块的 .rdata/.data 段找 type_info 指针链, 回溯 vftable -> constructor
  3. 通过 DebugSymbol.fromAddress 为每个 rdata 指针取名
  4. hook 最可能的函数候选 (通过 RTTI + 函数 prologue 扫描)
  5. 同时 hook Qt slot dispatch (QMetaObject::activate / qt_metacall)

用法: python -u forward_find.py
"""
import sys, time, json, subprocess, struct, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    out = subprocess.check_output(
        "netstat -ano 2>&1 | findstr :9882", shell=True).decode(errors="replace")
    for line in out.splitlines():
        if "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

main_pid = get_main_pid()
print(f"[*] PID = {main_pid}")

dev = frida.get_local_device()

# ── 主 JS ────────────────────────────────────────────────────────────────────
JS = r"""
'use strict';
send({type:'start', pid: Process.id});

var TARGET = "ForwardMessageToWeChatInternal";
// ASCII bytes
var TARGET_PAT = "46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 54 6f 57 65 43 68 61 74 49 6e 74 65 72 6e 61 6c";

// ── Step 1: 找包含目标字符串的所有模块 ──────────────────────────────────────
var hitMods = [];
Process.enumerateModules().forEach(function(m) {
    try {
        var matches = Memory.scanSync(m.base, m.size, TARGET_PAT);
        if (matches.length > 0) {
            hitMods.push({name:m.name, base:m.base.toString(), size:m.size,
                          count: matches.length,
                          addrs: matches.map(function(x){return x.address.toString();})});
        }
    } catch(e) {}
});
send({type:'hit_mods', data: hitMods});

// ── Step 2: 在命中模块内做 RDATA 指针反查 ─────────────────────────────────
// 对每个字符串地址 S, 搜索 4-byte LE(S) 的引用
function findRefs(mod, strAddrs) {
    var refs = {};
    strAddrs.forEach(function(sa) {
        var addrVal = ptr(sa).toUInt32();
        var b = [(addrVal & 0xFF), ((addrVal>>8)&0xFF), ((addrVal>>16)&0xFF), ((addrVal>>24)&0xFF)];
        var pat = b.map(function(x){return x.toString(16).padStart(2,'0');}).join(' ');
        try {
            var ms = Memory.scanSync(mod.base, mod.size, pat);
            if (ms.length > 0) refs[sa] = ms.map(function(m){return m.address.toString();});
        } catch(e) {}
    });
    return refs;
}

var allRefs = {};
hitMods.forEach(function(hm) {
    var refs = findRefs(hm, hm.addrs);
    var total = Object.values(refs).reduce(function(s,v){return s+v.length;},0);
    if (total > 0) allRefs[hm.name] = refs;
});
send({type:'rdata_refs', data: allRefs});

// ── Step 3: 从 rdata 引用出发找函数起始 ──────────────────────────────────
function findFuncPrologue(addr) {
    for (var back = 4; back <= 1024; back += 4) {
        try {
            var c = addr.sub(back);
            var b3 = new Uint8Array(c.readByteArray(3));
            if ((b3[0]===0x55 && b3[1]===0x8B && b3[2]===0xEC) ||
                (b3[0]===0x55 && b3[1]===0x89 && b3[2]===0xE5)) {
                return c;
            }
        } catch(e) {}
    }
    return null;
}

// ── Step 4: hook Qt QMetaObject::activate (信号分发) ─────────────────────
// 这样所有 Qt signal 都过一遍，找 "forward" 相关
var qtHooked = false;
var qtActivateAddr = Module.findExportByName(null, '_ZN11QMetaObject8activateEP7QObjectiPPv');
if (!qtActivateAddr) qtActivateAddr = Module.findExportByName(null, '?activate@QMetaObject@@SAXPAV1@PB1HPAPAUQBasicAtomicInt@@@Z');
if (qtActivateAddr) {
    send({type:'qt_activate_found', addr: qtActivateAddr.toString()});
    Interceptor.attach(qtActivateAddr, {
        onEnter: function(args) {
            // args: sender, meta, signal_index, argv
            try {
                var sender = args[0];
                var meta   = args[1];
                var sigIdx = args[2].toInt32();
                // 读取 QMetaObject 的 className (offset 0 = d ptr, d->stringdata offset 4)
                var d = meta.readPointer();  // superdata
                // qt4 style: QMetaObject.d.stringdata
                var sd = meta.add(4).readPointer();
                if (!sd.isNull()) {
                    var cn = sd.readCString(64);
                    if (cn && (cn.toLowerCase().indexOf('forward') >= 0 ||
                               cn.toLowerCase().indexOf('message') >= 0)) {
                        send({type:'qt_signal',
                              class_name: cn, signal: sigIdx,
                              sender: sender.toString()});
                    }
                }
            } catch(e) {}
        }
    });
    qtHooked = true;
}

// ── Step 5: hook wework/wechat 系列 DLL 的已导出 forward 函数 ────────────
var exportHooked = [];
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('wework') < 0 &&
        m.name.toLowerCase().indexOf('wechat') < 0 &&
        m.name.toLowerCase().indexOf('wxwork') < 0) return;
    try {
        m.enumerateExports().forEach(function(exp) {
            if (exp.name && exp.name.toLowerCase().indexOf('forward') >= 0) {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            send({type:'export_call', mod:m.name, name:exp.name,
                                  args: [args[0].toString(),args[1].toString(),
                                         args[2].toString(),args[3].toString()]});
                        }
                    });
                    exportHooked.push({mod:m.name, name:exp.name, addr:exp.address.toString()});
                } catch(e) {}
            }
        });
    } catch(e) {}
});
send({type:'export_hooks', hooked: exportHooked});

// ── Step 6: 从 rdata_refs 建立候选函数表并 hook ─────────────────────────
var candidatesHooked = [];
Object.values(allRefs).forEach(function(modRefs) {
    Object.values(modRefs).forEach(function(refAddrs) {
        refAddrs.forEach(function(ra) {
            var raPtr = ptr(ra);
            // ra 指向字符串的地址; ra 本身可能在 type_info 内
            // 从 ra 向上找 prologue
            var fs = findFuncPrologue(raPtr);
            if (fs) {
                var key = fs.toString();
                if (candidatesHooked.indexOf(key) < 0) {
                    candidatesHooked.push(key);
                    try {
                        Interceptor.attach(fs, {
                            onEnter: function(args) {
                                var dump = [];
                                for (var k=0;k<8;k++){try{dump.push(args[k].toString());}catch(e){dump.push('?');}}
                                send({type:'candidate_call', addr: fs.toString(), args:dump,
                                      ecx: this.context.ecx ? this.context.ecx.toString() : '?'});
                            }
                        });
                    } catch(e) {}
                }
            }
        });
    });
});
send({type:'candidates_hooked', count: candidatesHooked.length, addrs: candidatesHooked});
send({type:'ready', qt_hooked: qtHooked, exports: exportHooked.length,
      candidates: candidatesHooked.length});
"""

all_events = []

def safe_print(s):
    print(s.encode("gbk", errors="replace").decode("gbk"))

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    all_events.append(p)
    t = p.get("type","")

    if t == "start":
        print(f"  [JS] pid={p.get('pid')}")
    elif t == "hit_mods":
        for m in p["data"]:
            print(f"  [hit] {m['name']} count={m['count']} addrs={m['addrs'][:3]}")
    elif t == "rdata_refs":
        total = sum(len(v) for vv in p["data"].values() for v in vv.values())
        print(f"  [rdata_refs] total={total}")
        for mname, refs in p["data"].items():
            for sa, ras in refs.items():
                print(f"    {mname}: str@{sa} <- {ras[:3]}")
    elif t == "qt_activate_found":
        print(f"  [Qt] QMetaObject::activate @ {p['addr']}")
    elif t == "qt_signal":
        print(f"  [Qt signal] class={p.get('class_name')} signal_idx={p.get('signal')}")
    elif t == "export_hooks":
        print(f"  [exports] hooked {len(p['hooked'])} forward-related exports")
        for h in p["hooked"]:
            print(f"    {h['mod']} {h['name']} @ {h['addr']}")
    elif t == "export_call":
        print(f"\n[!] EXPORT CALL: {p['mod']} {p['name']}  args={p['args']}")
    elif t == "candidates_hooked":
        print(f"  [candidates] {p['count']} prologue候选已hook")
    elif t == "ready":
        print(f"\n[READY] qt={p['qt_hooked']} exports={p['exports']} candidates={p['candidates']}")
        print("[READY] Hook active! Please perform: right-click msg -> Forward -> select -> Send")
        (OUT_DIR / "forward_hook_ready.flag").write_text("ready")
    elif t == "candidate_call":
        print(f"\n[CANDIDATE CALL] addr={p['addr']} ecx={p.get('ecx')} args={p.get('args')}")
    elif t == "error":
        print(f"  [ERR] {p.get('msg','')}")

sess = dev.attach(main_pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] JS 加载完成，等待扫描...")

DURATION = 180
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] Ctrl+C")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_find_{ts}.json"
out.write_text(json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[*] Saved {len(all_events)} events -> {out}")
