"""
scan_insert_sql.py
在 WXWork.exe 内存中扫描所有 INSERT SQL 字符串
找到地址后，搜索 PUSH 指令 xref，定位 sqlite3_prepare 调用点

策略:
1. 扫描 message.db INSERT 相关字符串  
2. 找到 PUSH addr 指令（xref 到这些字符串的代码）
3. hook 那个调用点，等待转发操作
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[*] PID = {pid}")
dev = frida.get_local_device()

JS = r"""
'use strict';
send({t:'start', pid:Process.id});

var wx = Process.getModuleByName('WXWork.exe');
send({t:'module', base:wx.base.toString(), size:wx.size});

// Step 1: 扫描 INSERT SQL 字符串
var patterns = [
    {name:'insert_message',   hex:'49 4e 53 45 52 54 20 49 4e 54 4f 20 6d 65 73 73 61 67 65'},   // INSERT INTO message
    {name:'insert_table',     hex:'49 4e 53 45 52 54 20 4f 52 20 52 45 50 4c 41 43 45 20 49 4e 54 4f'},  // INSERT OR REPLACE INTO
    {name:'replace_into',     hex:'52 45 50 4c 41 43 45 20 49 4e 54 4f 20 6d 65 73 73 61 67 65'},  // REPLACE INTO message
    {name:'msg_type',         hex:'6d 65 73 73 61 67 65 5f 74 79 70 65'},   // message_type
    {name:'forward_id',       hex:'66 6f 72 77 61 72 64 5f 69 64'},         // forward_id
    {name:'origin_msgid',     hex:'6f 72 69 67 69 6e 5f 6d 73 67 69 64'},   // origin_msgid
];

var found = {};
for (var pi = 0; pi < patterns.length; pi++) {
    var p = patterns[pi];
    try {
        var hits = Memory.scanSync(wx.base, wx.size, p.hex);
        if (hits.length > 0) {
            found[p.name] = hits.map(function(h){
                var text = "";
                try { text = h.address.readCString(80); } catch(e){}
                return {addr: h.address.toString(), text: text};
            });
        }
    } catch(e) {}
}
send({t:'sql_scan', found: found});

// Step 2: 对每个找到的字符串，搜索 PUSH 指令 xref
// PUSH imm32 = 68 XX XX XX XX
var xrefs = {};
var foundKeys = Object.keys(found);
for (var ki = 0; ki < foundKeys.length; ki++) {
    var name = foundKeys[ki];
    var entries = found[name];
    for (var ei = 0; ei < entries.length; ei++) {
        var strAddr = parseInt(entries[ei].addr, 16);
        var b0 = (strAddr & 0xFF).toString(16).padStart(2,'0');
        var b1 = ((strAddr >> 8) & 0xFF).toString(16).padStart(2,'0');
        var b2 = ((strAddr >> 16) & 0xFF).toString(16).padStart(2,'0');
        var b3 = ((strAddr >> 24) & 0xFF).toString(16).padStart(2,'0');
        // Pattern: 68 [4-byte LE addr]
        var pushPat = '68 ' + b0 + ' ' + b1 + ' ' + b2 + ' ' + b3;
        try {
            var codeHits = Memory.scanSync(wx.base, wx.size, pushPat);
            if (codeHits.length > 0) {
                xrefs[name + '@' + entries[ei].addr] = codeHits.map(function(h){
                    return h.address.toString();
                });
            }
        } catch(e) {}
    }
}
send({t:'xrefs', data: xrefs});
"""

events = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t","")
    if t == "start":
        print(f"  [JS] pid={p.get('pid')}")
    elif t == "module":
        print(f"  [module] base={p['base']} size={p['size']}")
    elif t == "sql_scan":
        print(f"\n[SQL strings found]:")
        for name, hits in p.get("found",{}).items():
            for h in hits[:2]:
                print(f"  {name}: addr={h['addr']} text={h.get('text','')[:60]!r}")
    elif t == "xrefs":
        data = p.get("data",{})
        total = sum(len(v) for v in data.values())
        print(f"\n[PUSH xrefs] total={total}")
        for k, addrs in data.items():
            print(f"  {k}: <- {addrs[:3]}")

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
time.sleep(30)  # 等扫描完成

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"insert_sql_scan_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 结果已保存 -> {out_f}")
