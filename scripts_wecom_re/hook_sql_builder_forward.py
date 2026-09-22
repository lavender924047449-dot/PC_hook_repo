"""
hook_sql_builder_forward.py
Hook 0x1023810 (SQL 模板构建器) 
捕获完整 args: SQL模板 + 表名 + 列名 + backtrace
只打印 INSERT/REPLACE SQL（转发时必须 INSERT）
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

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
var TARGET = ptr(0x1023810);
var HIT = 0;
var INSERT_HITS = 0;

function safeStr(p, maxLen) {
    maxLen = maxLen || 200;
    try {
        if (p.isNull()) return '';
        var s = p.readCString(maxLen);
        return s || '';
    } catch(e) { return ''; }
}

Interceptor.attach(TARGET, {
    onEnter: function(args) {
        HIT++;
        if (HIT > 5000) return;
        
        // 尝试读 6 个 args 中的字符串
        var strs = [];
        for (var i = 0; i < 6; i++) {
            strs.push(safeStr(args[i], 300));
        }
        
        // 组合判断：找 SQL 模板
        var sqlTpl = '';
        var extraArgs = [];
        for (var i = 0; i < strs.length; i++) {
            var s = strs[i];
            if (!sqlTpl && s.match(/^(SELECT|INSERT|REPLACE|UPDATE|DELETE|CREATE|BEGIN|COMMIT|PRAGMA|select|insert|replace|update)/)) {
                sqlTpl = s;
            } else if (sqlTpl && s && s.length > 0 && s.length < 100) {
                extraArgs.push(s);
            }
        }
        
        if (!sqlTpl) return;  // 没有 SQL 模板则忽略
        
        var isInsert = sqlTpl.match(/^(INSERT|REPLACE|replace|insert)/i);
        var isMsg = sqlTpl.indexOf('message') >= 0 || (extraArgs.some(function(a){ return a.indexOf('message') >= 0; }));
        
        INSERT_HITS++;
        
        // 只对 INSERT/REPLACE 且涉及 message 的，或者前5次所有INSERT，发送详细事件
        var needBt = isInsert; // 所有 INSERT 都发送
        if (!isInsert && !isMsg && INSERT_HITS > 50) return;  // 非INSERT且非message且已有50次则跳过
        
        var bt = [];
        if (needBt) {
            bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 6)
                       .map(function(a){ return a.toString(); });
        }
        
        send({
            t: 'sql',
            n: HIT,
            tpl: sqlTpl.slice(0, 300),
            args: extraArgs.slice(0, 6),
            all_strs: strs.map(function(s){ return s.slice(0,100); }),
            isInsert: !!isInsert,
            tid: this.threadId,
            bt: bt
        });
    }
});
send({t:'hook_ready', addr:TARGET.toString()});
"""

events = []
insert_events = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t","")
    if t == "hook_ready":
        print(f"\n[HOOK READY] {p['addr']}")
        print(">>> 请立刻执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        OUT.joinpath("sql_builder_ready.flag").write_text("ready")
    elif t == "sql":
        tpl = p.get("tpl","")
        args = p.get("args",[])
        n = p.get("n",0)
        is_insert = p.get("isInsert", False)
        bt = p.get("bt",[])
        all_strs = p.get("all_strs",[])
        
        if is_insert:
            insert_events.append(p)
            line = f"[INSERT #{n}] {tpl[:100]} | args={args[:4]}"
            print(line.encode("utf-8","replace").decode("utf-8","replace"))
            if bt:
                bt_str = " | ".join(bt[:3])
                print(f"  bt: {bt_str}")
        elif "message" in tpl.lower() or any("message" in s.lower() for s in args):
            line = f"[MSG-SQL #{n}] {tpl[:80]!r} | args={args[:3]}"
            print(line.encode("utf-8","replace").decode("utf-8","replace"))

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] 加载中...")
time.sleep(3)

DURATION = 90
print(f"[*] 监听 {DURATION}s...")
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"sql_builder_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: INSERT={len(insert_events)} 条 -> {out_f}")
