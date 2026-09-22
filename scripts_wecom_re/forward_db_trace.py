"""
forward_db_trace.py — 最小化、安全的 NtWriteFile hook

策略:
  1. 扫描主进程中打开的 SQLite .db 文件句柄（和 ipc_pipe_final 一样的方式）
  2. 只对这些 handle 设置 NtWriteFile hook + FUZZY backtrace（不超过 5 个 hook）
  3. 等待用户执行转发操作 → 捕获调用链
  4. 不做 export 枚举，不做 Stalker，不注入子进程

注意: 使用 FUZZY backtrace (非 ACCURATE), 避免触发企微安全检测
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if ":9882" in line and "LISTENING" in line:
                return int(line.strip().split()[-1])
    except Exception:
        pass
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "WXWork.exe" in line:
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 2:
                    return int(parts[1])
    except Exception:
        pass
    raise RuntimeError("企微未运行")

main_pid = get_main_pid()
print(f"[*] 主进程 PID = {main_pid}")

dev = frida.get_local_device()

# ── Frida JS ─────────────────────────────────────────────────────────────────
JS = r"""
'use strict';
send({type:'start', pid:Process.id});

var ntdll  = Process.getModuleByName('ntdll.dll');
var NtQO   = new NativeFunction(ntdll.getExportByName('NtQueryObject'),
                 'int', ['pointer','int','pointer','uint','pointer']);

// ── Phase 1: 扫描 SQLite .db 文件句柄 ──────────────────────────────────────
var dbHandles = {};
var found = 0;

for (var h = 4; h <= 0x8000; h += 4) {
    var buf = Memory.alloc(2048);
    var rl  = Memory.alloc(4);
    try {
        if (NtQO(ptr(h), 1, buf, 2048, rl) !== 0) continue;
        var nl = buf.readU16();
        if (nl === 0 || nl > 1000) continue;
        var sp = buf.add(4).readPointer();
        if (sp.isNull()) continue;
        var name = sp.readUtf16String(nl / 2);
        if (!name) continue;
        // 匹配 SQLite db 文件 和 pipe
        if (name.indexOf('.db') >= 0 || name.indexOf('EnMicroMsg') >= 0 ||
            name.indexOf('MicroMsg') >= 0 || name.indexOf('WXWork') >= 0) {
            if (name.toLowerCase().indexOf('.db') >= 0) {
                dbHandles[h] = name;
                found++;
                if (found >= 10) break;  // 最多10个
            }
        }
    } catch(e) {}
}

var handleList = Object.keys(dbHandles).map(function(k){ return parseInt(k); });
send({type:'db_handles', handles: dbHandles,
      count: handleList.length});

if (handleList.length === 0) {
    send({type:'warn', msg:'未找到 .db 文件句柄，改为监听所有文件写入...'});
    // fallback: 不过滤 handle，直接 hook 并在 onEnter 过滤 db path
}

// ── Phase 2: NtWriteFile hook (只针对 db 句柄) ────────────────────────────
var NtWriteFile = ntdll.getExportByName('NtWriteFile');
var DB_SET = {};
handleList.forEach(function(h){ DB_SET[h] = true; });

var HIT_COUNT = 0;
var MAX_HITS = 50;

Interceptor.attach(NtWriteFile, {
    onEnter: function(args) {
        var handle = args[0].toUInt32();
        // 若有 db 句柄列表，只处理命中的
        if (handleList.length > 0 && !DB_SET[handle]) return;
        // 限制总命中数
        if (HIT_COUNT >= MAX_HITS) return;
        HIT_COUNT++;

        // FUZZY backtrace（轻量，避免检测）
        var bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                       .slice(0, 6)
                       .map(function(a){ return a.toString(); });

        // 读取 buffer 内容（最多 256 字节）
        var buf_ptr = args[5];  // UserBuffer
        var buf_len_ptr = args[6]; // UserBufferLength (uint32)
        var data_preview = '';
        try {
            var len = Math.min(args[6] ? args[6].toUInt32() : 0, 256);
            if (len > 0 && !buf_ptr.isNull()) {
                var bytes = new Uint8Array(buf_ptr.readByteArray(len));
                // 转 hex + ASCII
                var hex = Array.from(bytes).map(function(b){return b.toString(16).padStart(2,'0');}).join(' ');
                var asc = Array.from(bytes).map(function(b){
                    return (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
                }).join('');
                data_preview = hex.substring(0, 96) + ' | ' + asc.substring(0, 32);
            }
        } catch(e) {}

        var handleName = dbHandles[handle] || '?';
        send({type:'write_hit',
              handle: handle,
              handle_name: handleName,
              tid: this.threadId,
              bt: bt,
              data_preview: data_preview});
    }
});

send({type:'hook_ready', handle_count: handleList.length});
"""

all_events = []
hit_events = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        if msg.get("type") == "error":
            print(f"  [JS ERR] {msg.get('description','')}")
        return
    p = msg["payload"]
    all_events.append(p)
    t = p.get("type","")

    if t == "start":
        print(f"  [JS] pid={p.get('pid')}")
    elif t == "db_handles":
        print(f"  [db_handles] 找到 {p['count']} 个 SQLite 句柄:")
        for h, name in p["handles"].items():
            print(f"    h={h}  {name}")
    elif t == "warn":
        print(f"  [WARN] {p.get('msg','')}")
    elif t == "hook_ready":
        print(f"\n[HOOK READY] NtWriteFile hook 已设置 ({p['handle_count']} DB handles)")
        print(">>> 请立刻在企微执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        (OUT_DIR / "forward_hook_ready.flag").write_text("ready")
    elif t == "write_hit":
        hit_events.append(p)
        n = len(hit_events)
        print(f"\n[DB WRITE #{n}] handle={p['handle']} ({p.get('handle_name','?')!r}) tid={p['tid']}")
        print(f"  bt: {' | '.join(p.get('bt', ['?']))}")
        if p.get("data_preview"):
            print(f"  data: {p['data_preview'][:120]}")

sess = dev.attach(main_pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] JS 加载中，扫描 SQLite 句柄（~20s）...")

DURATION = 90
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] Ctrl+C")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_db_trace_{ts}.json"
out.write_text(json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: {len(hit_events)} 次 DB 写命中 -> {out}")
