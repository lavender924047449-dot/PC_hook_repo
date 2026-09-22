"""
forward_stalker.py
用 Frida Stalker 在主线程上追踪 CALL 事件，精准定位转发函数

流程:
  1. 附加 WXWork.exe 主进程
  2. 找 UI 主线程 ID（等待 onEnter dispatch 确认）
  3. 开始 Stalker（只记录 call 事件，过滤到 WXWork.exe 地址范围）
  4. 等待用户执行"转发"操作（30s 窗口）
  5. 停止 Stalker，输出调用的唯一地址列表
  6. 用 DebugSymbol.fromAddress 尝试命名函数

用法: python -u forward_stalker.py
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    # 优先用 netstat 找监听 9882 的进程
    try:
        out = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if ":9882" in line and "LISTENING" in line:
                return int(line.strip().split()[-1])
    except Exception:
        pass
    # 备用: 找内存最大的 WXWork.exe 进程
    dev = frida.get_local_device()
    procs = [(p.pid, p.name) for p in dev.enumerate_processes()
             if p.name.lower() == "wxwork.exe"]
    if not procs:
        raise RuntimeError("企微未运行")
    return max(procs, key=lambda x: x[0])[0]

main_pid = get_main_pid()
print(f"[*] 主进程 PID = {main_pid}")

dev = frida.get_local_device()

# ── Frida JS ─────────────────────────────────────────────────────────────────
JS = r"""
'use strict';
send({type:'start', pid: Process.id});

// WXWork.exe 地址范围
var wxmod = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase() === 'wxwork.exe') wxmod = m;
});
if (!wxmod) { send({type:'error', msg:'no WXWork.exe'}); }

var WX_BASE = wxmod ? wxmod.base.toUInt32() : 0;
var WX_END  = wxmod ? (wxmod.base.toUInt32() + wxmod.size) : 0;

send({type:'module', base: WX_BASE.toString(16), end: WX_END.toString(16)});

// --- Phase 1: 等待 DispatchMessage 确认 UI 线程 ---
var uiThreadId = null;
var dispatchAddr = Module.findExportByName('user32.dll', 'DispatchMessageW')
                || Module.findExportByName('user32.dll', 'DispatchMessageA');
if (dispatchAddr) {
    var dispatchHook = Interceptor.attach(dispatchAddr, {
        onEnter: function(args) {
            // 第一次进入的线程就是消息循环线程
            if (!uiThreadId) {
                uiThreadId = this.threadId;
                send({type:'ui_thread', tid: uiThreadId});
            }
        }
    });
}

// --- Phase 2: Stalker 控制 ---
var stalking = false;
var callSet  = {};   // addr -> count
var MAX_CALLS = 50000;
var totalCalls = 0;

function startStalker(tid) {
    if (stalking) return;
    stalking = true;
    Stalker.follow(tid, {
        events: {
            call: true,
            ret:  false,
            exec: false,
            block: false,
            compile: false
        },
        onReceive: function(events) {
            // events 是二进制 GumCallEvent 数组
            var ev = Stalker.parse(events, {annotate:false, stringify:false});
            for (var i = 0; i < ev.length; i++) {
                if (totalCalls > MAX_CALLS) break;
                var e = ev[i];
                // e[1] = target address (call destination)
                var target = e[1];
                if (typeof target === 'number' && target >= WX_BASE && target < WX_END) {
                    var key = target.toString(16);
                    callSet[key] = (callSet[key] || 0) + 1;
                }
                totalCalls++;
            }
        }
    });
    send({type:'stalker_started', tid: tid});
}

function stopStalker(tid) {
    if (!stalking) return;
    Stalker.unfollow(tid);
    stalking = false;
    // 取前 200 个最热地址
    var pairs = Object.keys(callSet).map(function(k){
        return {addr:'0x'+k, count: callSet[k]};
    }).sort(function(a,b){return b.count-a.count;}).slice(0,200);
    send({type:'stalker_result', total: totalCalls, unique: Object.keys(callSet).length,
          top: pairs});
}

// --- RPC 控制接口 ---
rpc.exports = {
    startStalker: function(tid) {
        uiThreadId = tid || uiThreadId;
        if (uiThreadId) {
            startStalker(uiThreadId);
            return 'ok tid=' + uiThreadId;
        }
        return 'no ui thread yet';
    },
    stopStalker: function() {
        if (uiThreadId) stopStalker(uiThreadId);
        return 'stopped';
    },
    getUiThread: function() { return uiThreadId; }
};
"""

all_events = []
ui_tid = None
stalker_result = None
script_obj = None

def on_msg(msg, data):
    global ui_tid, stalker_result
    if msg.get("type") != "send":
        if msg.get("type") == "error":
            print(f"  [JS ERR] {msg.get('description','')}")
        return
    p = msg["payload"]
    all_events.append(p)
    t = p.get("type","")
    if t == "start":
        print(f"  [JS] pid={p.get('pid')}")
    elif t == "module":
        print(f"  [module] WXWork.exe 0x{p['base']} - 0x{p['end']}")
    elif t == "ui_thread":
        ui_tid = p["tid"]
        print(f"  [UI thread] tid={ui_tid}")
    elif t == "stalker_started":
        print(f"\n[Stalker] 已开始追踪 tid={p['tid']}")
        print(">>> 请立刻在企微执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<\n")
        (OUT_DIR / "forward_hook_ready.flag").write_text("ready")
    elif t == "stalker_result":
        stalker_result = p
        print(f"\n[Stalker] 完成! total={p['total']} unique={p['unique']}")
        print("  Top WXWork.exe 调用热点:")
        for h in p["top"][:30]:
            sym = ""
            try:
                sym = str(script_obj.exports.addr_name(int(h["addr"],16)))
            except:
                pass
            print(f"    {h['addr']}  x{h['count']:5d}  {sym}")
    elif t == "error":
        print(f"  [ERR] {p.get('msg','')}")

sess = dev.attach(main_pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
script_obj = sc

print("[*] JS 已加载，等待 DispatchMessage 确认 UI 线程...")
# 等最多 10s 识别 UI 线程
deadline = time.time() + 10
while time.time() < deadline and ui_tid is None:
    time.sleep(0.5)

if ui_tid is None:
    print("[!] 未自动识别 UI 线程，使用进程线程列表")
    # 获取所有线程
    threads_js = """
    Process.enumerateThreads().map(function(t){
        return {id:t.id, state:t.state, pc:t.context.pc ? t.context.pc.toString() : '0x0'};
    });
    """
    threads = sess.create_script(f"send(JSON.stringify({threads_js}))")
    threads_data = []
    def on_thr(msg, data):
        if msg.get("type") == "send":
            import json as _j; global threads_data; threads_data = _j.loads(msg["payload"])
    threads.on("message", on_thr)
    threads.load()
    time.sleep(2)
    print(f"  线程列表: {threads_data[:5]}")
    if threads_data:
        ui_tid = threads_data[0]["id"]
        print(f"  选第一个线程: tid={ui_tid}")

# 开始 Stalker
print(f"[*] 启动 Stalker 追踪 tid={ui_tid}...")
result = sc.exports.start_stalker(ui_tid)
print(f"  -> {result}")

# 等待 30s 让用户执行转发
print("\n[*] 30s 捕获窗口开始 - 请立刻执行转发操作!")
time.sleep(30)

# 停止并收集结果
print("[*] 停止 Stalker...")
sc.exports.stop_stalker()
time.sleep(3)  # 等 onReceive 处理完

# 保存
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_stalker_{ts}.json"
out.write_text(json.dumps({"events": all_events, "result": stalker_result},
               ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[*] 已保存 -> {out}")
