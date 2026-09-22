# dispatch15.py -- 任务分发器 vtable diff 实验（动态基址版）
# ============================================================
# 修复：v2 改为运行时动态枚举 WXWork.exe 模块基址，再加 RVA
# 原因：文档记录基址 0xD80000 已失效，当前实测 0x2D0000（ASLR 跨会话漂移）
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/dispatch15.py
#
# 流程：
#   Phase 1 (5 min) -- baseline，勿操作企微
#   提示后立刻转发  -- 向任意联系人转发一条消息
#   Phase 2 (6 min) -- 观察，等待 server ACK 触发回调
#   保存 dispatch15_{ts}.json，打印 vtable diff

import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

# RVA（相对 WXWork.exe 基址，固定不随会话变化）
RVA_DISPATCHER = 0x44AAA0   # 任务分发器，序言 55 8b ec 6a ff 68
PHASE1_SEC = 300             # 5 分钟 baseline
PHASE2_SEC = 360             # 6 分钟观察

# ── 1. 找主进程 PID ────────────────────────────────────────────────────────────
def get_main_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("未找到 :9882 LISTENING -- 请先启动企微")

pid = get_main_pid()
print(f"[+] 主进程 PID = {pid}", flush=True)

# ── 2. Frida JS：动态定位 dispatcher，单探针只读 vtable ────────────────────────
JS = r"""
'use strict';

// 动态找 WXWork.exe 基址
var mods = Process.enumerateModules();
var wxBase = null;
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base;
        break;
    }
}
if (!wxBase) {
    send({t:'err', msg:'WXWork.exe not found in module list'});
    throw new Error('abort');
}

var RVA_DISP = 0x44AAA0;
var DISP_ADDR = wxBase.add(RVA_DISP);

// 验证序言（55 8b ec 6a ff 68）
var prologue = DISP_ADDR.readByteArray(6);
var prologue_hex = Array.from(new Uint8Array(prologue))
    .map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');

send({
    t:       'init',
    base:    wxBase.toString(),
    disp:    DISP_ADDR.toString(),
    prolog:  prologue_hex
});

// ── 安全读辅助 ──
function safeReadPtr(p, offset) {
    try { return p.add(offset).readPointer().toString(); } catch(e) { return '0x0'; }
}
function safeReadU32(p, offset) {
    try { return p.add(offset).readU32(); } catch(e) { return 0; }
}

var hitCount = 0;

// ── Hook 任务分发器（单探针，低压） ──
Interceptor.attach(DISP_ADDR, {
    onEnter: function(args) {
        hitCount++;
        var taskPtr = args[0];

        // vtable 指针 = *(task_ptr)
        var vtable = '0x0';
        var vt = ['0x0','0x0','0x0','0x0'];
        try {
            var vtPtr = taskPtr.readPointer();
            vtable = vtPtr.toString();
            for (var i = 0; i < 4; i++) {
                vt[i] = safeReadPtr(vtPtr, i * 4);
            }
        } catch(e) {}

        // task 对象中的 this 指针 (offset +4)
        var thisPtr = safeReadPtr(taskPtr, 4);

        // task 对象前 32 字节（原始 u32 数组）
        var raw = [];
        for (var j = 0; j < 8; j++) {
            raw.push(safeReadU32(taskPtr, j * 4));
        }

        send({
            ts:     Date.now(),
            hit:    hitCount,
            task:   taskPtr.toString(),
            vtable: vtable,
            vt:     vt,
            this_:  thisPtr,
            raw:    raw,
            tid:    this.threadId
        });
    }
});

send({t:'ready', addr: DISP_ADDR.toString()});
"""

# ── 3. 收集事件 ────────────────────────────────────────────────────────────────
events = []
init_info = {}

def on_message(msg, data):
    if msg.get("type") != "send":
        if msg.get("type") == "error":
            print(f"[Frida ERROR] {msg.get('description','')}", flush=True)
        return
    p = msg["payload"]
    t = p.get("t","")
    if t == "init":
        init_info.update(p)
        print(f"[+] WXWork.exe base = {p['base']}", flush=True)
        print(f"[+] Dispatcher addr  = {p['disp']}", flush=True)
        print(f"[+] Prologue bytes   = {p['prolog']}", flush=True)
        expected = "55 8b ec 6a ff 68"
        if expected in p.get("prolog",""):
            print(f"[+] Prologue OK ✓", flush=True)
        else:
            print(f"[!] Prologue MISMATCH — 地址可能错误！", flush=True)
        return
    if t == "err":
        print(f"[ERR] {p.get('msg')}", flush=True)
        return
    if t == "ready":
        print(f"[+] Hook READY @ {p.get('addr')}", flush=True)
        return
    # 普通 dispatch 事件
    events.append(p)
    vt = p.get("vt", [])
    ts_s = datetime.fromtimestamp(p["ts"]/1000).strftime("%H:%M:%S")
    print(
        f"  [{p.get('hit'):4d}] {ts_s}  vtable={p.get('vtable')}  "
        f"vt[0]={vt[0] if vt else '?'}  tid={p.get('tid')}",
        flush=True
    )

# ── 4. Attach ─────────────────────────────────────────────────────────────────
print(f"[*] Attaching to PID {pid}...", flush=True)
sess = frida.get_local_device().attach(pid)
sc   = sess.create_script(JS)
sc.on("message", on_message)
sc.load()
time.sleep(3)   # 等 init + ready

# ── Phase 1: Baseline ─────────────────────────────────────────────────────────
print(f"\n{'='*60}", flush=True)
print(f"[PHASE 1] Baseline {PHASE1_SEC//60} min — 请勿操作企微", flush=True)
print(f"{'='*60}", flush=True)

t_phase1_start = time.time()
time.sleep(PHASE1_SEC)
t_phase1_end   = time.time()

ph1 = [e for e in events
       if t_phase1_start*1000 <= e["ts"] <= t_phase1_end*1000]
baseline_vtables = set(e["vtable"] for e in ph1)

print(f"\n[+] Phase1: {len(ph1)} 事件, {len(baseline_vtables)} 种 vtable", flush=True)
for v in sorted(baseline_vtables):
    cnt = sum(1 for e in ph1 if e["vtable"] == v)
    vt0 = next((e["vt"][0] for e in ph1 if e["vtable"] == v), "?")
    print(f"     vtable={v}  vt[0]={vt0}  次数={cnt}", flush=True)

# ── Phase 2: 转发触发 + 观察 ──────────────────────────────────────────────────
print(f"\n{'='*60}", flush=True)
print(f">>> 请立刻在企微执行一次消息转发！<<<", flush=True)
print(f">>> 向任意联系人转发一条消息（长按→转发 或 右键→转发）<<<", flush=True)
print(f"[*] 观察窗口 {PHASE2_SEC//60} 分钟开始...", flush=True)
print(f"{'='*60}", flush=True)

t_phase2_start = time.time()
time.sleep(PHASE2_SEC)
t_phase2_end   = time.time()

# 从全量 events 分拣（on_message 在 sleep 中持续追加）
ph1 = [e for e in events if t_phase1_start*1000 <= e["ts"] <= t_phase1_end*1000]
ph2 = [e for e in events if t_phase2_start*1000 <= e["ts"] <= t_phase2_end*1000]
baseline_vtables = set(e["vtable"] for e in ph1)
ph2_vtables      = set(e["vtable"] for e in ph2)
new_vtables      = ph2_vtables - baseline_vtables

# ── 5. Unload（安全约束：立即 detach）────────────────────────────────────────
sc.unload()
sess.detach()
print("\n[+] Hook unloaded & session detached", flush=True)

# ── 6. 输出 diff ──────────────────────────────────────────────────────────────
print(f"\n{'='*60}", flush=True)
print(f"[=== VTABLE DIFF ===]", flush=True)
print(f"  Phase1: {len(ph1)} 事件, {len(baseline_vtables)} 种 vtable", flush=True)
print(f"  Phase2: {len(ph2)} 事件, {len(ph2_vtables)} 种 vtable", flush=True)
print(f"  新增 vtable: {len(new_vtables)}", flush=True)

for v in sorted(new_vtables):
    rel = [e for e in ph2 if e["vtable"] == v]
    vt  = rel[0].get("vt", []) if rel else []
    print(f"\n  ★ NEW vtable = {v}  次数={len(rel)}  tid={rel[0].get('tid') if rel else '?'}", flush=True)
    for i, fn in enumerate(vt):
        print(f"       vt[{i}] = {fn}", flush=True)
    print(f"       raw[0..3] = {rel[0].get('raw', [])[:4] if rel else []}", flush=True)

if not new_vtables:
    print("\n  [未发现新 vtable]", flush=True)
    if ph2_vtables:
        print("  Phase2 所有 vtable（含 baseline）：", flush=True)
        for v in sorted(ph2_vtables):
            cnt = sum(1 for e in ph2 if e["vtable"] == v)
            vt0 = next((e["vt"][0] for e in ph2 if e["vtable"] == v), "?")
            tag = "★NEW" if v in new_vtables else "    "
            print(f"  {tag} vtable={v}  vt[0]={vt0}  次数={cnt}", flush=True)
    if not ph2:
        print("  [提示] Phase2 也无事件 — 可能转发未触发分发器，或需更长等待", flush=True)
        print("         备选方案：hook vt0 所在的 CGI 层在转发前后对比 CGI args", flush=True)

# ── 7. 保存 ───────────────────────────────────────────────────────────────────
ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"dispatch15_{ts_str}.json"

result = {
    "pid":  pid,
    "ts":   ts_str,
    "init": init_info,
    "phase1": {
        "event_count": len(ph1),
        "vtables": sorted(baseline_vtables),
        "events":  ph1,
    },
    "phase2": {
        "event_count": len(ph2),
        "vtables": sorted(ph2_vtables),
        "events":  ph2,
    },
    "diff": {
        "new_vtables": sorted(new_vtables),
        "details": [
            {
                "vtable": v,
                "vt": next((e["vt"] for e in ph2 if e["vtable"] == v), []),
                "count": sum(1 for e in ph2 if e["vtable"] == v),
            }
            for v in sorted(new_vtables)
        ]
    },
    "all_events": events,
}

out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[+] 结果保存: {out_path}")
print(f"[+] 全程 {len(events)} dispatch 事件")
