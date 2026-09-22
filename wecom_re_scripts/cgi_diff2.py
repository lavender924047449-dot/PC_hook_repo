# cgi_diff2.py -- CGI 热路径 args diff（前后对比，自动找转发 pattern）
# ==========================================================================
# 不依赖固定 pattern，而是：
#   Phase1 30s: baseline（记录所有唯一 a1 pattern）
#   提示用户转发
#   Phase2 30s: 观察（记录新增 a1 pattern）
#   输出差异 → 这就是转发专属 CGI
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/cgi_diff2.py

import frida, subprocess, time, json, sys, threading, os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
RVA_CGI = 0x390B39
PHASE1_SEC = 30
PHASE2_SEC = 45

def get_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f"[+] PID = {pid}", flush=True)

# ─── Frida JS：每 100 次 hit 抽样一次所有 a1 pattern ──────────────────────────
JS = r"""
'use strict';
var wxBase = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base; break;
    }
}
var HOOK = wxBase.add(0x390B39);
var hitCount = 0;
var PHASE = 0;  // 0=baseline 1=fwd
var patCounts = {};  // pattern -> count in current phase
var SAMPLE_LIMIT = 5000;  // 安全上限

function toHex4(ptr) {
    try {
        var b = ptr.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return 'ERR'; }
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        hitCount++;
        if (hitCount > SAMPLE_LIMIT) return;

        var pat = 'ERR';
        try { pat = toHex4(args[1]); } catch(e) {}
        patCounts[pat] = (patCounts[pat] || 0) + 1;
    }
});

// 收到 collect 命令时，返回当前 patCounts 并清空
// Frida recv() 是一次性的，需要在回调中重新注册
function waitCollect() {
    recv('collect', function(msg) {
        var result = {};
        for (var k in patCounts) result[k] = patCounts[k];
        patCounts = {};
        hitCount = 0;
        send({t:'collected', phase: msg.phase || 'unknown', data: result});
        waitCollect();  // 重新注册，等待下一次 collect
    });
}
waitCollect();

send({t:'ready', base:wxBase.toString(), addr:HOOK.toString()});
"""

result_event = threading.Event()
collected = {}

def on_message(msg, data):
    if msg.get("type") == "error":
        print(f"[Frida ERR] {msg.get('description','')}", flush=True)
        return
    if msg.get("type") != "send": return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        print(f"[+] Hook READY @ {p.get('addr')}  base={p.get('base')}", flush=True)
    elif t == "collected":
        phase = p.get("phase","unknown")
        if isinstance(phase, str):
            collected[phase] = p.get("data",{})
        print(f"[+] {phase} 收集完成: {len(collected[phase])} 种 pattern", flush=True)
        result_event.set()

print(f"[*] Attaching...", flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_message)
sc.load()
time.sleep(1)

# ─── Phase 1: Baseline ────────────────────────────────────────────────────────
print(f"\n[PHASE 1] 采集 baseline {PHASE1_SEC}s（勿操作企微）...", flush=True)
time.sleep(PHASE1_SEC)
result_event.clear()
sc.post({"type": "collect", "phase": "baseline"})
result_event.wait(timeout=5)

baseline_pats = set(collected.get("baseline", {}).keys())
print(f"[+] Baseline patterns: {sorted(baseline_pats)}", flush=True)

# ─── 提示转发 ─────────────────────────────────────────────────────────────────
print(f"\n{'='*60}", flush=True)
print(f"★★★ 请立刻在企微执行消息转发！★★★", flush=True)
print(f"  右键聊天消息 → 转发 → 选联系人 → 发送", flush=True)
print(f"  有 {PHASE2_SEC}s 时间窗口", flush=True)
print(f"{'='*60}", flush=True)

# ─── Phase 2: 观察 ────────────────────────────────────────────────────────────
print(f"[PHASE 2] 观察 {PHASE2_SEC}s...", flush=True)
time.sleep(PHASE2_SEC)
result_event.clear()
sc.post({"type": "collect", "phase": "forward"})
result_event.wait(timeout=5)

fwd_pats = set(collected.get("forward", {}).keys())
new_pats = fwd_pats - baseline_pats

print(f"\n{'='*60}", flush=True)
print(f"[=== DIFF RESULT ===]", flush=True)
print(f"  Baseline: {len(baseline_pats)} 种 pattern", flush=True)
print(f"  Forward:  {len(fwd_pats)} 种 pattern", flush=True)
print(f"  新增 (转发专属): {len(new_pats)}", flush=True)

for pat in sorted(new_pats):
    cnt = collected.get("forward",{}).get(pat, 0)
    print(f"    ★ NEW a1[0:4] = '{pat}'  次数={cnt}", flush=True)

if not new_pats:
    print(f"\n  [未发现新 pattern]", flush=True)
    if not fwd_pats:
        print(f"  Phase2 无任何 hit — hook 在 Phase2 期间未触发", flush=True)
    else:
        print(f"  Phase2 中的 pattern（与 baseline 相同）：{sorted(fwd_pats)}", flush=True)
        print(f"  -> 转发 CGI 可能使用了 baseline 中已有的 pattern，需进一步分析", flush=True)
        # 找 Phase2 中计数异常高的 pattern
        bl_data = collected.get("baseline",{})
        fw_data = collected.get("forward",{})
        print(f"\n  Baseline vs Forward 计数对比（排除计数相近的）：", flush=True)
        for pat in sorted(fwd_pats):
            bl_cnt = bl_data.get(pat,0)
            fw_cnt = fw_data.get(pat,0)
            ratio = fw_cnt / (bl_cnt+0.1)
            if ratio > 2 or (fw_cnt - bl_cnt) > 5:
                print(f"    ↑ a1[0:4]='{pat}' bl={bl_cnt} fw={fw_cnt} ratio={ratio:.1f}x", flush=True)

# 保存
ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"cgi_diff2_{ts_str}.json"
out_path.write_text(json.dumps({
    "baseline": collected.get("baseline",{}),
    "forward": collected.get("forward",{}),
    "new_pats": list(new_pats),
}, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[+] 结果保存: {out_path}", flush=True)

os._exit(0)
