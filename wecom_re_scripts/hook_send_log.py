# hook_send_log.py — Hook WXWork+0x2B9566B（SendMessage 日志 PUSH 指令）
# 读栈参数 ([esp+0..0x40])，尝试解引用为字符串，抓 conversationId / msgId / ClientId / task_id
import frida, subprocess, sys, os, time, json
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
SENTINEL = OUT / '_send_done.flag'
if SENTINEL.exists(): SENTINEL.unlink()

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('WXWork :9882 not found')

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
// SendMessage 函数入口（回溯到 55 8B EC 6A FF 序言）
var RVA = 0x2B93BE2;
var TARGET = base.add(RVA);
send({t:'ready', base: base.toString(), target: TARGET.toString()});

function tryReadStr(p) {
    // 支持 ASCII + UTF-16LE
    try {
        var v = p.toInt32() >>> 0;
        if (v < 0x10000 || v > 0x80000000) return null;
        var bytes = new Uint8Array(ptr(v).readByteArray(512));
        if (bytes[0] < 0x20 || bytes[0] > 0x7e) return null;
        // 判 UTF-16：first byte ASCII, second byte 0
        if (bytes.length > 6 && bytes[1] === 0 && bytes[3] === 0 && bytes[5] === 0) {
            var s = '';
            for (var i = 0; i < 512; i += 2) {
                var c = bytes[i] | (bytes[i+1] << 8);
                if (c === 0 || c < 0x20 || c > 0x7e) break;
                s += String.fromCharCode(c);
            }
            if (s.length >= 3) return '[U16]' + s;
        }
        // ASCII
        var end = 0;
        while (end < 512 && bytes[end] >= 0x20 && bytes[end] < 0x7f) end++;
        if (end < 3) return null;
        var s2 = '';
        for (var i = 0; i < end; i++) s2 += String.fromCharCode(bytes[i]);
        return s2;
    } catch(e) { return null; }
}
// 兼容旧名
var tryReadCString = tryReadStr;

// 关键格式串地址（"do send message to peer post to session..." 的 .rdata 位置）
var FORMAT_STR = 0x0AE8C664;

var totalCount = 0;
var filteredCount = 0;
var retCounts = {};
// 4 处候选 .rdata 格式串（若命中任一即认为是 send 相关日志）
var FORMAT_CANDIDATES = [0x0AE8C664, 0x0AE8C858, 0x0AE8B768];

Interceptor.attach(TARGET, {
    onEnter: function(args) {
        totalCount++;
        try {
            var esp = this.context.esp;
            var ret = esp.readU32() >>> 0;
            retCounts[ret] = (retCounts[ret] || 0) + 1;

            // 扫栈 32 dwords，找任一候选格式串
            var hasFormat = false;
            var matchedFmt = 0;
            for (var i = 1; i <= 32; i++) {
                var v = 0;
                try { v = esp.add(i*4).readU32() >>> 0; } catch(e) { break; }
                for (var k = 0; k < FORMAT_CANDIDATES.length; k++) {
                    if (v === FORMAT_CANDIDATES[k]) { hasFormat = true; matchedFmt = v; break; }
                }
                if (hasFormat) break;
            }
            // 也检查寄存器
            if (!hasFormat) {
                var regs = [this.context.eax >>> 0, this.context.ebx >>> 0,
                            this.context.ecx >>> 0, this.context.edx >>> 0,
                            this.context.esi >>> 0, this.context.edi >>> 0];
                for (var i = 0; i < regs.length; i++) {
                    for (var k = 0; k < FORMAT_CANDIDATES.length; k++) {
                        if (regs[i] === FORMAT_CANDIDATES[k]) {
                            hasFormat = true; matchedFmt = regs[i]; break;
                        }
                    }
                    if (hasFormat) break;
                }
            }
            if (!hasFormat) return;

            filteredCount++;
            var frame = {
                hit: filteredCount,
                totalHit: totalCount,
                matchedFmt: '0x' + matchedFmt.toString(16),
                ts: Date.now(),
                esp: esp.toString(),
                ret_addr: '0x' + ret.toString(16),
                ecx: '0x' + (this.context.ecx >>> 0).toString(16),
                edx: '0x' + (this.context.edx >>> 0).toString(16),
                slots: []
            };
            // 读 esp+4..esp+0x80（32 个 dword = 参数区）
            for (var i = 1; i <= 32; i++) {
                var slot_addr = esp.add(i * 4);
                var slot_val = 0;
                try { slot_val = slot_addr.readU32() >>> 0; } catch(e) { break; }
                var entry = {
                    off: i * 4,
                    val: '0x' + slot_val.toString(16)
                };
                var s = tryReadCString(ptr(slot_val));
                if (s) entry.str = s;
                frame.slots.push(entry);
            }
            // 常见 C++ std::string 是"栈上对象"，本身占 16-28 字节
            // std::string 内部布局：{ptr, size, capacity} 或 SBO (small buffer)
            // 如果参数是 std::string* → 读 *(参数) 得到 data ptr
            for (var i = 1; i <= 8; i++) {
                var slot_val = esp.add(i * 4).readU32() >>> 0;
                if (slot_val > 0x10000 && slot_val < 0x80000000) {
                    try {
                        var deref = ptr(slot_val).readU32() >>> 0;
                        var s2 = tryReadCString(ptr(deref));
                        if (s2 && frame.slots[i-1]) {
                            frame.slots[i-1].deref_str = s2;
                        }
                    } catch(e) {}
                }
            }
            send({t:'hit', frame: frame});
        } catch(e) {
            send({t:'err', msg: e.message});
        }
    }
});

recv('stat', function(_) {
    var arr = [];
    for (var k in retCounts) arr.push([k, retCounts[k]]);
    arr.sort(function(a,b){ return b[1] - a[1]; });
    send({t:'stat', total: totalCount, filtered: filteredCount, topRet: arr.slice(0, 15)});
});
"""

hits = []
ready = [False]
stat_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        ready[0] = True
        print(f'[+] ready wxBase={p["base"]}  target={p["target"]}')
    elif p.get('t') == 'hit':
        f = p['frame']
        hits.append(f)
        print(f'\n★ FILTERED Hit #{f["hit"]}/{f["totalHit"]}  esp={f["esp"]}  ret={f["ret_addr"]}  ecx={f["ecx"]}  edx={f["edx"]}')
        printed = 0
        for s in f['slots'][:16]:
            marks = []
            if 'str' in s: marks.append(f'STR={s["str"][:80]!r}')
            if 'deref_str' in s: marks.append(f'*STR={s["deref_str"][:80]!r}')
            if marks:
                print(f'   [esp+{s["off"]:02x}] {s["val"]}  {"  ".join(marks)}')
                printed += 1
        if printed == 0:
            # 无字符串就打印前 8 个非零
            nz = [s for s in f['slots'] if s['val'] != '0x0'][:8]
            for s in nz:
                print(f'   [esp+{s["off"]:02x}] {s["val"]}')
    elif p.get('t') == 'err':
        print(f'   [!] onEnter err: {p["msg"]}')
    elif p.get('t') == 'stat':
        print(f'\n[STAT] 总命中 {p["total"]} 次；过滤后 {p["filtered"]} 次')
        print(f'[STAT] top ret_addr:')
        for k, v in p['topRet']:
            print(f'  {k}: {v}')
        stat_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
if not ready[0]:
    print('[!] 脚本未就绪'); sys.exit(1)

print('\n' + '='*60)
print('>>> 现在请转发 1 条到 FTA 或任意目标 <<<')
print(f'>>> 完成后创建 {SENTINEL.name} 触发 dump <<<')
print('='*60 + '\n')

t0 = time.time()
while not SENTINEL.exists() and time.time() - t0 < 15*60:
    time.sleep(0.5)
if SENTINEL.exists():
    try: SENTINEL.unlink()
    except: pass
    print(f'\n[+] sentinel 收到（等待 {time.time()-t0:.1f}s）')
time.sleep(2)

# 请 JS 侧返回统计
sc.post({'type': 'stat'})
t0 = time.time()
while not stat_ok[0] and time.time() - t0 < 5:
    time.sleep(0.2)

print(f'\n[结果] filtered hits: {len(hits)} 次')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'send_log_{ts}.json'
out.write_text(json.dumps({'pid': pid, 'ts': ts, 'hits': hits},
                          ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] 保存: {out}')
sc.unload()
sess.detach()
os._exit(0)
