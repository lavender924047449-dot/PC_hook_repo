# hook_msgtype_patch.py — Path 2 关键实验
#
# 假设：outer wrapper (vt=0xb0610c0) 的 this[+0x08] = 15 是"降级 unsupported" msgtype
#       改为 34 (WeChat 历史 voice msgtype) 后：
#         (a) 服务端接受 → 小号收到语音气泡 → 突破成功 🎉
#         (b) 服务端拒绝  → 小号啥都没收到 / 收到错误 → 政策强制在服务端
#         (c) 客户端在打包前二次判断 → 逻辑被跳过 or 崩溃
#
# 关键 offsets（从 _find_msgtype.py 结果）:
#   this+0x00 = vtable
#   this+0x08 = 15 (msgtype 强候选)  ← PATCH 这里
#   this+0x0c = 21 or 19 (可能长度/内容变化)
#   this+0x20 = seq 46/47/48 (单调递增)

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 120

# 目标
V_SER          = 0x09f042a0
PRESEND_RVA    = 0x919ffb2
OUTER_VT       = 0xb0610c0
PATCH_OFFSET   = 0x08
PATCH_ORIG     = 15
PATCH_NEW      = int(os.environ.get('VOICE_MSGTYPE', '34'))  # env var 可调
DRY_RUN        = os.environ.get('DRY_RUN', '0') == '1'

print(f'[*] patch target: outer wrapper this[+{PATCH_OFFSET:#x}] : {PATCH_ORIG} → {PATCH_NEW}')
print(f'[*] DRY_RUN={DRY_RUN} (1=只读不写；0=真 patch)')

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);
var V_SER = ptr(__V_SER__);
var OUTER_VT = __OUTER_VT__;
var PATCH_OFF = __PATCH_OFF__;
var PATCH_NEW = __PATCH_NEW__;
var DRY_RUN = __DRY_RUN__;

function safeBytes(a, sz) {
    try { var p = (typeof a === 'number') ? ptr(a) : a;
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function readU32(p) { try { return p.readU32(); } catch(e) { return 0; } }
function writeU32(p, v) { try { Memory.protect(p, 4, 'rwx'); p.writeU32(v); return true; } catch(e) { return false; } }

var WIN = {tid_state:{}, presend_cnt:0};
Interceptor.attach(PRESEND, {
    onEnter: function() {
        WIN.tid_state[this.threadId] = 1;
        WIN.presend_cnt++;
        send({t:'presend_enter', n:WIN.presend_cnt});
    },
    onLeave: function(rv) {
        delete WIN.tid_state[this.threadId];
        send({t:'presend_leave', n:WIN.presend_cnt, retval:'0x'+rv.toUInt32().toString(16)});
    }
});

var SER_CNT = 0;
Interceptor.attach(V_SER, {
    onEnter: function(args) {
        if (!WIN.tid_state[this.threadId]) return;
        SER_CNT++;
        var this_v = this.context.ecx.toUInt32();
        var raw = safeBytes(this_v, 128);
        if (!raw) return;
        var vt = ((new Uint8Array(raw))[0] | ((new Uint8Array(raw))[1]<<8) | ((new Uint8Array(raw))[2]<<16) | ((new Uint8Array(raw))[3]<<24)) >>> 0;
        if (vt !== OUTER_VT) return;  // 只处理外层 wrapper

        var offset_ptr = ptr(this_v).add(PATCH_OFF);
        var before = readU32(offset_ptr);
        this._before = before;
        this._addr = '0x'+this_v.toString(16);

        var arg0_v = args[0].toUInt32();
        var arg0_before = safeBytes(arg0_v, 512);

        var patched = false;
        if (!DRY_RUN) {
            patched = writeU32(offset_ptr, PATCH_NEW);
        }
        var after = readU32(offset_ptr);

        send({t:'ser_enter', n:SER_CNT, this_addr:this._addr,
              before:before, after:after, patched:patched,
              vt:'0x'+vt.toString(16),
              this_hex: toHex(raw),
              arg0_addr: '0x'+arg0_v.toString(16),
              arg0_before: arg0_before ? toHex(arg0_before) : null,
        });

        this._arg0_v = arg0_v;
    },
    onLeave: function(rv) {
        if (!this._before) return;   // 没进入 onEnter or 不是 outer
        var arg0_after = safeBytes(this._arg0_v, 512);
        send({t:'ser_leave', this_addr: this._addr,
              arg0_addr: '0x'+this._arg0_v.toString(16),
              arg0_after: arg0_after ? toHex(arg0_after) : null});
    }
});

send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
def on_msg(m, d):
    if m.get('type')=='error':
        print(f'[ERR] {m.get("description","")[:400]}', flush=True); return
    if m.get('type')!='send': return
    p = m['payload']; t = p.get('t')
    if t == 'ready':
        print('[+] patch hook ARMED', flush=True); return
    if t == 'presend_enter':
        print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER', flush=True); return
    if t == 'presend_leave':
        print(f'[PRESEND #{p["n"]}] LEAVE  retval={p["retval"]}\n{"="*72}', flush=True); return
    if t == 'ser_enter':
        mark = '★PATCHED' if p['patched'] else ('DRY-RUN' if DRY_RUN else '★FAILED')
        print(f'\n  ▶ SER onEnter #{p["n"]}  this={p["this_addr"]}  vt={p["vt"]}', flush=True)
        print(f'    this[+{PATCH_OFFSET:#x}] : {p["before"]} → {p["after"]}  {mark}', flush=True)
        # dump this
        if p.get('this_hex'):
            fn = OUT_DIR / f'msgtype_patch_{ts}_ser{p["n"]}_this_enter.bin'
            fn.write_bytes(bytes.fromhex(p['this_hex']))
        if p.get('arg0_before'):
            fn = OUT_DIR / f'msgtype_patch_{ts}_ser{p["n"]}_arg0_before.bin'
            fn.write_bytes(bytes.fromhex(p['arg0_before']))
        hits.append(p)
        return
    if t == 'ser_leave':
        if p.get('arg0_after'):
            fn = OUT_DIR / f'msgtype_patch_{ts}_arg0_after.bin'
            fn.write_bytes(bytes.fromhex(p['arg0_after']))
            # 找 msgtype varint 在 wire 里的位置
            data = bytes.fromhex(p['arg0_after'])
            # 找 tag byte 0x08 (field 1 varint) 后跟 patch_new 值
            for i in range(min(64, len(data)-2)):
                if data[i] == 0x08 and data[i+1] == PATCH_NEW:
                    print(f'    ✓ wire msgtype varint found @+{i:#x}: 08 {PATCH_NEW:02x}  ← patch 已写入 wire！', flush=True)
                    break
            else:
                # 找 old varint
                for i in range(min(64, len(data)-2)):
                    if data[i] == 0x08 and data[i+1] == PATCH_ORIG:
                        print(f'    ⚠ wire 里仍是旧 msgtype: 08 {PATCH_ORIG:02x} @+{i:#x}  ← patch 没生效到 wire', flush=True)
                        break
        return

def main():
    pid = get_pid(); print(f'[*] PID={pid}')
    js = (JS_TPL.replace('__PRESEND_RVA__', str(PRESEND_RVA))
                .replace('__V_SER__', str(V_SER))
                .replace('__OUTER_VT__', str(OUTER_VT))
                .replace('__PATCH_OFF__', str(PATCH_OFFSET))
                .replace('__PATCH_NEW__', str(PATCH_NEW))
                .replace('__DRY_RUN__', 'true' if DRY_RUN else 'false'))
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 你有 {CAPTURE_SEC}s ★★★')
    print(f'   1. 【多选】FTA 里的语音消息 → 【逐条转发】→ 选小号 → 发送')
    print(f'   2. 只做 1 次，观察小号那边收到什么')
    print(f'   3. 期望：语音气泡（突破）/ [语音]文本（服务端拒）/ 无消息（错）')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. SER outer hits = {len(hits)}', flush=True)
    os._exit(0)

if __name__ == '__main__':
    main()
