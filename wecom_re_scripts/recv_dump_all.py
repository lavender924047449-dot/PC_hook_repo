# recv_dump_all.py — 无差别 dump 所有 EVP_DecryptUpdate 输出
#
# 策略：抛弃 marker，只按 size ≥ 256B 过滤，去重防洪水，dump 前 80 份
# 用户操作：120s 窗口内，第 30 秒左右手机发一条新语音到 FTA
# 收工后离线用另一个脚本人肉分析
#
# 环境：Frida 17，Python 3.11 —— 单 hook + 无心跳（延续 stealth 模式）

import frida, subprocess, sys, os, json, time
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 120

print(f'[*] dump-all recon — ts={ts}  window={CAPTURE_SEC}s')

JS = r"""
'use strict';
var mod = Process.findModuleByName('libcrypto-1_1.dll');
if (!mod) { send({t:'fatal', msg:'no libcrypto-1_1.dll'}); }
else {
    var addr = mod.findExportByName('EVP_DecryptUpdate');
    if (!addr) { send({t:'fatal', msg:'no EVP_DecryptUpdate'}); }
    else {
        var MAX_DUMPS = 80;
        var MIN_SIZE = 256;
        var MAX_SIZE = 65536;
        var dumps = 0;
        var events = 0;
        var seen = {};  // 去重 key = size + head8

        function toHex(u8, n){
            var s='', lim=Math.min(n, u8.length);
            for(var i=0;i<lim;i++) s+=('0'+u8[i].toString(16)).slice(-2);
            return s;
        }

        Interceptor.attach(addr, {
            onEnter: function(a){
                this._out  = a[1];
                this._outl = a[2];
                this._inl  = a[4].toInt32();
            },
            onLeave: function(rv){
                if (rv.toInt32() !== 1) return;
                events++;
                if (dumps >= MAX_DUMPS) return;
                try {
                    var w = 0;
                    try { w = this._outl.readInt(); } catch(e){ w = this._inl; }
                    if (w < MIN_SIZE || w > MAX_SIZE) return;
                    var raw = this._out.readByteArray(w);
                    if (!raw) return;
                    var u8 = new Uint8Array(raw);
                    var key = w + '_' + toHex(u8, 8);
                    if (seen[key]) return;
                    seen[key] = 1;
                    dumps++;
                    send({t:'dump', seq:dumps, n:w, head:toHex(u8, Math.min(w, 128))}, raw);
                } catch(e) {}
            }
        });
        send({t:'armed'});
        setTimeout(function(){ send({t:'tick', events:events, dumps:dumps}); }, 30000);
        setTimeout(function(){ send({t:'tick', events:events, dumps:dumps}); }, 60000);
        setTimeout(function(){ send({t:'tick', events:events, dumps:dumps}); }, 90000);
        setTimeout(function(){ send({t:'tick', events:events, dumps:dumps}); }, 115000);
    }
}
"""

dumps = 0

def on_msg(m, data):
    global dumps
    if m.get('type') == 'error':
        print(f'[JS-ERR] {m.get("description","")[:400]}', flush=True); return
    if m.get('type') != 'send': return
    p = m['payload']; t = p.get('t')
    if t == 'fatal':
        print(f'[FATAL] {p["msg"]}', flush=True); return
    if t == 'armed':
        print(f'[+] armed. all EVP outputs ≥ 256B will be dumped (dedup + cap 80)', flush=True); return
    if t == 'tick':
        print(f'  ▶ tick  events={p["events"]}  dumps={p["dumps"]}', flush=True); return
    if t == 'dump':
        dumps += 1
        seq = p['seq']; n = p['n']; head = p['head']
        bin_path = OUT_DIR / f'evp_dump_{ts}_seq{seq:03d}_n{n}.bin'
        if data: bin_path.write_bytes(data)
        print(f'  ▪ dump #{seq}  n={n}  head={head[:48]}...  → {bin_path.name}', flush=True)


def get_pid():
    out = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('WXWork.exe not found')


def main():
    pid = get_pid()
    print(f'[*] target PID = {pid}')
    dev = frida.get_local_device()
    sess = dev.attach(pid)
    sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()
    print(f'\n{"="*72}')
    print(f'★★★ 120s 窗口 ★★★')
    print(f'   请在【第 30 秒左右】手机 → FTA → 按住说话 → 说 10 秒 → 松手发送')
    print(f'   然后【第 90 秒左右】再发一条（可选，双保险）')
    print(f'   期间 PC 保持 FTA 前台可见')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. 总 dump = {dumps}', flush=True)
    os._exit(0)

if __name__ == '__main__':
    main()
