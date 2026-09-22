# wsa_stack_scan.py
# 在 WSASend 触发时读取 ESP 以上 2KB 栈内存，扫描 compact (01 XX XX XX) 模式
# 同时读取调用栈各帧的 EBP 所指向的帧局部变量区

import frida, subprocess, sys, os, time, json, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx   = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
var wxEnd  = wxBase.add(wx.size);
var ws2  = Process.getModuleByName('ws2_32.dll');

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}
function addrInWx(a) {
    try { return a.compare(wxBase)>=0 && a.compare(wxEnd)<0; } catch(e) { return false; }
}

var wsaSend = null;
ws2.enumerateExports().forEach(function(e) { if (e.name==='WSASend') wsaSend=e.address; });

var hits = [];
var hitCount = 0;
var MAX = 10;

if (wsaSend) {
    Interceptor.attach(wsaSend, {
        onEnter: function(args) {
            if (hitCount >= MAX) return;
            
            // read buffer info
            var bufLen = 0; var bufHex = '';
            try {
                bufLen = args[1].readU32();
                if (bufLen > 0 && bufLen < 65536) {
                    var bufPtr = args[1].add(4).readPointer();
                    var d = new Uint8Array(bufPtr.readByteArray(Math.min(bufLen, 48)));
                    bufHex = Array.from(d).map(b=>('0'+b.toString(16)).slice(-2)).join('');
                }
            } catch(e) {}

            // 只关心 len<=50 的包（转发请求小包）
            if (bufLen > 50 || bufLen === 0) return;
            hitCount++;

            // 读当前 ESP 以上 2KB 栈内存
            var espVal = this.context.esp;
            var stack = safeR(espVal, 2048);
            
            // 扫描栈内存，找 01 XX XX XX 模式（4字节对齐）
            var compacts = [];
            if (stack) {
                for (var i = 0; i < stack.length - 3; i += 4) {
                    if (stack[i] === 0x01) {
                        var cv = stack[i+1].toString(16).padStart(2,'0') +
                                 stack[i+2].toString(16).padStart(2,'0') +
                                 stack[i+3].toString(16).padStart(2,'0');
                        compacts.push({off: i, val: '01' + cv});
                    }
                }
            }

            // 读 EBP 链（向上走 10 帧），读每帧的局部变量区（EBP-0x100 ~ EBP）
            var ebpVal = this.context.ebp;
            var frames = [];
            var curEbp = ebpVal;
            for (var fi = 0; fi < 12; fi++) {
                try {
                    var retAddr = curEbp.add(4).readU32() >>> 0;
                    var prevEbp = curEbp.readU32() >>> 0;
                    // 读本帧局部变量
                    var locals = safeR(curEbp.sub(0x80), 0x80 + 0x20);
                    var localCompacts = [];
                    if (locals) {
                        for (var li = 0; li < locals.length - 3; li += 4) {
                            if (locals[li] === 0x01) {
                                var cv2 = locals[li+1].toString(16).padStart(2,'0') +
                                          locals[li+2].toString(16).padStart(2,'0') +
                                          locals[li+3].toString(16).padStart(2,'0');
                                localCompacts.push({off: li - 0x80, val: '01'+cv2});
                            }
                        }
                    }
                    var inWx = addrInWx(ptr(retAddr));
                    frames.push({
                        fi: fi,
                        ret: '0x' + retAddr.toString(16),
                        rva: inWx ? '0x' + (retAddr - (wxBase.toInt32()>>>0)).toString(16) : null,
                        inWx: inWx,
                        localCompacts: localCompacts
                    });
                    if (prevEbp < (curEbp.toInt32()>>>0) || prevEbp > (curEbp.toInt32()>>>0) + 0x100000) break;
                    curEbp = ptr(prevEbp);
                } catch(e) { break; }
            }

            var rec = {bufLen:bufLen, buf:bufHex, stackCompacts:compacts.slice(0,30), frames:frames};
            hits.push(rec);
            send({t:'hit', bufLen:bufLen, buf:bufHex.slice(0,24),
                  nStackCompacts:compacts.length, 
                  nFrameCompacts: frames.reduce(function(s,f){return s+f.localCompacts.length;},0),
                  frames: frames.filter(function(f){return f.inWx;}).map(function(f){return f.rva;})
                 });
        }
    });
    send({t:'info', m:'WSASend hooked @ ' + wsaSend.toString()});
}

send({t:'ready'});
recv('dump', function(_) { send({t:'dump', hits:hits}); });
"""

ready_event = threading.Event()
dump_event  = threading.Event()
all_hits    = []

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  {p["m"]}')
    elif t == 'ready': ready_event.set()
    elif t == 'hit':
        print(f'\n  ★ WSASend len={p["bufLen"]} buf={p["buf"]}')
        print(f'    栈 compact 候选: {p["nStackCompacts"]} 个, 帧局部 compact 候选: {p["nFrameCompacts"]} 个')
        print(f'    WXWork 帧 RVA: {p["frames"]}')
    elif t == 'dump':
        all_hits.extend(p.get('hits',[]))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
ready_event.wait(10)

print('\n[等待] 60s — 请在企微转发一条消息！')
print('='*60)
time.sleep(60)

sc.post({'type':'dump'})
dump_event.wait(15)

print(f'\n[分析] {len(all_hits)} 次 WSASend hit')
for i, h in enumerate(all_hits):
    print(f'\n== Hit #{i+1} len={h["bufLen"]} buf={h["buf"][:16]} ==')
    
    scs = h.get('stackCompacts', [])
    print(f'  栈 compact 候选 ({len(scs)}):')
    from collections import Counter
    cc = Counter(c['val'] for c in scs)
    for v, cnt in cc.most_common(10):
        print(f'    {v}  x{cnt}')

    print(f'  帧局部变量 compact:')
    for fr in h.get('frames', []):
        lcs = fr.get('localCompacts', [])
        if lcs:
            rva = fr.get('rva', '?')
            print(f'    frame[{fr["fi"]}] ret={fr["ret"]} rva={rva}:')
            for lc in lcs:
                print(f'      off={lc["off"]:+d}  compact={lc["val"]}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'wsa_stack_{ts}.json'
out.write_text(json.dumps(all_hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
