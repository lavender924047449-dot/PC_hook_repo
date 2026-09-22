# hook_wire_patch.py — Path 2.5: 直接改 wire
#
# 策略：
#   1. this[+0x08] 保持不变 (=15)，让 C++ 正常写出 field1=1
#   2. 在 SER onLeave 里读 arg0 前 32 字节，找 `08 XX` (field1 varint tag)
#   3. 把 XX 直接改成候选值（默认 34）
#   4. 不改长度，纯替换 1 字节，不会触发大小校验
#
# 环境变量：
#   WIRE_MSGTYPE=34   （候选：34/43/50/62/9/74）
#   DRY_RUN=1         （只读不写）

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 120

V_SER       = 0x09f042a0
PRESEND_RVA = 0x919ffb2
OUTER_VT    = 0xb0610c0
WIRE_NEW    = int(os.environ.get('WIRE_MSGTYPE', '34'))
DRY_RUN     = os.environ.get('DRY_RUN', '0') == '1'

print(f'[*] wire patch: arg0[+1] (field1 varint value) → {WIRE_NEW}')
print(f'[*] DRY_RUN={DRY_RUN}')

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);
var V_SER   = ptr(__V_SER__);
var OUTER_VT = __OUTER_VT__;
var WIRE_NEW = __WIRE_NEW__;
var DRY_RUN  = __DRY_RUN__;

function safeBytes(a, sz) {
    try { var p = (typeof a==='number')?ptr(a):a;
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e){ return null; }
}
function toHex(ab){ var a=new Uint8Array(ab),s=''; for(var i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }

var WIN={tid:{},cnt:0};
Interceptor.attach(PRESEND,{
    onEnter:function(){ WIN.tid[this.threadId]=1; WIN.cnt++; send({t:'presend_enter',n:WIN.cnt}); },
    onLeave:function(rv){ delete WIN.tid[this.threadId]; send({t:'presend_leave',n:WIN.cnt,retval:'0x'+rv.toUInt32().toString(16)}); }
});

var SER_CNT=0;
Interceptor.attach(V_SER,{
    onEnter:function(args){
        if(!WIN.tid[this.threadId]) return;
        SER_CNT++;
        var this_v=this.context.ecx.toUInt32();
        var raw=safeBytes(this_v,32);
        if(!raw) return;
        var a=new Uint8Array(raw);
        var vt=(a[0]|(a[1]<<8)|(a[2]<<16)|(a[3]<<24))>>>0;
        if(vt!==OUTER_VT) return;
        this._arg0=args[0].toUInt32();
        this._sn=SER_CNT;
        this._is_outer=true;
    },
    onLeave:function(rv){
        if(!this._is_outer) return;
        var arg0=this._arg0;
        var head=safeBytes(arg0, 64);
        if(!head){ send({t:'ser_leave',err:'no head',sn:this._sn}); return; }
        var h=new Uint8Array(head);
        // 找 field1 varint: tag=0x08 at offset 0 (常见情况)
        var found_off=-1, orig_val=-1;
        for (var i=0;i<Math.min(32,h.length-1);i++){
            if (h[i]===0x08){
                // 只处理单字节 varint (< 128)
                if (h[i+1] < 0x80){
                    found_off=i+1; orig_val=h[i+1]; break;
                }
            }
        }
        if (found_off<0){
            send({t:'ser_leave',sn:this._sn,head:toHex(head),note:'field1 未找到'});
            return;
        }
        var patched=false;
        if (!DRY_RUN){
            try { Memory.protect(ptr(arg0+found_off),1,'rwx'); ptr(arg0+found_off).writeU8(WIRE_NEW); patched=true; } catch(e){}
        }
        var head2=safeBytes(arg0,64);
        send({t:'ser_leave',sn:this._sn, off:found_off, orig:orig_val, newv:WIRE_NEW,
              patched:patched, head_before:toHex(head), head_after: head2?toHex(head2):null});
    }
});
send({t:'ready'});
"""

hits=[]
def on_msg(m,d):
    if m.get('type')=='error': print(f'[ERR] {m.get("description","")[:400]}',flush=True); return
    if m.get('type')!='send': return
    p=m['payload']; t=p.get('t')
    if t=='ready': print('[+] wire patch hook ARMED',flush=True); return
    if t=='presend_enter': print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER',flush=True); return
    if t=='presend_leave': print(f'[PRESEND #{p["n"]}] LEAVE  retval={p["retval"]}\n{"="*72}',flush=True); return
    if t=='ser_leave':
        sn=p['sn']
        if 'err' in p: print(f'  ▶ SER#{sn} leave err={p["err"]}',flush=True); return
        if 'note' in p:
            print(f'  ▶ SER#{sn} leave: {p["note"]}   head={p["head"][:64]}',flush=True); return
        mark='★PATCHED' if p['patched'] else ('DRY-RUN' if DRY_RUN else '★FAIL')
        print(f'\n  ▶ SER#{sn} leave',flush=True)
        print(f'    field1 varint  @wire[+{p["off"]}]  : {p["orig"]} → {p["newv"]}  {mark}',flush=True)
        print(f'    head_before: {p["head_before"][:96]}',flush=True)
        print(f'    head_after : {p["head_after"][:96]}',flush=True)
        # 保存
        (OUT_DIR / f'wire_patch_{ts}_sn{sn}_before.bin').write_bytes(bytes.fromhex(p['head_before']))
        (OUT_DIR / f'wire_patch_{ts}_sn{sn}_after.bin' ).write_bytes(bytes.fromhex(p['head_after']))
        hits.append(p)

def get_pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l: return int(l.strip().split()[-1])
    raise RuntimeError('no pid')

def main():
    pid=get_pid(); print(f'[*] PID={pid}')
    js=(JS_TPL.replace('__PRESEND_RVA__',str(PRESEND_RVA))
              .replace('__V_SER__',str(V_SER))
              .replace('__OUTER_VT__',str(OUTER_VT))
              .replace('__WIRE_NEW__',str(WIRE_NEW))
              .replace('__DRY_RUN__','true' if DRY_RUN else 'false'))
    sess=frida.get_local_device().attach(pid)
    sc=sess.create_script(js); sc.on('message',on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 你有 {CAPTURE_SEC}s ★★★')
    print(f'   在 FTA 里【多选】那条语音 → 【逐条转发】→ 小号 → 发送')
    print(f'   只做 1 次\n{"="*72}\n',flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. SER outer hits = {len(hits)}',flush=True)
    os._exit(0)

if __name__=='__main__': main()
