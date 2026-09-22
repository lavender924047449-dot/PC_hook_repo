# hook_wire_sample.py — 采样：观察所有 wire 前 32B，不改任何字节
# 用途：跟不同类型消息一一对照，找 wire field1 (可能是 msgtype) 的编号规律

import frida, subprocess, sys, os
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR=Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts=datetime.now().strftime('%Y%m%d_%H%M%S')
CAP=int(os.environ.get('CAP','90'))
LABEL=os.environ.get('LABEL','sample')

V_SER=0x09f042a0
PRESEND_RVA=0x919ffb2
print(f'[*] sample mode (no patch)  LABEL={LABEL}  window={CAP}s')

JS=r"""
'use strict';
var mod=Process.getModuleByName('WXWork.exe');
var PRESEND=mod.base.add(__P__);
var V_SER=ptr(__S__);
function sb(a,sz){try{var p=(typeof a==='number')?ptr(a):a;var v=p.toUInt32();if(v<0x10000||v>0x7F000000)return null;return p.readByteArray(sz);}catch(e){return null;}}
function toHex(ab){var a=new Uint8Array(ab),s='';for(var i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}
var W={tid:{},cnt:0};
Interceptor.attach(PRESEND,{
    onEnter:function(){W.tid[this.threadId]=1;W.cnt++;send({t:'pe',n:W.cnt});},
    onLeave:function(rv){delete W.tid[this.threadId];send({t:'pl',n:W.cnt});}
});
var SN=0;
Interceptor.attach(V_SER,{
    onEnter:function(args){
        if(!W.tid[this.threadId])return;
        SN++;
        var tv=this.context.ecx.toUInt32();
        var raw=sb(tv,32); if(!raw){return;}
        var a=new Uint8Array(raw);
        var vt=(a[0]|(a[1]<<8)|(a[2]<<16)|(a[3]<<24))>>>0;
        this._sn=SN; this._vt=vt; this._arg0=args[0].toUInt32();
    },
    onLeave:function(rv){
        if(!this._sn)return;
        var head=sb(this._arg0,1024);
        send({t:'ser',sn:this._sn,vt:'0x'+this._vt.toString(16),
              arg0:'0x'+this._arg0.toString(16),
              head: head?toHex(head):null});
    }
});
send({t:'ok'});
"""

log=[]
def on_msg(m,d):
    if m.get('type')=='error':print(f'[ERR] {m.get("description","")[:400]}',flush=True);return
    if m.get('type')!='send':return
    p=m['payload']; t=p.get('t')
    if t=='ok':print('[+] ARMED',flush=True);return
    if t=='pe':print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER',flush=True);return
    if t=='pl':print(f'[PRESEND #{p["n"]}] LEAVE\n{"="*72}',flush=True);return
    if t=='ser':
        head=p['head'] or ''
        # 解析 wire 前 16B
        try:
            hb=bytes.fromhex(head)
            desc=[]
            if hb and hb[0]==0x08:
                desc.append(f'field1(varint)={hb[1]}')
            elif hb:
                desc.append(f'first={hb[0]:#x}')
            note=' | '.join(desc)
        except:
            note=''
        print(f'  ▶ SER#{p["sn"]}  vt={p["vt"]}  arg0={p["arg0"]}',flush=True)
        print(f'    head: {head[:96]}   {note}',flush=True)
        log.append(p)

def pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l: return int(l.strip().split()[-1])
    raise RuntimeError('no pid')

def main():
    P=pid(); print(f'[*] PID={P}')
    js=JS.replace('__P__',str(PRESEND_RVA)).replace('__S__',str(V_SER))
    s=frida.get_local_device().attach(P); sc=s.create_script(js); sc.on('message',on_msg); sc.load()
    import time,json
    print(f'\n{"="*72}\n★★★ {CAP}s 采样窗口 ★★★  LABEL={LABEL}')
    print(f'{"="*72}\n',flush=True)
    time.sleep(CAP)
    try:sc.unload();s.detach()
    except:pass
    # 落盘
    (OUT_DIR/f'wire_sample_{ts}_{LABEL}.json').write_text(json.dumps(log,indent=2),encoding='utf-8')
    print(f'\n[+] done. saved {len(log)} SER records to wire_sample_{ts}_{LABEL}.json',flush=True)
    os._exit(0)
if __name__=='__main__':main()
