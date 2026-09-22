# hook_wire_patch2.py — 带诊断的 wire patch
# 变化：
#   - 打印所有 PreSend 触发（不管有没有 outer SER）
#   - 打印窗口内 SER 的所有 vt 分布（帮助发现 wrapper vt 变化）
#   - 仍然只 patch OUTER_VT 的 wire[+1]

import frida, subprocess, sys, os
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR=Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts=datetime.now().strftime('%Y%m%d_%H%M%S')
CAP=150

V_SER=0x09f042a0
PRESEND_RVA=0x919ffb2
OUTER_VT=0xb0610c0
WIRE_NEW=int(os.environ.get('WIRE_MSGTYPE','34'))
DRY=os.environ.get('DRY_RUN','0')=='1'
print(f'[*] wire[+1] → {WIRE_NEW}  DRY={DRY}  (with vt diagnostics)')

JS=r"""
'use strict';
var mod=Process.getModuleByName('WXWork.exe');
var PRESEND=mod.base.add(__P__);
var V_SER=ptr(__S__);
var OUTER_VT=__OVT__, WIRE_NEW=__W__, DRY=__D__;
function sb(a,sz){try{var p=(typeof a==='number')?ptr(a):a;var v=p.toUInt32();if(v<0x10000||v>0x7F000000)return null;return p.readByteArray(sz);}catch(e){return null;}}
function toHex(ab){var a=new Uint8Array(ab),s='';for(var i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}
var W={tid:{},cnt:0};
Interceptor.attach(PRESEND,{
    onEnter:function(){W.tid[this.threadId]=1;W.cnt++;send({t:'pe',n:W.cnt});},
    onLeave:function(rv){delete W.tid[this.threadId];send({t:'pl',n:W.cnt,rv:'0x'+rv.toUInt32().toString(16)});}
});
var SN=0;
Interceptor.attach(V_SER,{
    onEnter:function(args){
        if(!W.tid[this.threadId])return;
        SN++;
        var tv=this.context.ecx.toUInt32();
        var raw=sb(tv,32); if(!raw){send({t:'s_short',sn:SN});return;}
        var a=new Uint8Array(raw);
        var vt=(a[0]|(a[1]<<8)|(a[2]<<16)|(a[3]<<24))>>>0;
        send({t:'s_vt',sn:SN,vt:'0x'+vt.toString(16),this_addr:'0x'+tv.toString(16)});
        if(vt!==OUTER_VT)return;
        this._arg0=args[0].toUInt32(); this._sn=SN; this._outer=true;
    },
    onLeave:function(rv){
        if(!this._outer)return;
        var a0=this._arg0;
        var head=sb(a0,64);
        if(!head){send({t:'sl_err',sn:this._sn});return;}
        var h=new Uint8Array(head);
        var off=-1,orig=-1;
        for(var i=0;i<Math.min(32,h.length-1);i++){
            if(h[i]===0x08 && h[i+1]<0x80){off=i+1;orig=h[i+1];break;}
        }
        var patched=false;
        if(off>=0 && !DRY){try{Memory.protect(ptr(a0+off),1,'rwx');ptr(a0+off).writeU8(WIRE_NEW);patched=true;}catch(e){}}
        var h2=sb(a0,64);
        send({t:'sl',sn:this._sn,off:off,orig:orig,newv:WIRE_NEW,patched:patched,
              hb:toHex(head),ha:h2?toHex(h2):null});
    }
});
send({t:'ok'});
"""

vt_stats={}
def on_msg(m,d):
    if m.get('type')=='error':print(f'[ERR] {m.get("description","")[:400]}',flush=True);return
    if m.get('type')!='send':return
    p=m['payload']; t=p.get('t')
    if t=='ok':print('[+] ARMED',flush=True);return
    if t=='pe':print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER',flush=True);return
    if t=='pl':
        print(f'[PRESEND #{p["n"]}] LEAVE  retval={p["rv"]}',flush=True)
        if vt_stats:
            print(f'  窗口内 SER vt 分布:')
            for vt,n in sorted(vt_stats.items(),key=lambda kv:-kv[1]):
                mark='  ★OUTER' if int(vt,16)==OUTER_VT else ''
                print(f'    {vt}  x{n}{mark}')
            vt_stats.clear()
        print('='*72,flush=True); return
    if t=='s_vt':
        vt_stats[p['vt']]=vt_stats.get(p['vt'],0)+1
        return
    if t=='sl':
        mark='★PATCHED' if p['patched'] else ('DRY' if DRY else ('★FAIL' if p['off']>=0 else '未找 field1'))
        print(f'  ▶ SER#{p["sn"]} leave  wire[+{p["off"]}] {p["orig"]}→{p["newv"]}  {mark}',flush=True)
        print(f'    hb: {p["hb"][:96]}',flush=True)
        print(f'    ha: {p["ha"][:96]}',flush=True)
        (OUT_DIR/f'wp2_{ts}_sn{p["sn"]}_b.bin').write_bytes(bytes.fromhex(p['hb']))
        (OUT_DIR/f'wp2_{ts}_sn{p["sn"]}_a.bin').write_bytes(bytes.fromhex(p['ha']))
        return
    if t=='sl_err':print(f'  ▶ SER#{p["sn"]} leave err',flush=True);return

def pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l: return int(l.strip().split()[-1])
    raise RuntimeError('no pid')

def main():
    P=pid(); print(f'[*] PID={P}')
    js=(JS.replace('__P__',str(PRESEND_RVA)).replace('__S__',str(V_SER))
          .replace('__OVT__',str(OUTER_VT)).replace('__W__',str(WIRE_NEW))
          .replace('__D__','true' if DRY else 'false'))
    s=frida.get_local_device().attach(P); sc=s.create_script(js); sc.on('message',on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ {CAP}s 窗口 ★★★')
    print(f'   建议: 【多选】那条语音 →【逐条转发】→ 小号 → 发送')
    print(f'   若怀疑去重: 试试换一条语音 或 先转给自己再转小号')
    print(f'{"="*72}\n',flush=True)
    time.sleep(CAP)
    try:sc.unload();s.detach()
    except:pass
    print(f'\n[+] done.',flush=True); os._exit(0)

if __name__=='__main__': main()
