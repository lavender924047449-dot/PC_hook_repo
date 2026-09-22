# exp_g3_body_slot.py — G3 下一步：抓住「谁把 [语音] 写进 std::string」+ body proto 槽位
#
# v2 已证明（g3exp_20260914_164957）：
#   PreSend 内 memcpy 拷的是已经编码好的 proto：
#     0a 08 [语音]           ← WriteString field1 的 payload（10B）
#     0a 0e 08 00 12 0a 0a 08 [语音]  ← 完整 body wrapper（16B，与 §47.15 一致）
#   调用链：
#     0x15a0de2  Serialize(body 两字段 proto)
#       → 0x9937f10  WriteString(field=2)
#         → 0x9933d40  WriteRaw → vcruntime memcpy
#   args[1] 无 [语音] 是因为字符串在 nested proto / std::string，不在 MessageObject 头 2KB。
#
# 本脚本：
#   1. hook 0x15a0de2（body Serialize）onEnter：dump this、读 MSVC std::string、确认槽位
#   2. hook 0x1e917e（std::string 堆拷贝/assign，SSO>15 才 memcpy）
#      以及 0x15a0de2 之前更有价值的：在 PreSend 窗口外也 hook WriteString 0x9937f10
#      当 string size==8 且内容是 [语音] 时打 backtrace → 降级赋值的上层
#   3. WriteString 0x9937f10：每次写入 [语音] 都打印 caller（不限 PreSend，降级可能更早）
#
# 用法：
#   python exp_g3_body_slot.py
#   150s：右键已同步语音 → 转发 → 发送 1 次

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 150

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND   = mod.base.add(0x919ffb2);
var BODY_SER  = mod.base.add(0x15a0de2);  // Serialize 2-field body proto
var INNER_SER = mod.base.add(0x1687402);  // Serialize: field1=string [语音]
var WRITE_STR = mod.base.add(0x9937f10);  // protobuf WriteString
var STR_ASSIGN= mod.base.add(0x1e917e);   // std::string assign (heap path)

var U8 = [0x5b,0xe8,0xaf,0xad,0xe9,0x9f,0xb3,0x5d];

function safeBytes(a, sz) {
    try {
        var p = (typeof a==='number')?ptr(a):a;
        var v = p.toUInt32();
        if (v<0x10000 || v>0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a=new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2);
    return s;
}
function findU8(ab) {
    if (!ab) return -1;
    var a=new Uint8Array(ab);
    outer: for (var i=0;i<=a.length-8;i++) {
        for (var j=0;j<8;j++) if (a[i+j]!==U8[j]) continue outer;
        return i;
    }
    return -1;
}
function describe(p) {
    try {
        var v=p.toUInt32(), b=mod.base.toUInt32();
        if (v>=b && v<b+mod.size) return 'wx+0x'+(v-b).toString(16);
        return '0x'+v.toString(16);
    } catch(e) { return '?'; }
}
function readStdStr(p) {
    try {
        var cap=p.add(0x14).readU32();
        var sz=p.add(0x10).readU32();
        if (sz>0x10000) return {err:'sz='+sz};
        var data = (cap>15) ? p.readPointer() : p;
        var raw=data.readByteArray(Math.min(sz, 256));
        return {sz:sz, cap:cap, ptr:'0x'+data.toUInt32().toString(16),
                hex: raw?toHex(raw):null, u8: raw?findU8(raw):-1};
    } catch(e) { return {err:e.message}; }
}
function bt6() {
    var out=[];
    try {
        var fr=Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,8);
        for (var i=0;i<fr.length;i++) out.push(describe(fr[i]));
    } catch(e) {}
    return out;
}

var WIN={tid:{}, n:0};

Interceptor.attach(PRESEND, {
    onEnter: function(){ WIN.tid[this.threadId]=1; WIN.n++; send({t:'pe', n:WIN.n}); },
    onLeave: function(){ delete WIN.tid[this.threadId]; send({t:'pl', n:WIN.n}); }
});

Interceptor.attach(BODY_SER, {
    onEnter: function(args) {
        var self=this.context.ecx;
        var raw=safeBytes(self, 128);
        var s10=readStdStr(self.add(0x10));
        var sPtr=null;
        try {
            var q=self.add(0x10).readPointer();
            sPtr=readStdStr(q);
        } catch(e) {}
        var has = (s10 && s10.u8>=0) || (sPtr && sPtr.u8>=0) || (raw && findU8(raw)>=0);
        if (!has && !WIN.tid[this.threadId]) return;
        send({t:'body_ser', in_presend:!!WIN.tid[this.threadId],
              this:'0x'+self.toUInt32().toString(16),
              has_bits: raw?toHex(raw).slice(16,24):null,
              this_hex: raw?toHex(raw):null,
              str_at_10: s10, str_via_ptr: sPtr,
              bt: bt6.call(this)});
    }
});

Interceptor.attach(INNER_SER, {
    onEnter: function(args) {
        var self=this.context.ecx;
        var raw=safeBytes(self, 64);
        var sPtr=null, sInline=null;
        try { sPtr=readStdStr(self.add(0x10).readPointer()); } catch(e) {}
        try { sInline=readStdStr(self.add(0x10)); } catch(e) {}
        var hit = (sPtr && sPtr.u8>=0) || (sInline && sInline.u8>=0);
        if (!hit) return;
        var f2=0,f3=0,f4=0,hb=0;
        try { hb=self.add(8).readU32(); } catch(e){}
        try { f2=self.add(0x14).readU32(); f3=self.add(0x18).readU32(); f4=self.add(0x1c).readU32(); } catch(e){}
        var vt=null;
        try { vt='0x'+self.readU32().toString(16); } catch(e){}
        send({t:'inner_ser', in_presend:!!WIN.tid[this.threadId],
              this:'0x'+self.toUInt32().toString(16), vt:vt, has_bits:hb,
              f2:f2, f3:f3, f4:f4,
              str_ptr:sPtr, str_inline:sInline,
              this_hex: raw?toHex(raw):null,
              bt: bt6.call(this)});
    }
});

Interceptor.attach(WRITE_STR, {
    onEnter: function(args) {
        // cdecl: field=[esp+4] after hook? thiscall+cdecl mix: ebp+8=field, ebp+c=string*, ebp+10=stream
        // Frida args: args[0]=field (first stack), args[1]=string*, args[2]=stream  for cdecl
        // 0x9937f10 uses [ebp+8]=field, [ebp+c]=std::string*, [ebp+10]=CodedOutputStream* (ecx also stream)
        var field=0, sp=null;
        try { field=args[0].toUInt32(); } catch(e){}
        try { sp=args[1]; } catch(e){}
        var st=sp?readStdStr(sp):null;
        if (!st || st.u8<0) return;
        send({t:'write_str', field:field, in_presend:!!WIN.tid[this.threadId],
              str:st, bt: bt6.call(this)});
    }
});

Interceptor.attach(STR_ASSIGN, {
    onEnter: function(args) {
        // thiscall: ecx=this, [ebp+8]=new_size, [ebp+10]=src  (from disasm)
        var n=0, src=null;
        try { n=args[0].toUInt32(); } catch(e){ return; }
        if (n<8 || n>64) return;
        try { src=args[2]; } catch(e){ try{ src=args[1]; }catch(e2){ return; } }
        var raw=safeBytes(src, n);
        if (!raw || findU8(raw)<0) {
            raw=safeBytes(args[1], n);
            if (!raw || findU8(raw)<0) return;
            src=args[1];
        }
        send({t:'str_assign', n:n, in_presend:!!WIN.tid[this.threadId],
              src:describe(src), hex:toHex(raw), bt: bt6.call(this)});
    }
});

send({t:'ready'});
rpc.exports.stats=function(){ return {presend:WIN.n}; };
"""

events=[]
bt_count=Counter()

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p=msg['payload']; t=p.get('t')
    if t=='ready':
        print('[+] hooks: PreSend + InnerSer 0x1687402 + BodySer 0x15a0de2 + WriteString + str_assign', flush=True)
        return
    if t=='pe':
        print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER', flush=True); return
    if t=='pl':
        print(f'[PRESEND #{p["n"]}] LEAVE\n{"="*72}', flush=True); return
    if t=='inner_ser':
        events.append(p)
        gate='PRE' if p['in_presend'] else 'pre-PreSend★'
        print(f'  ◆ InnerSer [{gate}] this={p["this"]} vt={p.get("vt")} has_bits={p.get("has_bits")} '
              f'f2={p.get("f2")} f3={p.get("f3")} f4={p.get("f4")}', flush=True)
        print(f'     str_ptr={p.get("str_ptr")}  str_inline={p.get("str_inline")}', flush=True)
        for i,f in enumerate((p.get('bt') or [])[:6]):
            print(f'     bt[{i}] {f}', flush=True)
            bt_count[f]+=1
        return
    if t=='write_str':
        events.append(p)
        gate='PRE' if p['in_presend'] else 'pre-PreSend★'
        print(f'  ★ WriteString field={p["field"]} [{gate}] sz={p["str"].get("sz")} hex={p["str"].get("hex")}', flush=True)
        for i,f in enumerate((p.get('bt') or [])[:6]):
            print(f'     bt[{i}] {f}', flush=True)
            bt_count[f]+=1
        return
    if t=='body_ser':
        events.append(p)
        gate='PRE' if p['in_presend'] else 'out'
        s=p.get('str_at_10') or {}
        s2=p.get('str_via_ptr') or {}
        print(f'  ▶ BodySer [{gate}] this={p["this"]}  str10={s}  ptr={s2}', flush=True)
        if p.get('this_hex'):
            fn=OUT/f'g3slot_{ts}_{p["this"]}_this.bin'
            try: fn.write_bytes(bytes.fromhex(p['this_hex']))
            except Exception: pass
        for i,f in enumerate((p.get('bt') or [])[:5]):
            print(f'     bt[{i}] {f}', flush=True)
        return
    if t=='str_assign':
        events.append(p)
        gate='PRE' if p['in_presend'] else 'pre-PreSend★'
        print(f'  ★ str_assign [{gate}] n={p["n"]} src={p["src"]} hex={p["hex"]}', flush=True)
        for i,f in enumerate((p.get('bt') or [])[:6]):
            print(f'     bt[{i}] {f}', flush=True)
            bt_count[f]+=1
        return

def get_pid():
    o=subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

def main():
    pid=get_pid(); print(f'[*] PID={pid}')
    sess=frida.get_local_device().attach(pid)
    sc=sess.create_script(JS); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ {CAPTURE_SEC}s：右键语音 → 转发 → 发送 1 次 ★★★')
    print(f'  重点看带 pre-PreSend★ 的 WriteString / str_assign backtrace\n{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工  events={len(events)}')
    if bt_count:
        print('★ backtrace 帧频次:')
        for k,c in bt_count.most_common(15):
            print(f'    {c:3d}  {k}')
    (OUT/f'g3slot_{ts}_report.json').write_text(
        json.dumps({'events':events, 'bt':dict(bt_count)}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'    产物 g3slot_{ts}_report.json')
    os._exit(0)

if __name__=='__main__':
    main()
