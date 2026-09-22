"""
forward_backtrace.py — 轻量版函数定位

策略:
  1. 找 WXWork.exe 基址和大小
  2. 扫描 "ForwardMessageToWeChatInternal" 字符串位置
  3. 读取每个字符串周围 256 字节，分析上下文
  4. 在字符串前后 4KB 内扫描 CALL 指令 (E8 ?? ?? ?? ??)
     并在每个 CALL 目标地址上设置 backtrace hook
  5. 等待用户执行转发，捕获到正确的调用后打印完整 backtrace

用法: python -u forward_backtrace.py
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if ":9882" in line and "LISTENING" in line:
                return int(line.strip().split()[-1])
    except Exception:
        pass
    # 备用: tasklist
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "WXWork.exe" in line:
                parts = line.strip('"').split('","')
                if len(parts) >= 2:
                    return int(parts[1])
    except Exception:
        pass
    raise RuntimeError("企微未运行，请先启动")

main_pid = get_main_pid()
print(f"[*] 主进程 PID = {main_pid}")

dev = frida.get_local_device()

JS = r"""
'use strict';
send({type:'start', pid:Process.id});

var wxmod = null;
Process.enumerateModules().forEach(function(m){
    if(m.name.toLowerCase()==='wxwork.exe') wxmod=m;
});
if(!wxmod){send({type:'error',msg:'no WXWork.exe'});}
send({type:'module', base:wxmod.base.toString(), size:wxmod.size});

// Step1: 找字符串
var TARGET_PAT = "46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 54 6f 57 65 43 68 61 74 49 6e 74 65 72 6e 61 6c";
var strMatches = Memory.scanSync(wxmod.base, wxmod.size, TARGET_PAT);
send({type:'str_count', count:strMatches.length,
      addrs: strMatches.slice(0,4).map(function(m){return m.address.toString();})});

// Step2: 读取第一个字符串附近内存，查看上下文
if(strMatches.length > 0){
    var sa = strMatches[0].address;
    // 读前256字节
    try{
        var before = sa.sub(256).readByteArray(256);
        send({type:'context_before', addr:sa.sub(256).toString(), data:Array.from(new Uint8Array(before))});
    }catch(e){}
    // 读字符串后256字节
    try{
        var after = sa.add(30).readByteArray(256);
        send({type:'context_after', addr:sa.add(30).toString(), data:Array.from(new Uint8Array(after))});
    }catch(e){}
}

// Step3: 在每个字符串地址附近 [-4096, +4096] 扫描 CALL 指令 (E8)
// E8 xx xx xx xx = CALL rel32
var callTargets = {};
strMatches.forEach(function(sm){
    var base = sm.address.sub(4096);
    // 逐字节扫描
    try{
        var buf = new Uint8Array(base.readByteArray(8192));
        for(var i=0;i<buf.length-4;i++){
            if(buf[i]===0xE8){
                // rel32 (little-endian, signed)
                var rel = buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24);
                // rel 作为有符号整数
                if(rel >= 0x80000000) rel = rel - 0x100000000;
                // call 指令地址 = base + i, 目标 = base + i + 5 + rel
                var callAddr = base.add(i).toUInt32();
                var target   = (callAddr + 5 + rel) >>> 0;
                var tStr = '0x' + target.toString(16);
                if(!callTargets[tStr]) callTargets[tStr] = {count:0, callSites:[]};
                callTargets[tStr].count++;
                callTargets[tStr].callSites.push('0x' + callAddr.toString(16));
            }
        }
    }catch(e){}
});

var targetKeys = Object.keys(callTargets);
send({type:'call_targets', count:targetKeys.length,
      sample: targetKeys.slice(0,20).map(function(k){
          return {addr:k, count:callTargets[k].count, sites:callTargets[k].callSites.slice(0,3)};
      })});

// Step4: 对每个 CALL 目标 hook，加 backtrace
var hooked = 0;
var wxBase = wxmod.base.toUInt32();
var wxEnd  = wxBase + wxmod.size;

targetKeys.forEach(function(tk){
    var target = parseInt(tk, 16);
    if(target < wxBase || target >= wxEnd) return;  // 只 hook WXWork.exe 内的目标
    try{
        var tp = ptr(target);
        // 验证目标是函数 prologue
        var bytes = new Uint8Array(tp.readByteArray(3));
        var isPrologue = (bytes[0]===0x55 && bytes[1]===0x8B && bytes[2]===0xEC) ||
                         (bytes[0]===0x55 && bytes[1]===0x89 && bytes[2]===0xE5) ||
                         (bytes[0]===0x56) || (bytes[0]===0x57) || // push esi / push edi
                         (bytes[0]===0x53);  // push ebx
        if(!isPrologue) return;
        (function(addr, sites){
            Interceptor.attach(addr, {
                onEnter: function(args){
                    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                             .map(function(a){ return a.toString(); });
                    var strs=[];
                    for(var k=0;k<6;k++){
                        try{
                            var s=args[k].readUtf16String(256);
                            if(s&&s.length>3) strs.push({idx:k,t:'u16',v:s});
                        }catch(e){}
                        try{
                            var s=args[k].readCString(256);
                            if(s&&s.length>3&&/[\x20-\x7e]{4}/.test(s)) strs.push({idx:k,t:'c',v:s});
                        }catch(e){}
                    }
                    send({type:'call_hit',
                          addr: addr.toString(),
                          call_sites: sites,
                          args:[args[0].toString(),args[1].toString(),
                                args[2].toString(),args[3].toString()],
                          strs:strs,
                          bt:bt.slice(0,8)});
                }
            });
        })(tp, callTargets[tk].callSites);
        hooked++;
    }catch(e){}
});

send({type:'setup_done', hooked:hooked});
"""

all_events = []
call_hits = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        if msg.get("type") == "error":
            print(f"  [JS ERR] {msg.get('description','')}")
        return
    p = msg["payload"]
    all_events.append(p)
    t = p.get("type","")
    if t == "start":
        print(f"  [JS] pid={p.get('pid')}")
    elif t == "module":
        print(f"  [module] base={p['base']} size={p['size']}")
    elif t == "str_count":
        print(f"  [strings] found={p['count']} addrs={p['addrs']}")
    elif t == "context_before":
        ba = bytes(p["data"])
        hex_lines = []
        for i in range(0, len(ba), 16):
            chunk = ba[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
            hex_lines.append(f"  {p['addr']}+{i:03x}: {hex_part:<48} |{asc_part}|")
        print(f"  [context_before] (last 256 bytes before string):")
        for l in hex_lines[-8:]: print(l)
    elif t == "context_after":
        ba = bytes(p["data"])
        hex_lines = []
        for i in range(0, len(ba), 16):
            chunk = ba[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
            hex_lines.append(f"  {p['addr']}+{i:03x}: {hex_part:<48} |{asc_part}|")
        print(f"  [context_after] (256 bytes after string):")
        for l in hex_lines[:8]: print(l)
    elif t == "call_targets":
        print(f"  [call_targets] near strings: {p['count']} unique targets")
        for s in p.get("sample",[])[:10]:
            print(f"    {s['addr']} x{s['count']} <- {s['sites'][:2]}")
    elif t == "setup_done":
        print(f"\n[READY] Hook {p['hooked']} 函数就绪!")
        print(">>> 请立刻在企微执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        (OUT_DIR / "forward_hook_ready.flag").write_text("ready")
    elif t == "call_hit":
        call_hits.append(p)
        n = len(call_hits)
        print(f"\n[HIT #{n}] addr={p['addr']} args={p['args']}")
        for s in p.get("strs",[]):
            print(f"  arg[{s['idx']}] {s['t']} = {repr(s['v'])[:80]}")
        print(f"  bt: {' | '.join(p.get('bt',['?'])[:4])}")
    elif t == "error":
        print(f"  [ERR] {p.get('msg','')}")

sess = dev.attach(main_pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] JS 加载完成，扫描中...")

DURATION = 120
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] Ctrl+C")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"forward_backtrace_{ts}.json"
out.write_text(json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[*] Saved {len(all_events)} events, {len(call_hits)} call hits -> {out}")
