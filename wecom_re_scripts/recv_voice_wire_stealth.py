# recv_voice_wire_stealth.py — 单 hook 点 · 安静模式 · 决定性一枪
#
# 目标：一次性抓到 PC 从服务器接收的完整 voice wire body，避免多次 attach/detach 触发反调试
#
# 策略：
#   - 只 hook 1 个点: libcrypto-1_1!EVP_DecryptUpdate（最可能是长连接/mmtls 解密出口）
#   - 无心跳（心跳会持续调用 Interceptor 内部状态检查）
#   - 关键字扩展：URL 家族 + 中文"语音"UTF-8 + silk 头 + 常见 protobuf voice 字段名
#   - 所有匹配到的 buffer 全部 dump（不限 40，改 200）
#   - 采样 60 秒，一次跑完不再反复 attach
#
# 环境：Frida 17，Python 3.11
# 前置：用户已重新登录 PC 企微且稳定运行 2 分钟以上，网络正常

import frida, subprocess, sys, os, json, time
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 60

print(f'[*] stealth recv recon — output ts={ts}')
print(f'[*] window={CAPTURE_SEC}s, single hook (EVP_DecryptUpdate only), no heartbeat')

JS = r"""
'use strict';

// ============ 扩展关键字表 ============
// UTF-8 中文
var CN_YU  = new Uint8Array([0xE8,0xAF,0xAD]);         // "语"
var CN_YIN = new Uint8Array([0xE9,0x9F,0xB3]);         // "音"
var CN_YUYIN = new Uint8Array([0xE8,0xAF,0xAD,0xE9,0x9F,0xB3]); // "语音"

// ASCII markers（voice 相关任意字段名 + URL 家族）
var ASCII_LIST = [
    'voice.qpic.cn','voice2.myqcloud.com','wework.qpic.cn','qpic.cn','myqcloud',
    'wxsnsdy','voiceid','voice_length','voicelength','voice_len','voicelen',
    'aeskey','aes_key','voice_aes','.silk','audio/silk','ww_voicemsg',
    'VoiceContent','VoiceMessage','voice_url','voice_size','voice_time',
    'voicemd5','MediaVoice','audiourl','audio_url','audio_id','mediaid',
    'MediaId','media_id','filekey','FileKey','.amr','audio/amr'
];
var ASCII_BYTES = ASCII_LIST.map(function(s){
    var a=new Uint8Array(s.length);
    for(var i=0;i<s.length;i++) a[i]=s.charCodeAt(i);
    return {name:s, bytes:a};
});

var SILK_A = new Uint8Array([0x02,0x24]);
var SILK_B = new Uint8Array([0x23,0x21,0x53,0x49,0x4c,0x4b]); // "#!SILK"

function scanFor(buf, needle) {
    var nl=needle.length, bl=buf.length, lim=bl-nl;
    outer: for (var i=0;i<=lim;i++){
        for (var j=0;j<nl;j++) if (buf[i+j]!==needle[j]) continue outer;
        return i;
    }
    return -1;
}

function scanAll(u8){
    var hits=[];
    // ASCII
    for (var k=0;k<ASCII_BYTES.length;k++){
        var o=scanFor(u8, ASCII_BYTES[k].bytes);
        if (o>=0) hits.push({name:ASCII_BYTES[k].name, off:o});
    }
    // Chinese
    var yy=scanFor(u8, CN_YUYIN);
    if (yy>=0) hits.push({name:'CN_语音', off:yy});
    else {
        var oy=scanFor(u8, CN_YU);
        if (oy>=0) hits.push({name:'CN_语', off:oy});
        var oi=scanFor(u8, CN_YIN);
        if (oi>=0) hits.push({name:'CN_音', off:oi});
    }
    // silk
    var sa=scanFor(u8, SILK_A);
    if (sa>=0) hits.push({name:'silk_02_24', off:sa});
    var sb=scanFor(u8, SILK_B);
    if (sb>=0) hits.push({name:'silk_hdr', off:sb});
    return hits;
}

function toHex(u8, n){
    var s='', lim=Math.min(n, u8.length);
    for(var i=0;i<lim;i++) s+=('0'+u8[i].toString(16)).slice(-2);
    return s;
}

// 找函数并 attach —— 只 hook 1 个点
var mod = Process.findModuleByName('libcrypto-1_1.dll');
if (!mod) { send({t:'fatal', msg:'libcrypto-1_1.dll not loaded'}); }
else {
    var addr = mod.findExportByName('EVP_DecryptUpdate');
    if (!addr) { send({t:'fatal', msg:'EVP_DecryptUpdate not exported'}); }
    else {
        var HIT_MAX = 200;
        var hitCount = 0;
        var eventCount = 0;
        Interceptor.attach(addr, {
            onEnter: function(a){
                this._out = a[1];
                this._outl = a[2];
                this._inl  = a[4].toInt32();
            },
            onLeave: function(rv){
                if (rv.toInt32() !== 1) return;
                eventCount++;
                if (hitCount >= HIT_MAX) return;
                try {
                    var written = 0;
                    try { written = this._outl.readInt(); } catch(e){ written = this._inl; }
                    if (written <= 8 || written > 200000) return;
                    var take = Math.min(written, 65536);
                    var raw = this._out.readByteArray(take);
                    if (!raw) return;
                    var u8 = new Uint8Array(raw);
                    var hits = scanAll(u8);
                    if (hits.length === 0) return;
                    hitCount++;
                    send({
                        t: 'hit',
                        seq: hitCount,
                        n: written,
                        hits: hits,
                        head: toHex(u8, Math.min(written, 384))
                    }, raw);
                } catch(e) {
                    // 静默：绝不 send err，避免噪音
                }
            }
        });
        send({t:'armed', addr: addr.toString()});
        // 定时报告（30s 一次，仅 2 次）
        setTimeout(function(){ send({t:'tick', events: eventCount, hits: hitCount}); }, 30000);
        setTimeout(function(){ send({t:'tick', events: eventCount, hits: hitCount}); }, 55000);
    }
}
"""

hit_count = 0

def on_msg(m, data):
    global hit_count
    if m.get('type') == 'error':
        print(f'[JS-ERR] {m.get("description","")[:400]}', flush=True)
        return
    if m.get('type') != 'send':
        return
    p = m['payload']; t = p.get('t')
    if t == 'fatal':
        print(f'[FATAL] {p["msg"]}', flush=True)
        return
    if t == 'armed':
        print(f'[+] armed @ {p["addr"]}', flush=True)
        return
    if t == 'tick':
        print(f'  ▶ tick  events={p["events"]}  hits={p["hits"]}', flush=True)
        return
    if t == 'hit':
        hit_count += 1
        seq = p['seq']; n = p['n']; hits = p['hits']
        bin_path  = OUT_DIR / f'recv_stealth_{ts}_seq{seq:03d}.bin'
        meta_path = OUT_DIR / f'recv_stealth_{ts}_seq{seq:03d}.json'
        if data: bin_path.write_bytes(data)
        meta_path.write_text(json.dumps({
            'seq':seq, 'n':n, 'hits':hits, 'head_hex':p['head'],
        }, ensure_ascii=False, indent=2), encoding='utf-8')
        names = ', '.join(h['name'] for h in hits[:8])
        print(f'  ★ HIT #{seq}  n={n}  [{names}]  → {bin_path.name}', flush=True)


def get_pid():
    out = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('WXWork.exe (port 9882) not found')


def main():
    pid = get_pid()
    print(f'[*] target PID = {pid}')
    dev = frida.get_local_device()
    sess = dev.attach(pid)
    sc = sess.create_script(JS)
    sc.on('message', on_msg)
    sc.load()
    print(f'\n{"="*72}')
    print(f'★★★ 60s 采样窗口 ★★★')
    print(f'   在窗口内：手机企微 → FTA → 按住说话 → 说 10 秒左右 → 松手发送')
    print(f'   PC 保持 FTA 会话前台可见')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. 总 HIT = {hit_count}', flush=True)
    os._exit(0)


if __name__ == '__main__':
    main()
