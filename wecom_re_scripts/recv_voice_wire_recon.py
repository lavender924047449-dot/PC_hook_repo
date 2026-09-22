# recv_voice_wire_recon.py — 广谱接收侧 voice wire 采样
#
# 目标：抓 PC 从服务器接收的完整 voice wire body
#   （含 CDN URL / aes_key / duration / silk 引用等），供 Stage 2 patch 重放
#
# 策略：
#   1. hook libssl-1_1!SSL_read (onLeave)      —— CGI 长轮询解密后的应用层字节
#   2. hook libcrypto-1_1!EVP_DecryptUpdate    —— mmtls-like frame 解密后
#   3. hook ws2_32!WSARecv / recv (onLeave)    —— 兜底
#   4. onLeave 扫 buffer 里 voice 特征关键字，命中即 dump
#
# 用户操作：脚本 ARMED 后，手机往 FTA 发一条 10 秒左右的语音消息，PC 保持前台
#
# 环境：Frida 17，Python 3.11

import frida, subprocess, sys, os, json, time
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

print(f'[*] recv voice wire recon — output ts={ts}')
print(f'[*] capture window = {CAPTURE_SEC}s')

JS = r"""
'use strict';

// ============ voice 特征关键字（多重命中提升可信度） ============
// 每个 marker 都是 UTF-8 字节；扫描到任何一个即视为潜在命中
var MARKERS = [
    'voice.qpic.cn',
    'voice2.myqcloud.com',
    'wework.qpic.cn/wwpicvoice',
    'wework.qpic.cn/wwpic3voice',
    'wxsnsdy',
    'voiceid',
    'voice_length',
    'voicelength',
    'aeskey',
    'voice_aes',
    '.silk',
    'audio/silk',
    'ww_voicemsg',
    'VoiceContent',
    'VoiceMessage',
    'voice_url',
    'voice_size',
];

// ---- 编译为 Uint8Array 便于快速比对 ----
var MARK_BYTES = MARKERS.map(function(s){
    var a=new Uint8Array(s.length);
    for(var i=0;i<s.length;i++) a[i]=s.charCodeAt(i);
    return {name:s, bytes:a};
});

// ---- Tencent SILK v3 头: 02 24 (Tencent variant) 或 "#!SILK_V3" ----
var SILK_TAG_A = new Uint8Array([0x02, 0x24]);  // Tencent silk 常见前缀
var SILK_TAG_B = new Uint8Array([0x23, 0x21, 0x53, 0x49, 0x4c, 0x4b, 0x5f, 0x56, 0x33]); // "#!SILK_V3"

function scanFor(buf, needle) {
    var nl = needle.length;
    var bl = buf.length;
    var lim = bl - nl;
    outer: for (var i = 0; i <= lim; i++) {
        for (var j = 0; j < nl; j++) {
            if (buf[i+j] !== needle[j]) continue outer;
        }
        return i;
    }
    return -1;
}

function scanBuf(u8) {
    var hits = [];
    for (var k = 0; k < MARK_BYTES.length; k++) {
        var off = scanFor(u8, MARK_BYTES[k].bytes);
        if (off >= 0) hits.push({name: MARK_BYTES[k].name, off: off});
    }
    var so = scanFor(u8, SILK_TAG_A);
    if (so >= 0) hits.push({name:'silk_tag_02_24', off: so});
    var sb = scanFor(u8, SILK_TAG_B);
    if (sb >= 0) hits.push({name:'silk_hdr_#!SILK_V3', off: sb});
    return hits;
}

// 快速裸扫是否含任意 URL 模式（http:// / https:// / .com / .cn）
var URL_HTTP  = new Uint8Array([0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f]); // "http://"
var URL_HTTPS = new Uint8Array([0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f]); // "https://"
var URL_QQCOM = new Uint8Array([0x71,0x71,0x2e,0x63,0x6f,0x6d]); // "qq.com"
var URL_TCENT = new Uint8Array([0x74,0x65,0x6e,0x63,0x65,0x6e,0x74]); // "tencent"
var URL_QPIC  = new Uint8Array([0x71,0x70,0x69,0x63]); // "qpic"
var URL_MYQCLOUD = new Uint8Array([0x6d,0x79,0x71,0x63,0x6c,0x6f,0x75,0x64]); // "myqcloud"
var URL_WW    = new Uint8Array([0x77,0x65,0x77,0x6f,0x72,0x6b]); // "wework"

function hasAnyUrlish(u8) {
    if (scanFor(u8, URL_HTTPS) >= 0) return 'https';
    if (scanFor(u8, URL_HTTP)  >= 0) return 'http';
    if (scanFor(u8, URL_QPIC)  >= 0) return 'qpic';
    if (scanFor(u8, URL_MYQCLOUD) >= 0) return 'myqcloud';
    if (scanFor(u8, URL_WW)    >= 0) return 'wework';
    if (scanFor(u8, URL_TCENT) >= 0) return 'tencent';
    if (scanFor(u8, URL_QQCOM) >= 0) return 'qq.com';
    return null;
}

// 判断是否要 wide-dump 这份 buffer
function shouldWideDump(src, u8) {
    if (STATS.wide >= WIDE_LIMIT) return false;
    if (u8.length < WIDE_MIN) return false;
    // 去重：src + size + 前 16 字节 hex
    var key = src + '_' + u8.length + '_' + toHexN(u8, 16);
    if (WIDE_SEEN[key]) return false;
    WIDE_SEEN[key] = 1;
    // 只留有 URL-ish 的（大幅收敛，防止 KB 级洪水）
    var kind = hasAnyUrlish(u8);
    if (!kind) return false;
    return kind;
}

function toHexN(u8, n) {
    var s='', lim=Math.min(n, u8.length);
    for(var i=0;i<lim;i++){ s+=('0'+u8[i].toString(16)).slice(-2); }
    return s;
}

function backtrace(ctx) {
    try {
        return Thread.backtrace(ctx, Backtracer.ACCURATE)
            .slice(0, 12)
            .map(function(a){ return a.toString(); });
    } catch(e) { return []; }
}

// ============ 事件计数与限流 ============
var STATS = { hookCount:0, ssl_leave:0, evp_leave:0, ws_leave:0, hits:0, wide:0 };
var HIT_LIMIT = 40;
var WIDE_LIMIT = 80;     // 无差别大 buffer dump 上限
var WIDE_MIN   = 512;    // buffer >= 这么大才 wide-dump
var WIDE_MAX_BYTES = 32768;

// 记录 wide-dump 已经采过的 (src, size, head8) 三元组，去重防止洪水
var WIDE_SEEN = {};

function tryHook(modName, fnName, hookFactory) {
    try {
        var m = Process.findModuleByName(modName);
        if (!m) { send({t:'no_mod', mod:modName}); return false; }
        var e = m.findExportByName(fnName);
        if (!e) { send({t:'no_exp', mod:modName, fn:fnName}); return false; }
        Interceptor.attach(e, hookFactory(modName, fnName));
        STATS.hookCount++;
        send({t:'hooked', mod:modName, fn:fnName, addr:e.toString()});
        return true;
    } catch(err) {
        send({t:'hook_err', mod:modName, fn:fnName, err:String(err)});
        return false;
    }
}

// ============ SSL_read hook ============
// int SSL_read(SSL *ssl, void *buf, int num) — 返回值 = 读到的字节数
tryHook('libssl-1_1.dll', 'SSL_read', function(mod, fn){
    return {
        onEnter: function(args) {
            this._buf = args[1];
            this._max = args[2].toInt32();
        },
        onLeave: function(rv) {
            var n = rv.toInt32();
            if (n <= 0) return;
            STATS.ssl_leave++;
            try {
                var raw = this._buf.readByteArray(Math.min(n, 65536));
                if (!raw) return;
                var u8 = new Uint8Array(raw);
                var hits = scanBuf(u8);
                if (hits.length > 0 && STATS.hits < HIT_LIMIT) {
                    STATS.hits++;
                    send({t:'hit', src:'SSL_read', seq:STATS.hits, n:n,
                        hits:hits, head:toHexN(u8, Math.min(n,256)),
                        bt:backtrace(this.context)}, raw);
                    return;
                }
                var kind = shouldWideDump('SSL_read', u8);
                if (kind) {
                    STATS.wide++;
                    send({t:'wide', src:'SSL_read', seq:STATS.wide, n:n,
                        kind:kind, head:toHexN(u8, Math.min(n,256)),
                        bt:backtrace(this.context)}, raw);
                }
            } catch(e) {
                send({t:'ssl_err', err:String(e)});
            }
        }
    };
});

// ============ EVP_DecryptUpdate hook ============
// int EVP_DecryptUpdate(ctx, out, outl, in, inl) — out 是解密结果
tryHook('libcrypto-1_1.dll', 'EVP_DecryptUpdate', function(mod, fn){
    return {
        onEnter: function(args) {
            this._out  = args[1];
            this._outl = args[2];  // int*
            this._inl  = args[4].toInt32();
        },
        onLeave: function(rv) {
            if (rv.toInt32() !== 1) return;
            STATS.evp_leave++;
            try {
                // 读 out 长度
                var written = 0;
                try { written = this._outl.readInt(); } catch(e) { written = this._inl; }
                if (written <= 0 || written > 200000) return;
                var raw = this._out.readByteArray(Math.min(written, 65536));
                if (!raw) return;
                var u8 = new Uint8Array(raw);
                var hits = scanBuf(u8);
                if (hits.length > 0 && STATS.hits < HIT_LIMIT) {
                    STATS.hits++;
                    send({t:'hit', src:'EVP_DecryptUpdate', seq:STATS.hits, n:written,
                        hits:hits, head:toHexN(u8, Math.min(written,256)),
                        bt:backtrace(this.context)}, raw);
                    return;
                }
                var kind = shouldWideDump('EVP_DecryptUpdate', u8);
                if (kind) {
                    STATS.wide++;
                    send({t:'wide', src:'EVP_DecryptUpdate', seq:STATS.wide, n:written,
                        kind:kind, head:toHexN(u8, Math.min(written,256)),
                        bt:backtrace(this.context)}, raw);
                }
            } catch(e) {
                send({t:'evp_err', err:String(e)});
            }
        }
    };
});

// ============ WSARecv hook (兜底) ============
// int WSARecv(SOCKET, LPWSABUF, DWORD, LPDWORD, ...) —— buf 结构体数组
tryHook('ws2_32.dll', 'WSARecv', function(mod, fn){
    return {
        onEnter: function(args) {
            this._pBuf   = args[1];
            this._nBuf   = args[2].toInt32();
            this._pBytes = args[3];  // LPDWORD received bytes
        },
        onLeave: function(rv) {
            STATS.ws_leave++;
            try {
                var got = 0;
                try { got = this._pBytes.readU32(); } catch(e) {}
                if (got <= 0) return;
                // 只看第一个 WSABUF
                var buf0_len = this._pBuf.readU32();       // WSABUF.len
                var buf0_ptr = this._pBuf.add(4).readPointer();  // WSABUF.buf
                var take = Math.min(got, buf0_len, 65536);
                if (take <= 0) return;
                var raw = buf0_ptr.readByteArray(take);
                if (!raw) return;
                var u8 = new Uint8Array(raw);
                var hits = scanBuf(u8);
                if (hits.length > 0 && STATS.hits < HIT_LIMIT) {
                    STATS.hits++;
                    send({t:'hit', src:'WSARecv', seq:STATS.hits, n:take,
                        hits:hits, head:toHexN(u8, Math.min(take,256)),
                        bt:backtrace(this.context)}, raw);
                    return;
                }
                var kind = shouldWideDump('WSARecv', u8);
                if (kind) {
                    STATS.wide++;
                    send({t:'wide', src:'WSARecv', seq:STATS.wide, n:take,
                        kind:kind, head:toHexN(u8, Math.min(take,256)),
                        bt:backtrace(this.context)}, raw);
                }
            } catch(e) {
                send({t:'ws_err', err:String(e)});
            }
        }
    };
});

// ============ 心跳 ============
setInterval(function(){
    send({t:'heartbeat', stats: STATS});
}, 10000);

send({t:'ready', hookCount: STATS.hookCount});
"""

hit_count = 0

def on_msg(m, data):
    global hit_count
    if m.get('type') == 'error':
        print(f'[JS-ERR] {m.get("description","")[:400]}', flush=True)
        return
    if m.get('type') != 'send':
        return
    p = m['payload']
    t = p.get('t')
    if t == 'ready':
        print(f'[+] hooks armed = {p["hookCount"]}', flush=True)
        return
    if t in ('no_mod', 'no_exp', 'hook_err'):
        print(f'  ✗ {t}: {p}', flush=True)
        return
    if t == 'hooked':
        print(f'  ✓ hooked {p["mod"]}!{p["fn"]}  @{p["addr"]}', flush=True)
        return
    if t == 'heartbeat':
        s = p['stats']
        print(f'  ♥ HB  hooks={s["hookCount"]}  ssl={s["ssl_leave"]}  evp={s["evp_leave"]}  ws={s["ws_leave"]}  hits={s["hits"]}  wide={s.get("wide",0)}', flush=True)
        return
    if t == 'wide':
        seq = p['seq']; src = p['src']; n = p['n']; kind = p['kind']
        bin_path = OUT_DIR / f'recv_wide_{ts}_seq{seq:03d}_{src}_{kind}.bin'
        if data:
            bin_path.write_bytes(data)
        meta_path = OUT_DIR / f'recv_wide_{ts}_seq{seq:03d}_{src}_{kind}.json'
        meta_path.write_text(json.dumps({
            'seq':seq, 'src':src, 'n':n, 'kind':kind,
            'head_hex':p['head'], 'bt':p.get('bt',[])
        }, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'  ▪ wide #{seq} {src} n={n} url_kind={kind}  → {bin_path.name}', flush=True)
        return
    if t in ('ssl_err', 'evp_err', 'ws_err'):
        print(f'  [{t}] {p.get("err","")[:200]}', flush=True)
        return
    if t == 'hit':
        hit_count += 1
        seq = p['seq']
        src = p['src']
        n   = p['n']
        hits = p['hits']
        bt  = p.get('bt', [])
        mod = Path(str(OUT_DIR))
        # dump binary
        bin_path = OUT_DIR / f'recv_voice_wire_{ts}_seq{seq:03d}_{src}.bin'
        if data:
            bin_path.write_bytes(data)
        # dump metadata
        meta = {
            'seq': seq,
            'src': src,
            'n': n,
            'hits': hits,
            'head_hex': p['head'],
            'bt': bt,
            'bin': str(bin_path.name),
        }
        meta_path = OUT_DIR / f'recv_voice_wire_{ts}_seq{seq:03d}_{src}.json'
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')
        # console banner
        hit_names = ', '.join(h['name'] for h in hits[:6])
        print(f'\n{"★"*72}', flush=True)
        print(f'★★★ HIT #{seq}  src={src}  n={n}  markers=[{hit_names}]', flush=True)
        print(f'★★★ bin  = {bin_path.name}', flush=True)
        print(f'★★★ meta = {meta_path.name}', flush=True)
        print(f'★★★ head[0:128] = {p["head"][:256]}', flush=True)
        if bt:
            print(f'★★★ bt top = {bt[0]}  {bt[1] if len(bt)>1 else ""}  {bt[2] if len(bt)>2 else ""}', flush=True)
        print(f'{"★"*72}\n', flush=True)


def get_pid():
    out = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
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
    print(f'★★★ 采样窗口 {CAPTURE_SEC}s ★★★')
    print(f'   请立即操作：手机企微 → 打开"文件传输助手" → 按住说话 → 说一句 10 秒左右的话 → 松手发送')
    print(f'   PC 侧保持企微在前台、FTA 会话打开')
    print(f'   只需发 1 条即可，多发也无妨')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try:
        sc.unload()
        sess.detach()
    except Exception:
        pass
    print(f'\n[+] 收工. 总命中 = {hit_count}', flush=True)
    print(f'[+] 产物目录: {OUT_DIR}', flush=True)
    if hit_count == 0:
        print('\n[!] 0 命中可能的原因：', flush=True)
        print('    1) marker 列表没覆盖到真实字段（voice URL 域名不同）', flush=True)
        print('    2) 消息未经 SSL_read/EVP_DecryptUpdate 路径（走 mmtls 自定义解密？）', flush=True)
        print('    3) 语音消息没有实际到达（手机侧还没发出 / PC 未同步）', flush=True)
        print('    → 下一步：扩展 marker 或换 hook 点', flush=True)
    os._exit(0)


if __name__ == '__main__':
    main()
