# find_mmtls.py -- 找 mmtls/TLS 层写入函数，在加密前截获明文 CGI 请求
import frida, subprocess, sys, os, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

done = threading.Event()
result = {}

def on_msg(msg, data):
    if msg.get('type') == 'send':
        result.update(msg['payload'])
    elif msg.get('type') == 'error':
        print('ERR:', msg['description'][:200], flush=True)
    done.set()

sess = frida.get_local_device().attach(pid)
JS = r"""
'use strict';
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;
var wxSize = Process.getModuleByName('WXWork.exe').size;

// 搜索与 TLS/mmtls/SSL 相关的字符串
var keywords = ['mmtls', 'SSL_write', 'ssl_write', 'mmtls_write', 'TLS', 'mmTLS',
                'encrypt', 'Encrypt', 'ENCRYPT', 'WriteRecord', 'write_record'];
var found = {};

for (var ki = 0; ki < keywords.length; ki++) {
    var kw = keywords[ki];
    // 转为 bytes pattern (ASCII)
    var pat = '';
    for (var ci = 0; ci < kw.length; ci++) {
        pat += ('0' + kw.charCodeAt(ci).toString(16)).slice(-2) + ' ';
    }
    pat = pat.trim();
    try {
        var res = Memory.scanSync(wxBase, wxSize, pat);
        if (res.length > 0) {
            var matches = [];
            for (var ri = 0; ri < Math.min(res.length, 3); ri++) {
                matches.push({
                    rva: res[ri].address.sub(wxBase).toUInt32(),
                    abs: res[ri].address.toString()
                });
            }
            found[kw] = {count: res.length, matches: matches};
        }
    } catch(e) {}
}

// 搜索 "mmtls" 相关函数在所有 DLL 中
var allMods = Process.enumerateModules();
var dllFound = [];
for (var mi = 0; mi < allMods.length; mi++) {
    var modName = allMods[mi].name.toLowerCase();
    if (modName.indexOf('ssl') >= 0 || modName.indexOf('tls') >= 0 || modName.indexOf('crypt') >= 0) {
        dllFound.push(allMods[mi].name + '|' + allMods[mi].base.toString());
    }
}

send({found: found, dllFound: dllFound, wxBase: wxBase.toString()});
"""
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
done.wait(30)

print(f"wxBase: {result.get('wxBase')}", flush=True)
print(f"\n=== TLS/加密相关 DLL ===", flush=True)
for s in result.get('dllFound', []):
    print(f'  {s}', flush=True)

print(f"\n=== WXWork.exe 内 TLS/mmtls 字符串 ===", flush=True)
for kw, info in result.get('found', {}).items():
    print(f'  [{kw}] count={info["count"]}', flush=True)
    for m in info.get('matches', []):
        print(f'    RVA=0x{m["rva"]:08x}  abs={m["abs"]}', flush=True)

sess.detach()
os._exit(0)
