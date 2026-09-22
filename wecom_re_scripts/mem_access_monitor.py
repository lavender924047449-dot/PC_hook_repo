# mem_access_monitor.py
# 用 MemoryAccessMonitor 监控 "before compress" 字符串所在内存页的读取
# 无需用户配合，转发时哪个函数访问这块内存就立即知道
#
# "before compress" @ 0xb72e681 → 所在页 0xb72e000

import frida, subprocess, sys, os, time, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID={pid}', flush=True)

JS = r"""
'use strict';
var PAGE_BASE = ptr(0xb72e000);
var PAGE_SIZE = 0x1000;
var accesses = [];
var MAX = 200;
var active = false;

try {
    MemoryAccessMonitor.enable([{base: PAGE_BASE, size: PAGE_SIZE}], {
        onAccess: function(details) {
            if (!active) return;
            if (accesses.length >= MAX) return;
            accesses.push({
                from: details.from.toString(),
                op: details.operation,
                addr: details.address.toString()
            });
        }
    });
    send({t:'monitor_ready', page: PAGE_BASE.toString()});
} catch(e) {
    send({t:'monitor_err', msg: e.message});
}

recv('start', function(_) { active = true;  send({t:'ack','msg':'monitoring started'}); });
recv('stop',  function(_) { active = false; send({t:'dump_result', accesses: accesses}); });
"""

accesses = []
done = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:200], flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t in ('monitor_ready','monitor_err','ack'):
        print('[%s] %s' % (t, p), flush=True)
    elif t == 'dump_result':
        accesses.extend(p.get('accesses',[]))
        done.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 60 秒内转发消息，然后等待结果 ===', flush=True)
sc.post({'type':'start'})
time.sleep(60)
sc.post({'type':'stop'})
done.wait(15)

# 统计访问这块内存的 IP
from collections import Counter
wx_base = 0x2d0000
ips = [a['from'] for a in accesses]
ip_ints = [int(x,16) for x in ips]
ip_rvas = [x - wx_base for x in ip_ints if 0x2d0000 <= x <= 0xcf00000]

cnt = Counter(ip_rvas)
print(f'\n[+] 总访问次数: {len(accesses)}', flush=True)
print('[+] 访问 "before compress" 页的 WXWork 代码地址（RVA）:')
for rva, count in cnt.most_common(20):
    print('  RVA=0x%08x  abs=0x%08x  count=%d' % (rva, rva+wx_base, count), flush=True)

# 找唯一的访问 IP（非循环热路径）
unique_ips = [rva for rva in ip_rvas if cnt[rva] < 20]
print('\n[+] 非热路径访问（可能是实际 log 调用点）:')
for rva in sorted(set(unique_ips)):
    print('  RVA=0x%08x  abs=0x%08x' % (rva, rva+wx_base), flush=True)

os._exit(0)
