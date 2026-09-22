# _read_vtable_slots.py — 读 vtable slot 找 ParseFrom
#
# Google Protobuf MessageLite 标准 vtable 布局:
#   slot 0  ~dtor
#   slot 1  GetTypeName
#   slot 2  New()
#   slot 3  New(Arena)
#   slot 4  Clear
#   slot 5  IsInitialized
#   slot 6  CheckTypeAndMergeFrom
#   slot 7  MergePartialFromCodedStream  ← ★ ParseFrom
#   slot 8  ByteSizeLong                  ← BYT
#   slot 9  SerializeWithCachedSizes      ← SER
#   ...
#
# 已知 BYT=0x9f03c40, SER=0x9f042a0
# 找到 BYT/SER 在 vtable 里的 slot idx → ParseFrom = slot idx(BYT) - 1

import frida, subprocess, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

VTABLES = [
    ('outer wrapper',    0xb0610c0),
    ('sub-msg A',        0xb06c9b8),
    ('repeated body',    0xb0656a8),
    ('ExtraContent #00', 0xb0901ac),
]

BYT_VA = 0x09f03c40
SER_VA = 0x09f042a0

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

JS = r"""
'use strict';
send({t:'ready'});
rpc.exports.readvt = function(va, n) {
    var p = ptr(va);
    var out = [];
    for (var i=0; i<n; i++) {
        try { out.push('0x' + p.add(i*4).readU32().toString(16)); }
        catch(e) { out.push('?'); }
    }
    return out;
};
"""

pid = get_pid()
print(f'[*] attaching PID={pid}')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
ready = [False]
def on_msg(m, d):
    if m.get('type')=='send' and m.get('payload',{}).get('t')=='ready':
        ready[0] = True
sc.on('message', on_msg); sc.load()
import time
for _ in range(30):
    if ready[0]: break
    time.sleep(0.1)

print(f'\n{"─"*80}')
print(f'{"label":<22}{"vt addr":<14}slots [0..15]')
print('─'*80)

parsefrom_candidates = {}

for label, vt in VTABLES:
    slots = sc.exports_sync.readvt(vt, 16)
    print(f'\n{label:<22}0x{vt:08x}')
    byt_slot, ser_slot = None, None
    for i, s in enumerate(slots):
        try:
            v = int(s, 16)
        except:
            v = 0
        mark = ''
        if v == BYT_VA: mark = '  ← BYT (ByteSizeLong)'; byt_slot = i
        elif v == SER_VA: mark = '  ← SER (SerializeWithCachedSizes)'; ser_slot = i
        print(f'    slot[{i:>2}] = {s}{mark}')
    if byt_slot is not None:
        pf_slot = byt_slot - 1
        pf_addr = slots[pf_slot]
        print(f'    → ★ ParseFrom candidate = slot[{pf_slot}] = {pf_addr}')
        parsefrom_candidates.setdefault(pf_addr, []).append(label)

print(f'\n{"═"*80}')
print(f'★ ParseFrom 候选汇总（越多 vtable 共享，越可能是 shared MergeFromCodedStream）:')
for addr, labels in sorted(parsefrom_candidates.items(), key=lambda kv: -len(kv[1])):
    print(f'  {addr:<12}  shared by {len(labels)} vtable(s): {labels}')

# 顺便读几个 76-pool 已知 Extra 类型的 vtable 对比
print(f'\n{"─"*80}\n对比几个 76-pool 的 vtable slot[7]/[8]/[9]:')
import json
from pathlib import Path
POOL = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\parse_typeurl_pool_20260914_122249.json')
if POOL.exists():
    entries = json.loads(POOL.read_text('utf-8'))['entries']
    for idx in [0, 25, 50, 75]:  # 采样 4 个
        if idx < len(entries):
            e = entries[idx]
            va = e['entry_va']
            slots = sc.exports_sync.readvt(va, 16)
            print(f'  #{idx:<3} 0x{va:x}  {e["type_url"]}')
            for i in (6, 7, 8, 9, 10, 11):
                try:
                    v = int(slots[i], 16)
                    mark = ''
                    if v == BYT_VA: mark = ' ← BYT'
                    elif v == SER_VA: mark = ' ← SER'
                    print(f'    slot[{i}] = {slots[i]}{mark}')
                except: pass

sc.unload(); sess.detach()
print('\n[done]')
