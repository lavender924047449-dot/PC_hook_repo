# dump_loghelper_all.py  — 第十三轮 P0
# ---------------------------------------------------------------
# 目的：hook WXWork.exe + RVA 0x2B93BE2（第十二轮末证实的 log helper）
# 策略：完全不做 .rdata 常量过滤；每次命中都：
#   * 记录 ret_addr（caller，用于聚合）
#   * 读栈 32 dwords + 6 通用寄存器
#   * 尝试将每个候选指针 deref 为 ASCII / UTF-16 字符串
# 输出：NDJSON（一次一行，便于中断/追加），同时实时高亮含 "do send message" /
#       "conversationId" / "msgId" / "ClientId" 关键词的条目
# 反查：结束后聚合 ret_addr、按关键字筛条目、导出 caller 命中榜
# ---------------------------------------------------------------
import frida, subprocess, sys, os, time, json, re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = datetime.now().strftime('%Y%m%d_%H%M%S')
NDJSON = OUT / f'loghelper_dump_{TS}.ndjson'
SUMMARY = OUT / f'loghelper_summary_{TS}.json'
SENTINEL = OUT / '_loghelper_done.flag'
if SENTINEL.exists():
    SENTINEL.unlink()

KEYWORDS = [
    'do send message', 'send message to peer', 'conversationId',
    'msgId', 'ClientId', 'task id', 'PostSendMessage', 'ForwardMessage',
]

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('WXWork :9882 not found')

pid = get_pid()
print(f'PID = {pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var wxEnd = base.add(wx.size);
var RVA = 0x2B93BE2;
var TARGET = base.add(RVA);
send({t:'ready', base: base.toString(), target: TARGET.toString(),
      wxSize: wx.size});

// 尝试把 32-bit 值当指针 deref 成字符串
function tryReadStr(v) {
    if (v < 0x10000 || v >= 0xF0000000) return null;
    try {
        var p = ptr(v);
        var bytes = null;
        try { bytes = new Uint8Array(p.readByteArray(256)); }
        catch (e) { return null; }
        if (!bytes || bytes.length < 3) return null;
        var b0 = bytes[0], b1 = bytes[1];
        // UTF-16LE 判定: b0 是 ASCII 可打印, b1 == 0, b3 == 0
        if (b0 >= 0x20 && b0 < 0x7f && b1 === 0 &&
            bytes.length > 6 && bytes[3] === 0 && bytes[5] === 0) {
            var s = '';
            for (var i = 0; i < 256; i += 2) {
                var c = bytes[i] | (bytes[i+1] << 8);
                if (c === 0) break;
                if (c < 0x20 || c > 0x7e) { if (i < 6) return null; break; }
                s += String.fromCharCode(c);
            }
            if (s.length >= 3) return '[U16]' + s;
            return null;
        }
        // ASCII 判定
        if (b0 < 0x20 || b0 > 0x7e) return null;
        var end = 0;
        while (end < 256 && bytes[end] >= 0x20 && bytes[end] < 0x7f) end++;
        if (end < 4) return null;
        var s2 = '';
        for (var i = 0; i < end; i++) s2 += String.fromCharCode(bytes[i]);
        return s2;
    } catch (e) { return null; }
}

var totalCount = 0;
Interceptor.attach(TARGET, {
    onEnter: function(args) {
        totalCount++;
        try {
            var esp = this.context.esp;
            var ret = esp.readU32() >>> 0;
            var frame = {
                n: totalCount,
                ts: Date.now(),
                ret: ret,
                slots: []
            };
            // 6 通用寄存器
            var regs = {
                eax: this.context.eax >>> 0,
                ebx: this.context.ebx >>> 0,
                ecx: this.context.ecx >>> 0,
                edx: this.context.edx >>> 0,
                esi: this.context.esi >>> 0,
                edi: this.context.edi >>> 0
            };
            var regBag = [];
            for (var k in regs) {
                var s = tryReadStr(regs[k]);
                var e = {r:k, v:regs[k]};
                if (s) e.str = s;
                regBag.push(e);
            }
            frame.regs = regBag;
            // 32 dwords stack
            for (var i = 1; i <= 32; i++) {
                var v = 0;
                try { v = esp.add(i*4).readU32() >>> 0; }
                catch (e) { break; }
                var entry = {o: i*4, v: v};
                var s1 = tryReadStr(v);
                if (s1) entry.str = s1;
                // std::string* → 读 *(v) 再 tryReadStr
                if (v > 0x10000 && v < 0xF0000000) {
                    try {
                        var d = ptr(v).readU32() >>> 0;
                        var s2 = tryReadStr(d);
                        if (s2) entry.dstr = s2;
                    } catch(e) {}
                }
                frame.slots.push(entry);
            }
            send({t:'hit', f: frame});
        } catch (e) {
            send({t:'err', msg: e.message});
        }
    }
});
recv('stat', function(_) {
    send({t:'stat', total: totalCount});
});
"""

ndjson_f = NDJSON.open('w', encoding='utf-8')
hit_count = 0
kw_hit_count = 0
ret_counter = Counter()
kw_ret_counter = Counter()
kw_examples = defaultdict(list)  # ret -> [full frame]
ready = [False]
stat_ok = [None]
base_val = [0]


def slot_strings(f):
    out = []
    for s in f.get('slots', []):
        if 'str' in s:
            out.append(('S+{:02x}'.format(s['o']), s['str']))
        if 'dstr' in s:
            out.append(('S*+{:02x}'.format(s['o']), s['dstr']))
    for r in f.get('regs', []):
        if 'str' in r:
            out.append((r['r'], r['str']))
    return out


def hit_matches_keyword(strs):
    for _, txt in strs:
        low = txt.lower()
        for kw in KEYWORDS:
            if kw.lower() in low:
                return kw, txt
    return None, None


def on_msg(msg, data):
    global hit_count, kw_hit_count
    if msg.get('type') == 'error':
        print('ERR:', msg.get('description', '')[:250])
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t')
    if t == 'ready':
        ready[0] = True
        base_val[0] = int(p['base'], 16)
        print(f'[+] ready base={p["base"]} target={p["target"]}')
        return
    if t == 'stat':
        stat_ok[0] = p['total']
        return
    if t == 'err':
        print('[JS ERR]', p.get('msg'))
        return
    if t != 'hit':
        return
    f = p['f']
    hit_count += 1
    ret_counter[f['ret']] += 1
    strs = slot_strings(f)
    kw, txt = hit_matches_keyword(strs)
    # NDJSON 一行一条（仅保留字符串槽 + ret，压缩尺寸）
    line = {
        'n': f['n'], 'ts': f['ts'],
        'ret': f['ret'],
        'strs': [[k, v] for k, v in strs],
    }
    if kw:
        line['kw'] = kw
        kw_hit_count += 1
        kw_ret_counter[f['ret']] += 1
        # 保存完整 frame（含所有 slot 数值）到 examples
        if len(kw_examples[f['ret']]) < 5:
            kw_examples[f['ret']].append(f)
        print(f'★ #{f["n"]}  ret=0x{f["ret"]:08x}  KW={kw!r}  txt={txt[:120]!r}')
    ndjson_f.write(json.dumps(line, ensure_ascii=False) + '\n')
    if hit_count % 500 == 0:
        print(f'  ... {hit_count} hits, {kw_hit_count} kw-hits')


sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
if not ready[0]:
    print('[!] JS 未就绪')
    sys.exit(1)

print('\n' + '='*72)
print('>>> 请在企微中执行 1-3 次转发（FTA→FTA 或 FTA→外部）              <<<')
print(f'>>> 完成后 New-Item {SENTINEL.name}  即触发结束和聚合             <<<')
print('>>> 默认最长运行 15 分钟                                             <<<')
print('='*72 + '\n')

t0 = time.time()
last_hb = t0
while not SENTINEL.exists() and time.time() - t0 < 15*60:
    time.sleep(0.5)
    if time.time() - last_hb > 30:
        last_hb = time.time()
        print(f'  [hb] elapsed={int(time.time()-t0)}s hits={hit_count} kw_hits={kw_hit_count}')

if SENTINEL.exists():
    try: SENTINEL.unlink()
    except: pass
    print(f'\n[+] sentinel 收到（等待 {time.time()-t0:.1f}s）')

# 请 JS 返回总命中
sc.post({'type': 'stat'})
tw = time.time()
while stat_ok[0] is None and time.time() - tw < 5:
    time.sleep(0.1)

ndjson_f.close()

base_hex = f'0x{base_val[0]:08x}'
top_all = ret_counter.most_common(20)
top_kw = kw_ret_counter.most_common(30)

def ret_to_rva(ret):
    if ret > base_val[0]:
        return ret - base_val[0]
    return None

summary = {
    'pid': pid, 'ts': TS, 'base': base_hex,
    'total_hits': hit_count,
    'kw_hits': kw_hit_count,
    'top_ret_all': [
        {'ret': f'0x{r:08x}', 'rva': f'0x{ret_to_rva(r):x}' if ret_to_rva(r) else None,
         'count': c} for r, c in top_all
    ],
    'top_ret_kw': [
        {'ret': f'0x{r:08x}', 'rva': f'0x{ret_to_rva(r):x}' if ret_to_rva(r) else None,
         'count': c} for r, c in top_kw
    ],
    'kw_examples': {
        f'0x{r:08x}': v for r, v in kw_examples.items()
    },
    'keywords': KEYWORDS,
}
SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

print(f'\n[结果]')
print(f'  total hits    = {hit_count}')
print(f'  keyword hits  = {kw_hit_count}')
print(f'  ndjson        = {NDJSON.name}')
print(f'  summary       = {SUMMARY.name}')
print(f'\n[Top ret_addr — 全部]')
for r, c in top_all[:10]:
    rva = ret_to_rva(r)
    print(f'  ret=0x{r:08x}  RVA=0x{rva:x}  count={c}' if rva else
          f'  ret=0x{r:08x}  (非 WXWork)  count={c}')

print(f'\n[Top ret_addr — 命中关键字]')
for r, c in top_kw[:15]:
    rva = ret_to_rva(r)
    print(f'  ret=0x{r:08x}  RVA=0x{rva:x}  count={c}' if rva else
          f'  ret=0x{r:08x}  (非 WXWork)  count={c}')

sc.unload()
sess.detach()
os._exit(0)
