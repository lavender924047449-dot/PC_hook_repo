"""找出 plaintext JSON 中 CGI#1001 的 payload 指针"""
import json, re, glob, os, sys, base64
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 最新的 plaintext
files = sorted(glob.glob('plaintext_*.json'), key=os.path.getmtime)
data = json.load(open(files[-1], encoding='utf-8'))
print('total captures:', len(data))

# 每条 capture 有: ts, a1, a2_addr, a2(hex), a3, ptrs
for i, cap in enumerate(data):
    a2 = bytes.fromhex(cap.get('a2','').replace(' ',''))
    a2_str = ''.join(chr(b) if 32<=b<127 else '.' for b in a2)
    has1001 = 'cgi request:1001' in a2_str
    hasURL = 'i.work.weixin' in a2_str
    hasUUID = len(a2) > 24 and a2[8:9] == b'-' and a2[13:14] == b'-'

    print('\n=== cap#%d  a2=%s  1001=%s  URL=%s  UUID=%s ===' % (
        i+1, cap.get('a2_addr'), has1001, hasURL, hasUUID))

    # 找 compress length
    m = re.search(r'cgi request:1001 (\w+) compress length (\d+)', a2_str)
    if m:
        print('  CGI LOG: cgi request:1001 %s compress length %s' % (m.group(1), m.group(2)))
        payload_len = int(m.group(2))
    else:
        payload_len = None

    # 打印 a2 前 192 字节
    for off in range(0, min(192, len(a2)), 16):
        row = a2[off:off+16]
        hx = ' '.join('%02x' % b for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print('  %04x: %-47s  %s' % (off, hx, asc))

    # 在 ptrs deref 里找有意义内容
    interesting = []
    for addr_hex, hexd in cap.get('ptrs', {}).items():
        bs2 = bytes.fromhex(hexd.replace(' ',''))
        s = ''.join(c for c in bs2.decode('utf-8', errors='ignore') if c.isprintable())
        if len(s) > 8:
            # 过滤代码/UI 字符串
            if not re.search(r'\.xml|weclaw|bubble|RtlAlloc|glyph|layout|unread', s):
                interesting.append((addr_hex, s, bs2))

    # 如果有 payload_len，找大小接近 payload_len 的指针数据
    if interesting:
        print('  Notable deref ptrs:')
        for addr, s, raw in interesting[:8]:
            # 尝试 b64 decode
            b64m = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', s)
            if b64m:
                try:
                    dec = base64.b64decode(b64m.group() + '==')
                    dec_s = ''.join(c for c in dec.decode('utf-8', errors='ignore') if c.isprintable())
                    if dec_s:
                        print('    [b64 @0x%s (%d b)] %r' % (addr, len(dec), dec_s[:120]))
                        continue
                except:
                    pass
            print('    [@0x%s] %r' % (addr, s[:120]))
