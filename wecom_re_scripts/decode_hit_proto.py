# decode_hit_proto.py — 从 hook_serialize HIT 的 ecx dump 里扫 proto wire 段并解码
#
# 思路：
#   1. ecx 是 MessageLite* (C++ 对象，前 4 字节 vtable ptr + 一堆 heap ptr + inline string 字段)
#   2. 内嵌的 std::string 字段（MSVC 布局）：
#        SSO 模式 (cap <= 15): [char[16]][size:u32][cap:u32]
#        heap 模式 (cap > 15): [char* ptr][unused][size:u32][cap:u32]
#      判断：如果 dword @+0x14 (cap) <= 15，则前 16B 是 inline；否则 dword @+0x00 是 char*
#   3. 一旦找到 std::string，其内容可能是：
#        a) 明文 proto wire bytes（第一字节 = 合法 tag: 0x0a/0x12/0x18/0x22...）
#        b) base64 编码的 proto（全 ASCII base64 charset）
#   4. 全 buffer 扫：滑窗找 `size:cap` 后跟合法 wire tag 的位置
#
# 用法：python decode_hit_proto.py <bin>

import sys, struct, base64
from pathlib import Path

BASE64_CHARS = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

def is_base64_ascii(b, min_len=16):
    if len(b) < min_len: return False
    return all(c in BASE64_CHARS for c in b)

def read_varint(data, pos):
    v = 0; shift = 0; start = pos
    while pos < len(data) and pos - start < 10:
        b = data[pos]; pos += 1
        v |= (b & 0x7f) << shift; shift += 7
        if not (b & 0x80): return v, pos
    return None, pos

def looks_like_proto(data, min_tags=2):
    """尝试从头解 min_tags 个合法 wire tag，全程 payload 在范围内"""
    pos = 0; tags = 0; max_field = 0
    while pos < len(data) and tags < 12:
        v, pos2 = read_varint(data, pos)
        if v is None: break
        wt = v & 7; f = v >> 3
        if f == 0 or f > 200 or wt in (3, 4) or wt > 5:
            break
        max_field = max(max_field, f)
        pos = pos2
        if wt == 0:   # varint
            _, pos = read_varint(data, pos)
        elif wt == 1: pos += 8
        elif wt == 5: pos += 4
        elif wt == 2:
            L, pos = read_varint(data, pos)
            if L is None or L > len(data) - pos: break
            pos += L
        tags += 1
    return tags >= min_tags, tags, max_field

def decode_proto_pretty(data, indent=0, max_depth=4):
    """浅解 proto：只列出 tags + payload 预览"""
    out = []; pos = 0
    while pos < len(data):
        v, pos2 = read_varint(data, pos)
        if v is None: break
        wt = v & 7; f = v >> 3
        if f == 0 or f > 500 or wt in (3, 4) or wt > 5: break
        pos = pos2
        if wt == 0:
            val, pos = read_varint(data, pos)
            out.append(('  '*indent) + f'field {f}: varint = {val}')
        elif wt == 1:
            if pos+8 > len(data): break
            val = struct.unpack('<Q', data[pos:pos+8])[0]; pos += 8
            out.append(('  '*indent) + f'field {f}: fixed64 = 0x{val:x}')
        elif wt == 5:
            if pos+4 > len(data): break
            val = struct.unpack('<I', data[pos:pos+4])[0]; pos += 4
            out.append(('  '*indent) + f'field {f}: fixed32 = 0x{val:x}')
        elif wt == 2:
            L, pos = read_varint(data, pos)
            if L is None or L > len(data) - pos: break
            payload = data[pos:pos+L]; pos += L
            # 尝试判断是嵌套 proto 还是字符串
            printable = sum(1 for b in payload if 32 <= b < 127 or b in (9,10,13))
            if len(payload) >= 2 and max_depth > 0:
                ok, nt, mf = looks_like_proto(payload, min_tags=2)
                if ok:
                    out.append(('  '*indent) + f'field {f}: message ({L} bytes) {{')
                    out.extend(decode_proto_pretty(payload, indent+1, max_depth-1))
                    out.append(('  '*indent) + '}')
                    continue
            if printable >= max(1, len(payload) - 2):
                out.append(('  '*indent) + f'field {f}: string({L}) = {payload!r}')
            else:
                hex_prev = payload[:32].hex()
                out.append(('  '*indent) + f'field {f}: bytes({L}) = {hex_prev}{"..." if L>32 else ""}')
    return out


def scan_bin(path):
    data = Path(path).read_bytes()
    print(f'\n{"="*72}\n== SCAN {Path(path).name}  size={len(data)}  ==')
    # 1. 先扫 MSVC std::string 候选（size/cap 对）
    print('\n-- std::string candidates (size,cap valid; content = proto/base64) --')
    for pos in range(0, len(data) - 24, 4):
        # 尝试 SSO 模式：[char[16]][size][cap]
        size = struct.unpack_from('<I', data, pos+0x10)[0]
        cap  = struct.unpack_from('<I', data, pos+0x14)[0]
        if cap > 15:
            # heap 模式，读 char* 
            ptr = struct.unpack_from('<I', data, pos+0x00)[0]
            # 我们没法解引用 heap ptr（离线 dump），只能标记
            if 10 < size < 4096 and size < cap < 65536:
                print(f'  @+0x{pos:04x}  heap-string  ptr=0x{ptr:x}  size={size}  cap={cap}')
        else:
            # SSO：char[16] 里存字符串
            if 3 < size <= 15 and cap == 15:
                s = data[pos:pos+size]
                if all(32 <= b < 127 for b in s):
                    print(f'  @+0x{pos:04x}  SSO-string   size={size}  cap={cap}  = {s.decode()!r}')

    # 2. 全 buffer 扫 proto wire 起点
    print('\n-- proto wire candidates (从任意偏移看是否是合法 proto) --')
    hits = []
    for pos in range(len(data) - 16):
        sub = data[pos:pos+min(len(data)-pos, 512)]
        ok, nt, mf = looks_like_proto(sub, min_tags=3)
        if ok and nt >= 4:
            hits.append((pos, nt, mf))
    # 去重相邻
    dedup = []
    last = -100
    for pos, nt, mf in sorted(hits, key=lambda x: -x[1]):
        if abs(pos - last) < 8: continue
        dedup.append((pos, nt, mf)); last = pos
        if len(dedup) >= 5: break
    for pos, nt, mf in dedup:
        print(f'\n  @+0x{pos:04x}  tags={nt}  max_field={mf}')
        print('  --- decode ---')
        payload = data[pos:pos+min(len(data)-pos, 256)]
        for line in decode_proto_pretty(payload)[:30]:
            print(f'  {line}')

    # 3. 全 buffer 扫 base64 段（可能是嵌套 proto 的 base64 wrap）
    print('\n-- long ASCII base64 runs (>=32 chars, may decode to proto) --')
    i = 0
    while i < len(data):
        if data[i] not in BASE64_CHARS: i += 1; continue
        j = i
        while j < len(data) and data[j] in BASE64_CHARS: j += 1
        run = data[i:j]
        if len(run) >= 32:
            s = run.decode('ascii')
            # trim padding to multiple of 4
            slen = (len(s) // 4) * 4
            try:
                dec = base64.b64decode(s[:slen] + '===')
                # is dec proto-like?
                ok, nt, mf = looks_like_proto(dec, min_tags=2)
                print(f'  @+0x{i:04x} run_len={len(s)}  {"★PROTO"+f"(tags={nt},mf={mf})" if ok else ""}  {s[:60]!r}')
                if ok and nt >= 3:
                    for line in decode_proto_pretty(dec)[:20]:
                        print(f'    {line}')
            except Exception:
                pass
        i = j


if __name__ == '__main__':
    for p in sys.argv[1:] or []:
        scan_bin(p)
