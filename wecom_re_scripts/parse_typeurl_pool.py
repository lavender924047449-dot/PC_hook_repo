# parse_typeurl_pool.py — 拆解 0xb0901ac 处的 ww_richmessage.Extra* 描述符池
#
# 结构（观察 hook_Ad3_..._h1_leave_a5.bin 得出）：
#   每条 entry = 16 个 dword header + 内联 null-term 字符串（type_url）+ 4-byte 对齐 pad
#   两条 entry 之间连续排列，无 sentinel（用字符串 "ww_richmessage." 起始作切割）
#
# 目的：
#   1. 逐条列出（enum idx → type_url）—— 这就是 msgtype 到 proto 类型的实际映射表
#   2. 提取 header 里的函数指针（落在 .text 范围内）
#   3. 与 callchain_*.json 交叉，标记「PreSend chain 内」的函数指针
#      → 命中的就是 ConstructMessageProtobuf 的构造 / 序列化实现候选
#
# 数据文件：hook_Ad3_20260914_121136_h1_leave_a5.bin（8192 字节，从 0xb0901ac 起）

import sys, json, struct, re
from pathlib import Path
from datetime import datetime

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
POOL_BIN = OUT_DIR / 'hook_Ad3_20260914_121136_h1_leave_a5.bin'
POOL_BASE_VA = 0xb0901ac
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

# .text 边界（供函数指针筛选）—— 用当轮 runtime module.base（Frida 报 0x5e0000）
# 但代码里的绝对地址可能相对不同 base；我们用宽范围过滤：0x400000..0x0c000000
TEXT_LO = 0x00400000
TEXT_HI = 0x0c000000


def load_callchain():
    cands = sorted([p for p in OUT_DIR.glob('callchain_*.json')
                    if 'trace' not in p.name and 'flat' not in p.name],
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands: return {}, None
    j = json.loads(cands[0].read_text(encoding='utf-8'))
    fns = {fn['va']: fn['depth'] for fn in j['functions']}
    return fns, cands[0].name


def parse_pool(data, base_va):
    """按 'ww_' 起始切分 entry。返回 [{idx, va, type_url, header_dwords, fnptrs}]"""
    # 找所有 "ww_richmessage." 出现位置
    marker = b'ww_richmessage.'
    starts = [m.start() for m in re.finditer(re.escape(marker), data)]
    entries = []
    for i, s in enumerate(starts):
        # type_url = 从 s 起到下一个 \0
        end = data.find(b'\x00', s)
        if end == -1: end = len(data)
        type_url = data[s:end].decode('ascii', errors='replace')
        # header 起点 = 上一条 entry 结束（或 pool 起点）
        prev_end = 0 if i == 0 else starts[i-1] + 0  # 起点：上一条 type_url 结束后
        if i == 0:
            hdr_start = 0
        else:
            # 上一条 type_url 结束的下一个 4-byte 对齐 pos
            prev_str_end = data.find(b'\x00', starts[i-1])
            hdr_start = ((prev_str_end + 4) // 4) * 4
        hdr_end = s
        header = data[hdr_start:hdr_end]
        # 拆 dword
        n_dwords = len(header) // 4
        dwords = struct.unpack(f'<{n_dwords}I', header[:n_dwords*4])
        # fn ptr 候选
        fnptrs = [(j, d) for j, d in enumerate(dwords)
                  if TEXT_LO <= d < TEXT_HI]
        entries.append({
            'idx': i,
            'entry_va': base_va + hdr_start,
            'type_url': type_url,
            'hdr_off': hdr_start,
            'hdr_len': hdr_end - hdr_start,
            'dwords': dwords,
            'fnptrs': fnptrs,
        })
    return entries


def main():
    data = POOL_BIN.read_bytes()
    print(f'[*] pool bin: {POOL_BIN.name}  size={len(data)}  base_va=0x{POOL_BASE_VA:x}')
    chain_fns, chain_name = load_callchain()
    print(f'[*] callchain: {chain_name}  ({len(chain_fns)} fns)')

    entries = parse_pool(data, POOL_BASE_VA)
    print(f'[+] parsed {len(entries)} entries\n')

    # 收集所有 fn ptrs + 交叉 chain
    all_fnptrs = {}
    for e in entries:
        for off, p in e['fnptrs']:
            all_fnptrs.setdefault(p, []).append((e['idx'], e['type_url'], off*4))
    on_chain_fnptrs = {p: v for p, v in all_fnptrs.items() if p in chain_fns}

    # 打印每条 entry
    print(f'=== ww_richmessage.Extra* type_url pool (msgtype → proto class) ===')
    print(f'{"idx":<4} {"entry_va":<12} {"hlen":<5} {"type_url":<48} fnptrs(rva)')
    for e in entries:
        fp_str = ','.join(f'0x{p:x}' for _, p in e['fnptrs'][:6])
        print(f'{e["idx"]:<4} 0x{e["entry_va"]:08x}  {e["hdr_len"]:<5} {e["type_url"]:<48} {fp_str}')

    print(f'\n=== fn ptrs summary ===')
    print(f'total unique fn ptrs in pool: {len(all_fnptrs)}')
    print(f'on-PreSend-chain fn ptrs:     {len(on_chain_fnptrs)}  ★★★')
    for p, uses in sorted(on_chain_fnptrs.items()):
        types = ', '.join(f'#{u[0]}:{u[1]}' for u in uses[:3])
        depth = chain_fns[p]
        print(f'  0x{p:08x} (d{depth})  used by: {types}')

    # 若一个 fn ptr 被 N 条 entry 共享，就是 message factory / 通用序列化器
    shared = {p: u for p, u in all_fnptrs.items() if len(u) >= 3}
    print(f'\n=== fn ptrs shared by >=3 entries (通用 serialize/factory 候选) ===')
    for p, uses in sorted(shared.items(), key=lambda kv: -len(kv[1]))[:20]:
        depth = chain_fns.get(p)
        chain_mark = f'★CHAIN d{depth}' if depth is not None else ''
        types = ', '.join(f'#{u[0]}({u[1][:24]})' for u in uses[:4])
        print(f'  0x{p:08x}  used_by={len(uses):>3} entries  {chain_mark:<12}  {types}')

    # 落盘
    out = {
        'meta': {'pool_base_va': POOL_BASE_VA, 'n_entries': len(entries),
                 'callchain': chain_name, 'ts': ts},
        'entries': [{**e, 'dwords': list(e['dwords'])} for e in entries],
        'unique_fnptrs': [
            {'ptr': p, 'depth': chain_fns.get(p), 'on_chain': p in chain_fns,
             'used_by': [{'idx': u[0], 'type_url': u[1], 'hdr_off': u[2]} for u in v]}
            for p, v in sorted(all_fnptrs.items())
        ],
    }
    fp = OUT_DIR / f'parse_typeurl_pool_{ts}.json'
    fp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'\n[+] wrote {fp.name}')


if __name__ == '__main__':
    main()
