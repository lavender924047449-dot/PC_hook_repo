# xref_typeurl_pool2.py — 修正版：全 .text 一遍扫 prologue → 建索引 → bisect 归属
#
# 相比 v1 的改动：
#   1. 一次性扫全 .text 所有可能 prologue 模式，建 sorted list（va）
#   2. 对每个 xref insn_va，用 bisect 找 <= insn_va 的最大 prologue va = 函数起点
#   3. 支持多种 prologue：
#      - 55 8B EC              # 标准 push ebp; mov ebp, esp
#      - 55 8B EC 83 EC        # 上面 + sub esp,imm
#      - 56 8B F1              # __thiscall + push esi + mov esi, ecx
#      - 53 56 57              # push ebx, esi, edi
#      - 8B FF 55 8B EC        # MS "hot-patch" hook prologue (mov edi, edi)
#      - 6A ?? 68              # push imm; push offset  (SEH setup start)
#   4. 要求前一字节是 CC/C3/C2/90/00 之一（函数尾/nop 填充）
#
# 产物：xref_typeurl_v2_<ts>.json + 控制台 top 30

import sys, json, bisect
from pathlib import Path
from datetime import datetime
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

WXWORK = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
POOL_BASE_RVA = 0x0b0901ac
POOL_WIDTH    = 0x1000
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

# Prologue 模板：(byte_pattern, min_len)。前一字节需要是 CC/C3/C2/90/00
PROLOGUE_PATTERNS = [
    b'\x55\x8b\xec',          # push ebp; mov ebp, esp
    b'\x8b\xff\x55\x8b\xec',  # hot-patch mov edi,edi + push ebp; mov ebp,esp
    b'\x56\x8b\xf1',          # push esi; mov esi, ecx
    b'\x53\x56\x57\x8b',      # push ebx,esi,edi + mov ...
    b'\x51\x56\x8b\xf1',      # push ecx; push esi; mov esi, ecx
]

def load_pe():
    pe = pefile.PE(str(WXWORK), fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.Name.rstrip(b'\x00') == b'.text':
            return pe, ib, ib + s.VirtualAddress, s.get_data()
    raise RuntimeError('no .text')


def build_prologue_index(text_data, text_va):
    """扫 .text 一遍，返回排好序的 prologue va 列表 + 前置字节要求"""
    prologues = set()
    boundary = {0xCC, 0xC3, 0xC2, 0x90, 0x00}
    for pat in PROLOGUE_PATTERNS:
        L = len(pat)
        start = 1
        pos = text_data.find(pat, start)
        while pos != -1:
            if text_data[pos-1] in boundary:
                prologues.add(text_va + pos)
            pos = text_data.find(pat, pos + 1)
    sorted_pros = sorted(prologues)
    return sorted_pros


def scan_bytes(text_data, text_va):
    hits = []
    for off in range(len(text_data) - 3):
        val = (text_data[off]
               | (text_data[off+1] << 8)
               | (text_data[off+2] << 16)
               | (text_data[off+3] << 24))
        if POOL_BASE_RVA <= val < POOL_BASE_RVA + POOL_WIDTH:
            hits.append({'byte_va': text_va + off, 'imm_val': val})
    return hits


def find_containing_insn(md, text_va, text_data, byte_va, imm_val):
    start = max(byte_va - 16, text_va)
    off = start - text_va
    body = text_data[off:off + 32]
    for insn in md.disasm(body, start):
        if insn.address <= byte_va < insn.address + insn.size:
            if f'0x{imm_val:x}' in insn.op_str:
                return {'insn_va': insn.address, 'size': insn.size,
                        'mnem': insn.mnemonic, 'op_str': insn.op_str,
                        'bytes': insn.bytes.hex()}
    return None


def main():
    print('[*] loading PE …', flush=True)
    pe, ib, text_va, text_data = load_pe()
    print(f'    image_base=0x{ib:08x}  text_va=0x{text_va:08x}  size=0x{len(text_data):x}')

    print('[*] building prologue index …', flush=True)
    pros = build_prologue_index(text_data, text_va)
    print(f'    unique prologues in .text = {len(pros)}')

    print('[*] byte-scanning immediates in pool range …', flush=True)
    byte_hits = scan_bytes(text_data, text_va)
    print(f'    raw byte-hits = {len(byte_hits)}')

    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False
    print('[*] capstone verifying + bisect fn-owner …', flush=True)
    verified = []
    for h in byte_hits:
        ins = find_containing_insn(md, text_va, text_data, h['byte_va'], h['imm_val'])
        if not ins: continue
        # bisect：<= insn_va 的最大 prologue
        idx = bisect.bisect_right(pros, ins['insn_va']) - 1
        if idx < 0:
            fn_va = None
        else:
            fn_va = pros[idx]
        h['insn'] = ins
        h['fn_va'] = fn_va
        h['fn_rva'] = (fn_va - ib) if fn_va else None
        h['pool_off'] = h['imm_val'] - POOL_BASE_RVA
        verified.append(h)
    print(f'    verified = {len(verified)}')

    # cross-ref with callchain
    chain_json = sorted([p for p in OUT_DIR.glob('callchain_*.json')
                         if 'trace' not in p.name and 'flat' not in p.name],
                        key=lambda p: p.stat().st_mtime, reverse=True)
    chain_fns = {}
    if chain_json:
        j = json.loads(chain_json[0].read_text(encoding='utf-8'))
        for fn in j['functions']:
            chain_fns[fn['va']] = fn['depth']
        print(f'[*] cross-ref against {chain_json[0].name} ({len(chain_fns)} fns)')

    for h in verified:
        h['depth'] = chain_fns.get(h['fn_va']) if h['fn_va'] else None
        h['on_presend_chain'] = h['depth'] is not None

    # 按 fn 聚合
    per_fn = {}
    for h in verified:
        key = h['fn_va'] if h['fn_va'] else 0
        per_fn.setdefault(key, []).append(h)
    fn_summary = []
    for fn_va, hs in per_fn.items():
        offs = sorted({h['pool_off'] for h in hs})
        insns = list({f"{h['insn']['mnem']} {h['insn']['op_str']}" for h in hs})[:5]
        fn_summary.append({
            'fn_va': fn_va,
            'fn_rva': (fn_va - ib) if fn_va else None,
            'n_hits': len(hs),
            'n_unique_offs': len(offs),
            'depth': hs[0].get('depth'),
            'on_presend_chain': hs[0].get('on_presend_chain', False),
            'off_min': offs[0] if offs else None,
            'off_max': offs[-1] if offs else None,
            'pool_offsets_sample': offs[:8],
            'sample_insns': insns,
        })
    # 排序：先 on_chain，再按 unique_offs（enumerator 特征），再 hits
    fn_summary.sort(key=lambda x: (not x['on_presend_chain'], -x['n_unique_offs'], -x['n_hits']))

    out = {
        'meta': {'exe': str(WXWORK), 'image_base': ib, 'pool_base_rva': POOL_BASE_RVA,
                 'pool_width': POOL_WIDTH, 'ts': ts,
                 'n_prologues': len(pros),
                 'n_byte_hits': len(byte_hits), 'n_verified': len(verified),
                 'n_unique_fns': len(per_fn)},
        'per_fn': fn_summary,
        'raw': verified,
    }
    p = OUT_DIR / f'xref_typeurl_v2_{ts}.json'
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[+] wrote {p.name}  ({len(fn_summary)} unique fns)')

    print(f'\n=== TOP 30 fns by (on_chain, unique_pool_offsets, hits) ===')
    print(f'{"fn_rva":<12} {"chain":<7} {"d":<3} {"hits":<5} {"uniq_off":<9} {"off_range":<20} sample_insn')
    for f in fn_summary[:30]:
        chain = '★CHAIN' if f['on_presend_chain'] else ''
        d = str(f['depth']) if f['depth'] is not None else '-'
        rva = f'0x{f["fn_rva"]:08x}' if f['fn_rva'] else '(no_prol)'
        rng = f'+0x{f["off_min"]:x}..+0x{f["off_max"]:x}' if f['off_min'] is not None else ''
        si = (f['sample_insns'][0][:60] + '…') if f['sample_insns'] and len(f['sample_insns'][0])>60 else (f['sample_insns'][0] if f['sample_insns'] else '')
        print(f'{rva:<12} {chain:<7} {d:<3} {f["n_hits"]:<5} {f["n_unique_offs"]:<9} {rng:<20} {si}')


if __name__ == '__main__':
    main()
