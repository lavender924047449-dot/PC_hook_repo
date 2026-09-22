# xref_typeurl_pool.py — 在 WXWork.exe .text 里 xref 静态 type_url pool 地址
#
# 目标：`0xb0901ac` = `ww_richmessage.Extra*` type_url pool（§47.11.5 锁定）
# 假设：ConstructMessageProtobuf 本尊会把这个池的元素拷进输出 buffer
#   → 会在指令里以 immediate 出现（`push 0xb0901ac` / `mov reg, 0xb0901ac` /
#      `lea reg, [0xb0901ac]` / `mov reg, [0xb0901ac+i*4]`）
#
# 策略：
#   1. 两遍搜索：
#      a) 字节级：LE bytes `AC 01 09 0B`（宽粗，捕获所有 immediate/displacement 出现位置）
#      b) capstone：以字节命中的 va 为中心 -16 反汇编 32 字节，取出真正含该 immediate 的指令
#   2. 目标 RVA 展宽到 [0xb0901ac, 0xb0902ac]（池头 + 256B 尾部），因为编译器可能用
#      `0xb0901ac + i*4` 的 base+idx 寻址，或直接引用池中间的某条 entry
#   3. 对每个 hit，反查所属函数（linear-sweep backward 找 prologue 0x55 0x8b 0xec）
#   4. 交叉：与 callchain_*.json 的 688 fn 名单核对，若命中 depth 1..5 里的 fn 高亮
#
# 产物：xref_typeurl_<ts>.json（结构化） + 控制台 top 20

import sys, json, re
from pathlib import Path
from datetime import datetime
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

WXWORK = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
POOL_BASE_RVA = 0x0b0901ac
POOL_WIDTH    = 0x1000     # 覆盖到 +4KB（type_url 表 8KB，其中前 4KB 里大部分 entry 是指向字符串的指针）
BACK_SCAN_MAX = 32         # capstone 反汇编时向前多扫的字节

ts = datetime.now().strftime('%Y%m%d_%H%M%S')


def load_pe():
    pe = pefile.PE(str(WXWORK), fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b'\x00') == b'.text':
            text = s; break
    if not text: raise RuntimeError('no .text')
    text_rva = text.VirtualAddress
    text_data = text.get_data()
    text_va = ib + text_rva
    return pe, ib, text_va, text_rva, text_data


def scan_bytes(text_data, text_va):
    """粗扫：所有 LE-4 immediate 落在 [POOL_BASE, POOL_BASE+POOL_WIDTH) 的字节位置"""
    hits = []
    # 目标 LE 4 字节的第一个字节固定，先按此扫再验证高位
    # 但因为 POOL_WIDTH 大，直接遍历
    for off in range(len(text_data) - 3):
        val = (text_data[off]
               | (text_data[off+1] << 8)
               | (text_data[off+2] << 16)
               | (text_data[off+3] << 24))
        if POOL_BASE_RVA <= val < POOL_BASE_RVA + POOL_WIDTH:
            hits.append({'byte_va': text_va + off, 'imm_val': val})
    return hits


def find_containing_insn(md, text_va, text_data, byte_va, imm_val):
    """从 byte_va - BACK_SCAN_MAX 反汇编 BACK_SCAN_MAX*2，找出包含 imm_val 的指令"""
    start = max(byte_va - BACK_SCAN_MAX, text_va)
    off = start - text_va
    length = min(BACK_SCAN_MAX * 2, len(text_data) - off)
    body = text_data[off:off + length]
    best = None
    for insn in md.disasm(body, start):
        # 命中：指令覆盖 byte_va（起始 <= byte_va <= end），且 op_str 里含该 immediate
        if insn.address <= byte_va < insn.address + insn.size:
            hex_imm = f'0x{imm_val:x}'
            if hex_imm in insn.op_str:
                best = {
                    'insn_va': insn.address, 'size': insn.size,
                    'mnem': insn.mnemonic, 'op_str': insn.op_str,
                    'bytes': insn.bytes.hex(),
                }
                break
    return best


def find_containing_fn(text_data, text_va, insn_va, max_back=0x4000):
    """向前扫 prologue `55 8B EC`（前一字节 C3/C2/CC）作为函数起点，最多回 16KB"""
    end_off = insn_va - text_va
    start = max(end_off - max_back, 0)
    for off in range(end_off - 3, start - 1, -1):
        if (text_data[off] == 0x55 and text_data[off+1] == 0x8b and text_data[off+2] == 0xec
                and (off == 0 or text_data[off-1] in (0xc3, 0xcc, 0xc2))):
            return text_va + off
    return None


def main():
    print(f'[*] loading PE …', flush=True)
    pe, ib, text_va, text_rva, text_data = load_pe()
    print(f'    image_base=0x{ib:08x}  text_va=0x{text_va:08x}  size=0x{len(text_data):x}')

    print(f'[*] byte-scan for immediate in [0x{POOL_BASE_RVA + ib:08x}, 0x{POOL_BASE_RVA + ib + POOL_WIDTH:08x}) …', flush=True)
    byte_hits = scan_bytes(text_data, text_va)
    print(f'    raw byte-hits = {len(byte_hits)}')

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    print(f'[*] capstone verify + function-owner resolve …', flush=True)
    verified = []
    for i, h in enumerate(byte_hits):
        ins = find_containing_insn(md, text_va, text_data, h['byte_va'], h['imm_val'])
        if not ins: continue
        fn_va = find_containing_fn(text_data, text_va, ins['insn_va'])
        h['insn'] = ins
        h['fn_va'] = fn_va
        h['fn_rva'] = (fn_va - ib) if fn_va else None
        h['pool_off'] = h['imm_val'] - POOL_BASE_RVA
        verified.append(h)
        if (i+1) % 500 == 0:
            print(f'    verified {i+1}/{len(byte_hits)} …', flush=True)
    print(f'[+] verified insn-level hits = {len(verified)}')

    # 与 callchain 交叉
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
        if h['fn_va'] is not None and h['fn_va'] in chain_fns:
            h['depth'] = chain_fns[h['fn_va']]
            h['on_presend_chain'] = True
        else:
            h['depth'] = None
            h['on_presend_chain'] = False

    # 按 fn 聚合
    per_fn = {}
    for h in verified:
        key = h['fn_va'] if h['fn_va'] else 0
        per_fn.setdefault(key, []).append(h)
    fn_summary = []
    for fn_va, hs in per_fn.items():
        fn_summary.append({
            'fn_va': fn_va,
            'fn_rva': (fn_va - ib) if fn_va else None,
            'n_hits': len(hs),
            'depth': hs[0].get('depth'),
            'on_presend_chain': hs[0].get('on_presend_chain', False),
            'pool_offsets': sorted({h['pool_off'] for h in hs}),
            'sample_insns': [f"{h['insn']['mnem']} {h['insn']['op_str']}" for h in hs[:5]],
        })
    fn_summary.sort(key=lambda x: (not x['on_presend_chain'], -x['n_hits']))

    # 输出
    out = {
        'meta': {'exe': str(WXWORK), 'image_base': ib, 'pool_base_rva': POOL_BASE_RVA,
                 'pool_width': POOL_WIDTH, 'ts': ts,
                 'n_byte_hits': len(byte_hits), 'n_verified': len(verified),
                 'n_unique_fns': len(per_fn)},
        'per_fn': fn_summary,
        'raw': verified,
    }
    p = OUT_DIR / f'xref_typeurl_{ts}.json'
    p.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[+] wrote {p.name}  ({len(fn_summary)} unique fns)')

    print(f'\n=== TOP 25 fns by hit-count (on-chain first) ===')
    print(f'{"fn_rva":<12} {"chain":<7} {"depth":<5} {"hits":<5} {"pool_offs (bytes into 0xb0901ac)":<40} sample_insn')
    for f in fn_summary[:25]:
        chain = '★CHAIN' if f['on_presend_chain'] else ''
        d = str(f['depth']) if f['depth'] is not None else '-'
        rva = f'0x{f["fn_rva"]:08x}' if f['fn_rva'] else '(no_proluge)'
        pos = ','.join(f'+0x{o:x}' for o in f['pool_offsets'][:6])
        si = f['sample_insns'][0] if f['sample_insns'] else ''
        print(f'{rva:<12} {chain:<7} {d:<5} {f["n_hits"]:<5} {pos:<40} {si}')


if __name__ == '__main__':
    main()
