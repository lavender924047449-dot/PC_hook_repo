# _g3_disasm_high.py — 高层 serialize 函数完整反汇编
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = IB + s.VirtualAddress
        text_data = s.get_data()
        break
md = Cs(CS_ARCH_X86, CS_MODE_32)

def find_pro(rva, max_back=0x1000):
    off = (IB + rva) - text_va
    for back in range(0, max_back):
        o = off - back
        if o < 1: break
        if text_data[o:o+3] == b'\x55\x8b\xec' and text_data[o-1] in (0xCC, 0xC3, 0x90):
            return text_va + o
        if o >= 3 and text_data[o:o+3] == b'\x55\x8b\xec' and text_data[o-3] == 0xC2:
            return text_va + o
    return None

def dump_fn(rva, tag, maxb=512):
    va = IB + rva
    pro = find_pro(rva)
    print('='*80)
    print(f'{tag}  hit_rva=0x{rva:x}  pro_rva=0x{(pro-IB) if pro else 0:x}')
    start = pro or (va - 32)
    off = start - text_va
    n = 0
    for insn in md.disasm(text_data[off:off+maxb], start):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        mark = ''
        if insn.address == va: mark = '  <<< HIT'
        print(f'  0x{insn.address:08x} rva+{insn.address-IB:x}  {raw:<24} {insn.mnemonic} {insn.op_str}{mark}')
        n += 1
        if insn.mnemonic == 'ret' and n > 8:
            # 第一个 ret 之后若 HIT 已过就停
            if insn.address >= va or n > 80:
                break
        if n > 90:
            print('  ...')
            break
    print()

dump_fn(0x15a0e13, 'bt3 0x15a0e13', 700)
dump_fn(0x1589e65, 'bt5 0x1589e65', 700)
dump_fn(0x9937f10, 'WriteString-like 0x9937f10', 400)
dump_fn(0x9933d40, 'WriteRaw 0x9933d40', 200)
