# _disasm_fn.py — 反汇编指定 VA 前 256 字节
import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

WXWORK = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(WXWORK, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va = IB + s.VirtualAddress
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False

def disasm(va, n=256, tag=''):
    off = va - text_va
    if off < 0 or off + n > len(text_data):
        print(f'{tag} VA=0x{va:x} out of .text'); return
    body = text_data[off:off+n]
    print(f'\n=== {tag}  VA=0x{va:08x}  RVA=0x{va-IB:08x}  ===')
    for insn in md.disasm(body, va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  0x{insn.address:08x}  {raw:<28} {insn.mnemonic} {insn.op_str}')
        if insn.mnemonic in ('ret', 'retn') or (insn.mnemonic == 'jmp' and 'x' not in insn.op_str[0:2]):
            break

# 目标
for va, tag in [
    (0x9f042a0, 'PTR_A (0x9f042a0 = 76-shared fn)'),
    (0x9f03c40, 'PTR_B (0x9f03c40 = 76-shared fn)'),
    # 调用者所在函数：ret_addr = 0x9f036ed / 0x9f043a6 → 调用位置前几字节
    (0x9f036e0, 'caller-site around A ret 0x9f036ed'),
    (0x9f04390, 'caller-site around B ret 0x9f043a6'),
]:
    disasm(va, 256, tag)
