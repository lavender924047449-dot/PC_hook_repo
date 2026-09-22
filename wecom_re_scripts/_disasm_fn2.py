# _disasm_fn2.py — 反汇编（修正 ASLR）
# 运行时 mod.base = 0x5e0000（Frida 报告），file preferred = 0x400000
# ASLR shift = +0x1e0000。所以 runtime_VA 转 file_offset：
#   preferred_VA = runtime_VA - 0x1e0000
#   file_offset  = preferred_VA - text_va_preferred (=0x401000)

import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

WXWORK = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
ASLR_SHIFT = 0x1e0000

pe = pefile.PE(WXWORK, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase   # 0x400000
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text_va_preferred = IB + s.VirtualAddress   # 0x401000
        text_data = s.get_data()
        break

md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = False

def disasm_runtime(rt_va, n=256, tag='', back=0):
    """rt_va = 运行时 abs VA；back = 向前多扫的字节数"""
    pref_va = rt_va - ASLR_SHIFT
    off = pref_va - text_va_preferred - back
    if off < 0 or off + n > len(text_data):
        print(f'{tag} rt_va=0x{rt_va:x} pref=0x{pref_va:x} off=0x{off:x} out of .text'); return
    body = text_data[off:off+n+back]
    disp_va = rt_va - back
    print(f'\n=== {tag}  rt_va=0x{rt_va:08x}  pref_va=0x{pref_va:08x}  file_off=0x{off:x}  ===')
    for insn in md.disasm(body, disp_va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        marker = ' ★' if insn.address == rt_va else ''
        print(f'  0x{insn.address:08x}  {raw:<26} {insn.mnemonic} {insn.op_str}{marker}')
        if insn.mnemonic in ('ret', 'retn'):
            break

for va, tag, back in [
    (0x9f042a0, 'PTR_A (76-shared)', 0),
    (0x9f03c40, 'PTR_B (76-shared)', 0),
    # ret_addr 附近（onEnter 时 returnAddress = 调用后返回处）
    (0x9f036ed, 'A caller ret site', 16),   # 反汇编前 16 字节看 CALL 指令
    (0x9f043a6, 'B caller ret site', 16),
]:
    disasm_runtime(va, 160, tag, back)
