# _g3_disasm_callers.py — 反汇编 G3 v2 memcpy 命中的 caller 链
import sys
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
WXWORK = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

pe = pefile.PE(WXWORK, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
text = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        text = s
        break
text_va = IB + text.VirtualAddress
text_data = text.get_data()
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def rva_to_off(rva):
    va = IB + rva
    return va, va - text_va

def find_prologue(rva, max_back=0x800):
    va, off = rva_to_off(rva)
    for back in range(0, max_back):
        o = off - back
        if o < 1:
            break
        # CC/C3/C2 then 55 8B EC
        prev = text_data[o-1]
        if text_data[o:o+3] == b'\x55\x8b\xec' and prev in (0xCC, 0xC3, 0xC2, 0x90):
            return IB + (text_va - IB) + o  # wait
    # simpler: scan backward for 55 8B EC
    for back in range(0, max_back):
        o = off - back
        if o < 1:
            break
        if text_data[o:o+3] == b'\x55\x8b\xec':
            if o == 0 or text_data[o-1] in (0xCC, 0xC3, 0x90, 0xC2):
                return text_va + o
            # also accept if previous is C2 xx xx
            if o >= 3 and text_data[o-3] == 0xC2:
                return text_va + o
    return None

def disasm_range(va, nbyte=180, stop_ret=False):
    off = va - text_va
    body = text_data[off:off+nbyte]
    lines = []
    for insn in md.disasm(body, va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        lines.append((insn, f'  0x{insn.address:08x} (rva+0x{insn.address-IB:x})  {raw:<24} {insn.mnemonic} {insn.op_str}'))
        if stop_ret and insn.mnemonic in ('ret',):
            break
    return lines

# Frida returnAddress ≈ instruction AFTER the call. So memcpy CALL is just before RVA.
TARGETS = [
    ('memcpy-ret  ★ proto 0a08[语音]', 0x9933daa),
    ('bt1', 0x9937fd3),
    ('bt2', 0x993806b),
    ('bt3 候选高层 serialize', 0x15a0e13),
    ('bt4', 0x99381f3),
    ('bt5 候选更上层', 0x1589e65),
    ('std::string? 0x1e91c7', 0x1e91c7),
    ('std::string? 0x1e966c', 0x1e966c),
]

print(f'image_base=0x{IB:08x}  .text VA=0x{text_va:08x}\n')

for tag, rva in TARGETS:
    va = IB + rva
    print('='*80)
    print(f'{tag}  RVA=0x{rva:x}  VA=0x{va:x}')
    pro = find_prologue(rva)
    if pro:
        print(f'  prologue @ VA=0x{pro:x}  RVA=0x{pro-IB:x}  (fn size ~{va-pro:#x} to ret-addr)')
    else:
        print('  prologue: not found in 0x800')
    # 反汇编 memcpy 调用点前 32B + 后 48B
    start = va - 24
    print('  --- around call/ret-addr ---')
    for insn, line in disasm_range(start, 80):
        mark = '  <<<' if insn.address == va else ''
        print(line + mark)
    if pro:
        print('  --- fn head 12 insns ---')
        for insn, line in disasm_range(pro, 64)[:12]:
            print(line)
    print()
