"""静态反汇编 wx+0x0919eaa0 (A_d1_root) 及 wx+0x09926c00 (BeginSendMsg)。

目标：
- 看 A_d1_root 内部有几个大分支（switch/jt/vtable[N]）
- 看它读了哪些 arg 字段（args[0]->+offset），推断结构体形状
- 提取它内部引用到的字符串常量（识别是不是 SendMessage 相关逻辑）
- 拉出它 CALL 的下一层函数 RVA 列表，为下一步跟踪 voice 分支做准备
"""
import pefile
import struct
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

TARGETS = [
    (0x0919eaa0, "A_d1_root"),
    (0x09926c00, "BeginSendMsg"),
    (0x09926cc0, "C_d4"),
    (0x0919ffb2, "PreSend"),  # for reference
]

MAX_INSN = 500  # ~2-3KB of code
MAX_STRLEN = 200


def load_sections(pe):
    """Return list of (name, va_start, va_end, data). Also .rdata slice for strings."""
    secs = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        va = IB + s.VirtualAddress
        data = s.get_data()
        secs.append((name, va, va + len(data), data))
    return secs


def read_at(secs, va, n):
    for name, s, e, data in secs:
        if s <= va < e:
            off = va - s
            return data[off : off + n]
    return b""


def is_in_text(secs, va):
    for name, s, e, _ in secs:
        if name == ".text" and s <= va < e:
            return True
    return False


def is_readable_string_at(secs, va, minlen=4, maxlen=MAX_STRLEN):
    """Return decoded ASCII string if VA points to a printable C-string >= minlen chars."""
    data = read_at(secs, va, maxlen)
    if not data:
        return None
    # find null
    end = data.find(b"\x00")
    if end < 0:
        return None
    if end < minlen:
        return None
    s = data[:end]
    try:
        s2 = s.decode("ascii")
    except UnicodeDecodeError:
        return None
    # must be mostly printable
    if not all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in s):
        return None
    return s2


def find_function_end(md, secs, start_va, limit=8192):
    """Rough: walk instructions until we hit a RET followed by INT3 padding or another PROC-like start."""
    data = read_at(secs, start_va, limit)
    end_va = start_va
    hit_ret = False
    for insn in md.disasm(data, start_va):
        end_va = insn.address + insn.size
        m = insn.mnemonic
        if m.startswith("ret"):
            hit_ret = True
            # peek next 4 bytes for INT3 padding
            nxt = read_at(secs, end_va, 4)
            if nxt and nxt[0] == 0xCC:
                break
        elif hit_ret:
            # if we see meaningful code after a ret, we crossed function boundary
            if m not in ("nop", "int3"):
                # take previous end
                break
    return end_va


def analyze_function(pe, secs, md, rva, label):
    start_va = IB + rva
    print(f"\n{'='*80}\n=== {label} @ wx+0x{rva:08x}  VA=0x{start_va:08x} ===\n{'='*80}")

    end_va = find_function_end(md, secs, start_va, limit=32768)
    size = end_va - start_va
    print(f"[fn size ~= {size} bytes]")

    data = read_at(secs, start_va, size)
    if not data:
        print("  <no data>")
        return

    call_targets = Counter()
    jmp_targets = Counter()
    string_refs = []
    arg_reads = Counter()          # [ebp+8/+c/+10/...] source-side
    this_reads = Counter()         # [ecx+X], [esi+X] with esi holding this
    imm_consts = Counter()         # small immediates that look interesting
    switch_like = []               # jmp [table+eax*4]
    total_insn = 0

    for insn in md.disasm(data, start_va):
        total_insn += 1
        mnem = insn.mnemonic
        op_str = insn.op_str

        # calls / jumps
        if mnem == "call":
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    call_targets[op.imm] += 1
        elif mnem.startswith("j") and mnem != "jmp":
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    jmp_targets[op.imm] += 1
        elif mnem == "jmp":
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    jmp_targets[op.imm] += 1
                elif op.type == CS_OP_MEM:
                    # jmp [disp + reg*scale]
                    if op.mem.base != 0 and op.mem.scale >= 2:
                        switch_like.append((insn.address, op_str))

        # string ref: any immediate that lands in .rdata as a printable string
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if 0x400000 <= v < 0x40000000:
                    s = is_readable_string_at(secs, v, minlen=5)
                    if s:
                        string_refs.append((insn.address, v, s[:80]))
                imm_consts[v] += 1
            elif op.type == CS_OP_MEM:
                # mov reg, [ebp + N]  = arg read
                if op.mem.base != 0 and op.mem.disp != 0 and op.mem.index == 0:
                    base_name = insn.reg_name(op.mem.base)
                    disp = op.mem.disp
                    if base_name == "ebp":
                        arg_reads[disp] += 1
                    elif base_name in ("ecx", "esi", "edi"):
                        # heuristic: field access on this-ptr
                        if -0x1000 <= disp <= 0x10000:
                            this_reads[(base_name, disp)] += 1

    print(f"[insn count: {total_insn}]")
    print(f"[calls (unique targets): {len(call_targets)}]")
    print(f"[cond jumps: {sum(jmp_targets.values())}]")
    print(f"[switch-like jmp [reg*N + disp]: {len(switch_like)}]")

    # ---------- args (from stdcall/cdecl frame layout) ----------
    print("\n[ARG READS (mov/... [ebp + N])]")
    for disp in sorted(arg_reads.keys()):
        count = arg_reads[disp]
        if disp >= 8:
            argnum = (disp - 8) // 4
            print(f"  [ebp+0x{disp:x}]  arg{argnum}   count={count}")
        elif disp < 0:
            print(f"  [ebp-0x{-disp:x}] local     count={count}")

    # ---------- this-ptr field reads ----------
    print("\n[THIS-PTR FIELD READS (top 20)]")
    for (reg, disp), c in this_reads.most_common(20):
        if disp >= 0:
            print(f"  [{reg}+0x{disp:x}]  count={c}")
        else:
            print(f"  [{reg}-0x{-disp:x}] count={c}")

    # ---------- string refs ----------
    print(f"\n[STRING REFS: {len(string_refs)} total]")
    seen = set()
    for addr, v, s in string_refs:
        if s in seen:
            continue
        seen.add(s)
        print(f"  @0x{addr:08x}  \"{s}\"")
        if len(seen) >= 40:
            print(f"  ... ({len(string_refs) - len(seen)} more)")
            break

    # ---------- callees ----------
    print(f"\n[CALL TARGETS: {len(call_targets)} unique, top 25 by count]")
    for tgt, c in call_targets.most_common(25):
        if is_in_text(secs, tgt):
            rva_t = tgt - IB
            marker = " *IN.text" if is_in_text(secs, tgt) else ""
            print(f"  wx+0x{rva_t:08x}  (VA 0x{tgt:08x})  ×{c}{marker}")
        else:
            print(f"  0x{tgt:08x} (external?)  ×{c}")

    # ---------- switch tables ----------
    if switch_like:
        print(f"\n[SWITCH-LIKE JMP {len(switch_like)}]")
        for addr, opstr in switch_like[:10]:
            print(f"  @0x{addr:08x}  jmp {opstr}")


def main():
    print("[*] Loading PE...")
    pe = pefile.PE(PE_PATH, fast_load=True)
    secs = load_sections(pe)
    print(f"[*] Sections: {[(n, hex(s), hex(e)) for n,s,e,_ in secs]}")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for rva, label in TARGETS:
        try:
            analyze_function(pe, secs, md, rva, label)
        except Exception as e:
            print(f"[!] {label}: {e}")


if __name__ == "__main__":
    main()
