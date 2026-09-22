"""定位 cmd 0x602 (=1538) 的所有 mov/cmp 站点，并反汇编所在函数。

已知 §47.16.14: RVA 0x1cc12e 有 `mov dword ptr [ebp-4], 0x602`。
本脚本：
- 全 .text 扫描 `C7 45 XX 02 06 00 00`（mov [ebp+disp], 0x602）
- 全 .text 扫描 `C7 44 24 XX 02 06 00 00`（mov [esp+disp], 0x602）
- 全 .text 扫描 `68 02 06 00 00`（push 0x602）
- 全 .text 扫描 `3D 02 06 00 00`（cmp eax, 0x602）
- 全 .text 扫描 `81 3D 02 06 00 00`（cmp dword, 0x602）不太靠谱先跳过
- 对每个命中：回溯找函数起点（扫上一段 `int 3 int 3 55 8B EC` 或 `int 3 int 3 push ebp`），反汇编前 200 条 insn，抽字符串
"""
import pefile
import re
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000
KEYWORDS = ["voice_time","cdn_key","aes_key","SILK","silk","SendVoice","send_voice",
            "voice","Voice","ITEM_VOICE","0602","cmd_602","msg_type","MsgType","content_type",
            "PostSend","upload","Upload","cdn","CDN","emoji"]


def load_sections(pe):
    return [
        (s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
         IB + s.VirtualAddress,
         IB + s.VirtualAddress + len(s.get_data()),
         s.get_data())
        for s in pe.sections
    ]


def read_at(secs, va, n):
    for name, s, e, data in secs:
        if s <= va < e:
            return data[va - s : va - s + n]
    return b""


def is_str_at(secs, va, minlen=4, maxlen=256):
    data = read_at(secs, va, maxlen)
    if not data: return None
    end = data.find(b"\x00")
    if end < minlen: return None
    s = data[:end]
    try: s.decode("ascii")
    except UnicodeDecodeError: return None
    if not all(0x20 <= b < 0x7F or b in (9,10,13) for b in s): return None
    return s.decode("ascii")


def find_fn_start(text_data, text_va, va, back=0x2000):
    """From va, walk back to find function prologue: `CC CC 55 8B EC` or `CC CC 8B FF 55 8B EC`."""
    off = va - text_va
    lo = max(0, off - back)
    seg = text_data[lo:off]
    # look for `CC CC` followed by push ebp/mov ebp,esp OR mov edi,edi
    # patterns: b'\xcc\xcc\x55\x8b\xec' or b'\xcc\xcc\x8b\xff\x55\x8b\xec' or `\xcc\xcc\x53\x56\x57` etc
    for pat in [b'\xcc\xcc\x55\x8b\xec', b'\xcc\xcc\x8b\xff\x55\x8b\xec', b'\xcc\xcc\x8b\xff', b'\xcc\xcc\x55']:
        idx = seg.rfind(pat)
        if idx >= 0:
            fn_off = lo + idx + 2  # skip the CC CC padding
            return text_va + fn_off
    return None


def analyze_fn(md, secs, text_data, text_va, fn_start, max_insn=400):
    data = read_at(secs, fn_start, 16384)
    strings = []
    calls = []
    for i, insn in enumerate(md.disasm(data, fn_start)):
        if i >= max_insn: break
        if insn.mnemonic == "call":
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    calls.append(op.imm)
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if 0x400000 <= v < 0x40000000:
                    s = is_str_at(secs, v)
                    if s and s not in strings: strings.append(s)
        # stop at ret+CC
        if insn.mnemonic.startswith("ret"):
            nxt = read_at(secs, insn.address + insn.size, 4)
            if nxt and nxt[0] == 0xCC:
                break
    return strings, calls


def main():
    print("[*] loading PE...")
    pe = pefile.PE(PE_PATH, fast_load=True)
    secs = load_sections(pe)
    text_name, text_va, text_end, text_data = next(x for x in secs if x[0] == ".text")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # patterns
    patterns = {
        # mov [ebp+disp], 0x602 : C7 45 XX 02 06 00 00
        "mov [ebp+disp8], 0x602": rb"\xC7\x45.\x02\x06\x00\x00",
        # mov [esp+disp], 0x602 : C7 44 24 XX 02 06 00 00
        "mov [esp+disp8], 0x602": rb"\xC7\x44\x24.\x02\x06\x00\x00",
        # push 0x602 : 68 02 06 00 00
        "push 0x602":              rb"\x68\x02\x06\x00\x00",
        # cmp eax, 0x602 : 3D 02 06 00 00
        "cmp eax, 0x602":          rb"\x3D\x02\x06\x00\x00",
        # mov reg, 0x602 : B8/B9/BA... 02 06 00 00 (mov r32, imm32 uses B8+r)
        "mov r32, 0x602":          rb"[\xB8-\xBF]\x02\x06\x00\x00",
    }

    hits = []  # list of (pattern_name, va)
    for name, pat in patterns.items():
        for m in re.finditer(pat, text_data):
            va = text_va + m.start()
            hits.append((name, va))
    print(f"[+] total pattern hits: {len(hits)}")

    # dedupe + analyze
    seen_fn = set()
    fn_reports = []
    for name, va in hits:
        fn_start = find_fn_start(text_data, text_va, va)
        if fn_start is None:
            continue
        if fn_start in seen_fn:
            continue
        seen_fn.add(fn_start)
        strings, calls = analyze_fn(md, secs, text_data, text_va, fn_start)
        score = sum(1 for s in strings for kw in KEYWORDS if kw in s)
        fn_reports.append({
            "fn_rva": fn_start - IB,
            "hit_va": va,
            "hit_pat": name,
            "strings": strings,
            "ncalls": len(calls),
            "score": score,
        })

    # sort by score desc
    fn_reports.sort(key=lambda r: (-r["score"], -len(r["strings"])))

    print(f"\n[+] unique functions with 0x602 usage: {len(fn_reports)}")
    print("=" * 90)
    for r in fn_reports:
        print(f"\nfn wx+0x{r['fn_rva']:08x}  hit@wx+0x{r['hit_va']-IB:08x} ({r['hit_pat']})  score={r['score']}  strs={len(r['strings'])}  ncalls={r['ncalls']}")
        for s in r["strings"][:25]:
            kw = ""
            for k in KEYWORDS:
                if k in s: kw = f" ★{k}"; break
            print(f"    {s[:120]!r}{kw}")


if __name__ == "__main__":
    main()
