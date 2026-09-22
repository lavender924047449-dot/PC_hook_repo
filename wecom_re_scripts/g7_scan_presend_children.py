"""批量反汇编 PreSend (wx+0x0919ffb2) 的 30 个下游函数，抽字符串，按语音关键字打分排序。

方法：
- 先反汇编 PreSend 自身，收集所有 `call imm` 目标（in .text）
- 对每个目标：
  * 找函数边界（walk to ret+cc padding，最多 32KB）
  * 收集所有 immediate 引用的 .rdata 字符串
  * 收集所有 `call imm` 的下一层函数（用于后续深挖）
  * 按语音关键字打分：voice / SILK / silk / cdn_key / aes_key / voice_time / 0602 / Voice / ITEM_VOICE / SendVoice / send_voice
- 输出按分数降序 + 每个函数展示 top 20 strings

不再反汇编 PreSend 自身以外的函数超过 3000 insn。
"""
import pefile
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000
PRESEND_RVA = 0x0919ffb2
MAX_INSN_PER_FN = 3000
MAX_FN_BYTES = 32768

KEYWORDS = {
    "voice_time": 10,
    "cdn_key":    10,
    "aes_key":    10,
    "SendVoice":  10,
    "send_voice": 10,
    "ITEM_VOICE": 10,
    "SILK":        8,
    "silk":        8,
    "0602":        6,
    "0x602":       6,
    "voice":       4,
    "Voice":       4,
    "VoiceMessage":15,
    "VoiceContent":15,
    "audio":       2,
    "Audio":       2,
    "msg_type":    1,
    "MsgType":     1,
    "content_type":1,
    "SendMsg":     1,
    "PreSend":     1,
}


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


def is_in_text(secs, va):
    for name, s, e, _ in secs:
        if name == ".text" and s <= va < e:
            return True
    return False


def is_str_at(secs, va, minlen=4, maxlen=256):
    data = read_at(secs, va, maxlen)
    if not data:
        return None
    end = data.find(b"\x00")
    if end < minlen:
        return None
    s = data[:end]
    try:
        s.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in s):
        return None
    return s.decode("ascii")


def find_fn_end(md, secs, start_va, limit=MAX_FN_BYTES):
    data = read_at(secs, start_va, limit)
    end_va = start_va
    hit_ret = False
    n = 0
    for insn in md.disasm(data, start_va):
        n += 1
        if n > MAX_INSN_PER_FN:
            break
        end_va = insn.address + insn.size
        m = insn.mnemonic
        if m.startswith("ret"):
            hit_ret = True
            nxt = read_at(secs, end_va, 4)
            if nxt and nxt[0] == 0xCC:
                break
        elif hit_ret:
            if m not in ("nop", "int3"):
                break
    return end_va


def analyze(pe, secs, md, rva):
    start_va = IB + rva
    end_va = find_fn_end(md, secs, start_va)
    size = end_va - start_va
    data = read_at(secs, start_va, size)
    strings = []
    calls = Counter()
    insn_n = 0
    for insn in md.disasm(data, start_va):
        insn_n += 1
        if insn_n > MAX_INSN_PER_FN:
            break
        if insn.mnemonic == "call":
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    tgt = op.imm
                    if is_in_text(secs, tgt):
                        calls[tgt] += 1
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                v = op.imm & 0xFFFFFFFF
                if 0x400000 <= v < 0x40000000:
                    s = is_str_at(secs, v)
                    if s:
                        strings.append(s)
    # dedupe strings but preserve order
    seen = set()
    uniq = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return size, insn_n, uniq, calls


def score(strings):
    total = 0
    hits = []
    for s in strings:
        low = s
        for kw, w in KEYWORDS.items():
            if kw in low:
                total += w
                hits.append((kw, s[:80]))
    return total, hits


def main():
    print("[*] loading PE...")
    pe = pefile.PE(PE_PATH, fast_load=True)
    secs = load_sections(pe)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # 1) enumerate PreSend children
    _, _, _, pre_calls = analyze(pe, secs, md, PRESEND_RVA)
    children = list(pre_calls.keys())
    print(f"[+] PreSend has {len(children)} unique call targets in .text")

    # 2) analyze each child
    rows = []
    for tgt in children:
        rva = tgt - IB
        try:
            size, insn_n, strs, calls = analyze(pe, secs, md, rva)
            sc, hits = score(strs)
            rows.append({
                "rva": rva,
                "size": size,
                "insn": insn_n,
                "nstrs": len(strs),
                "score": sc,
                "kw_hits": hits,
                "strings_top": strs[:15],
                "n_calls": len(calls),
                "calls_top": [t - IB for t, _ in calls.most_common(8)],
            })
        except Exception as e:
            rows.append({"rva": rva, "err": str(e)})

    # 3) EXPAND: for each depth-1 child, also analyze all its depth-2 children
    print("\n[*] expanding depth-2...")
    seen_rva = set(r["rva"] for r in rows)
    seen_rva.add(PRESEND_RVA)
    d2_rows = []
    for r in rows:
        if r.get("err"): continue
        for ctgt_rva in r.get("calls_top", []):
            if ctgt_rva in seen_rva: continue
            seen_rva.add(ctgt_rva)
            try:
                size, insn_n, strs, calls = analyze(pe, secs, md, ctgt_rva)
                sc, hits = score(strs)
                d2_rows.append({
                    "rva": ctgt_rva,
                    "parent": r["rva"],
                    "size": size,
                    "insn": insn_n,
                    "nstrs": len(strs),
                    "score": sc,
                    "kw_hits": hits,
                    "strings_top": strs[:15],
                    "n_calls": len(calls),
                })
            except Exception as e:
                pass
    print(f"[+] depth-2: {len(d2_rows)} additional functions")

    all_rows = rows + d2_rows
    all_rows.sort(key=lambda r: (-r.get("score", 0), -r.get("size", 0)))
    rows = all_rows

    print("\n" + "=" * 90)
    print(f"{'RVA':<14} {'score':>5} {'size':>7} {'insn':>5} {'nstr':>4} {'ncall':>5}  top strings / kw hits")
    print("=" * 90)
    for r in rows:
        rva = r["rva"]
        if r.get("err"):
            print(f"wx+0x{rva:08x}  ERR: {r['err']}")
            continue
        parent_tag = f"  <-parent=wx+0x{r['parent']:08x}" if r.get("parent") else "  <-PreSend"
        print(f"wx+0x{rva:08x}  {r['score']:>5} {r['size']:>7} {r['insn']:>5} {r['nstrs']:>4} {r['n_calls']:>5} {parent_tag}")
        if r["kw_hits"]:
            for kw, s in r["kw_hits"][:8]:
                print(f"    ★ kw={kw:12}  \"{s}\"")
        else:
            for s in r["strings_top"][:5]:
                print(f"      {s!r}")

    # 4) also flag: any child that recursively calls something with score
    print("\n" + "=" * 90)
    print("Children with kw hits (score>0):")
    for r in rows:
        if r.get("score", 0) > 0:
            print(f"  wx+0x{r['rva']:08x}  score={r['score']}  size={r['size']}  n_kw={len(r['kw_hits'])}")


if __name__ == "__main__":
    main()
