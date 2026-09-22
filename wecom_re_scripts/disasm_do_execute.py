# disasm_do_execute.py — P2 · 纯静态反汇编找 conversationId 字段偏移
# =============================================================================
#
# 前置发现（第二十四轮）：
#   Hook `0x34eea12` 等 PostSendMessageTask2 核心方法会触发企微 anti-tamper
#   自杀 → 换纯静态反汇编方案（零 hook 风险）
#
# 本脚本目标：
#   1. Attach WXWork（只读，无 Interceptor）
#   2. 对每个 log 字符串 xref 位点前 256 字节反汇编
#   3. 找 `mov r32, [ecx+imm]` / `lea r32, [ecx+imm]` / `push [ecx+imm]` 模式
#   4. 这些指令加载 `this->fieldX` 到 log 参数 → imm 就是字段偏移
#   5. 输出偏移候选（每个 log site 都会产生一批）
#
# 用法：& Python311 runtime/wecom_re/disasm_do_execute.py
# =============================================================================

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

# 每个 log call site 相对于 wxwork.exe base 的偏移（第二十四轮 find_do_execute.py 输出）
LOG_SITES = [
    ("0x2b7ec48", "PostSendMessageTask2 execte, conversationId = "),
    ("0x2b8abe5", "PostSendMessageTask2, need upload resource conversationId ="),
    ("0x2b9f835", "PostSendMessageTask2, upload resource conversationId ="),
    ("0x2b93984", "PostSendMessageTask2 SendMessage tmp_task_key"),
]

# 4 个函数入口
FN_ENTRIES = [
    ("0x2b7ea12", "DoExecute"),
    ("0x2b8ab12", "need_upload_resource"),
    ("0x2b9f772", "upload_resource"),
    ("0x2b934e2", "SendMessage_method"),
]

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg: 'wx base=' + WXBASE + ' size=0x' + wx.size.toString(16)});

// 反汇编从 startAddr 开始 n 条指令
function disasmRange(startAddr, nInstr){
    const results = [];
    let cur = startAddr;
    for (let i = 0; i < nInstr; i++){
        try {
            const insn = Instruction.parse(cur);
            results.push({
                va: cur.toString(),
                off: '0x' + cur.sub(WXBASE).toUInt32().toString(16),
                size: insn.size,
                mnem: insn.mnemonic,
                op: insn.opStr,
                str: insn.toString()
            });
            cur = cur.add(insn.size);
        } catch(e){
            results.push({va: cur.toString(), error: e.message});
            break;
        }
    }
    return results;
}

// 从 startAddr 向后线性反汇编 nInstr 条
// 但我们要"向前"到 log site，所以做法：从函数入口开始反汇编到 log site + 20，
// 然后取 log site 之前 30 条
function disasmFrom(fnEntryOff, targetSiteOff, tailN, headN){
    // fnEntry → walkthrough disassembly until we pass targetSite; keep last N insns
    const entryAddr = WXBASE.add(fnEntryOff);
    const targetAddr = WXBASE.add(targetSiteOff);
    const buf = [];
    let cur = entryAddr;
    const stopAt = targetAddr.add(headN * 8); // 大致偏移量
    let hitTarget = false;
    let insnsAfterTarget = 0;
    for (let i = 0; i < 10000; i++){
        try {
            const insn = Instruction.parse(cur);
            const cvOff = cur.sub(WXBASE).toUInt32();
            const tvOff = targetAddr.sub(WXBASE).toUInt32();
            // target 可能落在指令内部（imm32 的一部分），判定"包含 target"
            const contains = (cvOff <= tvOff && tvOff < cvOff + insn.size);
            buf.push({
                va: cur.toString(),
                off: '0x' + cvOff.toString(16),
                size: insn.size,
                mnem: insn.mnemonic,
                op: insn.opStr,
                str: insn.toString(),
                is_target: contains
            });
            if (contains) hitTarget = true;
            if (hitTarget){
                insnsAfterTarget++;
                if (insnsAfterTarget >= headN) break;
            }
            cur = cur.add(insn.size);
            // 防止走太远
            if (cur.sub(entryAddr).toUInt32() > 16384) break;
        } catch(e){
            buf.push({va: cur.toString(), error: e.message});
            // 出错时尝试跳一个字节继续（可能是数据混入代码）
            cur = cur.add(1);
            if (cur.sub(entryAddr).toUInt32() > 16384) break;
        }
    }
    // 找 target 指令位置，取前 tailN 条
    let targetIdx = -1;
    for (let i = 0; i < buf.length; i++){
        if (buf[i].is_target) { targetIdx = i; break; }
    }
    if (targetIdx < 0){
        // target 没找到（可能对齐问题），退化：返回全部
        return {found: false, insns: buf};
    }
    const start = Math.max(0, targetIdx - tailN);
    const end = Math.min(buf.length, targetIdx + headN + 1);
    return {found: true, target_index: targetIdx - start, insns: buf.slice(start, end)};
}

rpc.exports = {
    disasmAroundSite: function(fnEntryOff, siteOff, tailN, headN){
        return disasmFrom(parseInt(fnEntryOff, 16), parseInt(siteOff, 16),
                          tailN || 40, headN || 5);
    },
    disasmLinear: function(startOff, n){
        return disasmRange(WXBASE.add(parseInt(startOff, 16)), n || 60);
    },
    resolveExports: function(){
        return {base: WXBASE.toString(), size: wx.size};
    }
};
send({t:'ready'});
"""


def get_wxwork_pid() -> int:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.split()[-1])
    raise RuntimeError("WXWork.exe :9882 not listening")


def extract_reg_offsets(insns: list[dict], regs=("ecx", "esi", "edi", "ebx", "eax", "edx")) -> dict:
    """从反汇编列表里提取所有 [reg+imm] 的 imm 值，按寄存器分类。"""
    import re
    result: dict[str, list[tuple[int, str]]] = {r: [] for r in regs}
    pats = {r: re.compile(rf'\[{r}(?:\s*\+\s*(0x[0-9a-fA-F]+|\d+))?\]') for r in regs}
    for ins in insns:
        op = ins.get("op", "") or ""
        for r, pat in pats.items():
            m = pat.search(op)
            if m:
                imm_s = m.group(1)
                if imm_s:
                    imm = int(imm_s, 16) if imm_s.startswith("0x") else int(imm_s)
                else:
                    imm = 0
                result[r].append((imm, ins.get("str", "")))
    return result


def find_this_save(insns: list[dict]) -> str | None:
    """找函数入口 `mov [ebp-XX], ecx` (this 保存到栈的位置)。"""
    import re
    pat = re.compile(r'mov\s+dword ptr \[(ebp\s*-\s*0x[0-9a-fA-F]+)\],\s*ecx')
    # 只看前 15 条指令（函数序言范围）
    for ins in insns[:15]:
        s = ins.get("str", "")
        m = pat.search(s)
        if m:
            return m.group(1).replace(" ", "")
    return None


def main() -> int:
    pid = get_wxwork_pid()
    print(f"[*] attaching PID={pid} (READ-ONLY, no hooks)")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    # 对每个 log site，用它的对应函数入口做上下文反汇编
    # DoExecute (2b7ea12) → site 2b7ec48
    # need_upload (2b8ab12) → site 2b8abe5
    # upload_resource (2b9f772) → site 2b9f835
    # SendMessage_method (2b934e2) → site 2b93984
    pairs = list(zip(FN_ENTRIES, LOG_SITES))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"disasm_do_execute_{ts}.txt"

    ecx_offset_ctr: Counter = Counter()

    with out_path.open("w", encoding="utf-8") as fout:
        for (fn_off, fn_label), (site_off, site_label) in pairs:
            print(f"\n{'='*80}")
            print(f"[FN] {fn_off} ({fn_label})  →  log site {site_off}")
            print(f"     label: {site_label!r}")
            fout.write(f"\n{'='*80}\n[FN] {fn_off} ({fn_label})  →  site {site_off}\n")
            fout.write(f"     label: {site_label!r}\n")

            r = script.exports_sync.disasm_around_site(fn_off, site_off, 60, 60)
            insns = r.get("insns", [])
            found = r.get("found", False)
            if not found:
                print("     ❌ 未能找到 target 位点（可能起点错位）")
                fout.write("     ❌ target not found\n")
                continue

            tgt_idx = r.get("target_index", -1)
            # 只把完整反汇编 dump 到文件（不打屏），避免刷屏
            for i, ins in enumerate(insns):
                marker = "  →" if i == tgt_idx else "   "
                s = ins.get("str", ins.get("error", "?"))
                fout.write(f"{marker} {ins.get('off','?'):10s}  {s}\n")

            # 找 this 在函数入口被保存到栈的位置
            this_slot = find_this_save(insns)
            if this_slot:
                print(f"     ★ this saved at: {this_slot}")
                fout.write(f"\n     ★ this saved at: {this_slot}\n")

            # 提取所有寄存器 offset 引用
            pre = insns[:tgt_idx + 1] if tgt_idx > 0 else insns
            reg_offsets = extract_reg_offsets(pre)
            # 找 esi/edi/ebx 上的 [reg+X] 大偏移引用（更可能是 this->field）
            for reg in ("esi", "edi", "ebx", "ecx"):
                filtered = [(o, ln) for (o, ln) in reg_offsets[reg]
                            if 0x10 <= o < 0x400]  # 排除 [ebp-...] 局部变量
                if filtered:
                    print(f"     [{reg}+X] 大偏移引用 (top 10):")
                    fout.write(f"\n     [{reg}+X] 大偏移引用:\n")
                    seen_offs: Counter = Counter()
                    for off, ln in filtered:
                        seen_offs[off] += 1
                    for off, cnt in seen_offs.most_common(10):
                        # 找一个示例 line
                        example = next(ln for (o, ln) in filtered if o == off)
                        print(f"        {reg}+0x{off:x}  (x{cnt})  eg: {example}")
                        fout.write(f"        {reg}+0x{off:x}  (x{cnt})  eg: {example}\n")
                        ecx_offset_ctr[(reg, off)] += cnt

    print(f"\n\n{'='*80}")
    print("[+] 4 个 log site 汇总 [reg+X] 出现频次（重复越高 = 越可能是 this->conv_id 字段）:")
    for key, n in ecx_offset_ctr.most_common(30):
        if isinstance(key, tuple):
            reg, off = key
            print(f"     [{reg}+0x{off:x}]  count={n}")
        else:
            print(f"     [ecx+0x{key:x}]  count={n}")
    print(f"\n[+] → {out_path.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
