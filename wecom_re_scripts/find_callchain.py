# find_callchain.py — 从 PreSendNewMessage @ RVA 0x919ffb2 出发，
# 静态 BFS 5 层 CALL，输出候选 ConstructMessageProtobuf 名单。
#
# 产物：
#   callchain_<ts>.json       - 完整调用图（含每个 fn 的 CALL 目标）
#   callchain_<ts>_flat.txt   - RVA 扁平清单，供 hook 使用
#
# 依据 §47.10.11 一句话交接：
#   PreSend → sub_118AEB00 → sub_115838C0 → sub_118AF0C0 → sub_118AEAA0 → sub_118AF2F0
#   我们不认那些 IDA name（版本不一致），只信自己的 RVA 追下去。

import sys, json
from pathlib import Path
from datetime import datetime
from collections import deque
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_RET, CS_GRP_JUMP

WXWORK = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
PRESEND_RVA = 0x919ffb2

MAX_DEPTH = 5
MAX_FN_BYTES = 8192          # 单个函数最多扫 8KB（一般 <2KB 就 RET）
MAX_INSNS = 4000
MAX_TOTAL_FUNCS = 4000       # 全局上限，防爆
LOG_EVERY = 500

ts = datetime.now().strftime('%Y%m%d_%H%M%S')


def load_pe():
    print('[*] Loading PE …', flush=True)
    pe = pefile.PE(str(WXWORK), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    text_sec = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode(errors='replace')
        if name == '.text':
            text_sec = s
            break
    if not text_sec:
        raise RuntimeError('no .text')
    text_va = image_base + text_sec.VirtualAddress
    text_data = text_sec.get_data()
    text_end = text_va + len(text_data)
    print(f'    image_base = 0x{image_base:08x}')
    print(f'    .text VA=0x{text_va:08x}  size=0x{len(text_data):x}  end=0x{text_end:08x}')
    return pe, image_base, text_va, text_end, text_data


def make_reader(text_va, text_end, text_data):
    def read(va, n):
        if va < text_va or va + n > text_end:
            return None
        off = va - text_va
        return text_data[off:off + n]
    return read


def walk_function(md, read, entry_va):
    """线性反汇编一个函数，返回 CALL 目标 rel32 RVA 列表（image_base 已去掉外部）。
    只收集 direct call (E8 disp32) 与 direct jmp-to-func 疑似 tail call (E9 disp32)。
    """
    body = read(entry_va, MAX_FN_BYTES)
    if not body:
        return [], 'no_body'
    calls = []
    tail_jmps = []
    end_reason = 'limit'
    seen_ret = False
    n_insn = 0
    for insn in md.disasm(body, entry_va):
        n_insn += 1
        if n_insn > MAX_INSNS:
            end_reason = 'insn_limit'
            break

        mnem = insn.mnemonic
        if mnem == 'call':
            op = insn.op_str
            # direct: "0xXXXXXXXX"
            if op.startswith('0x'):
                try:
                    tgt = int(op, 16)
                    calls.append({'from_va': insn.address, 'tgt_va': tgt})
                except ValueError:
                    pass
            # else indirect (reg / mem) → skip
        elif mnem == 'jmp':
            op = insn.op_str
            if op.startswith('0x'):
                try:
                    tgt = int(op, 16)
                    # 跨函数 tail-jmp（跳出本函数体范围）视为候选
                    if abs(tgt - entry_va) > MAX_FN_BYTES:
                        tail_jmps.append({'from_va': insn.address, 'tgt_va': tgt})
                except ValueError:
                    pass
            # 无条件 jmp 通常是函数尾（编译器不生成 fallthrough）
            if not seen_ret:
                # 只把在函数早期出现的 jmp 视为"可能提前结束"，晚期忽略
                if insn.address - entry_va < 32:
                    # 极短包装函数：JMP thunk
                    end_reason = 'thunk_jmp'
                    break
        elif mnem in ('ret', 'retn'):
            seen_ret = True
            end_reason = 'ret'
            break
        elif mnem.startswith('int') and insn.bytes[0] in (0xcc,):  # int3 → 常见函数结束填充
            if seen_ret:
                break
    return calls + tail_jmps, end_reason


def in_text(va, text_va, text_end):
    return text_va <= va < text_end


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pe, image_base, text_va, text_end, text_data = load_pe()
    read = make_reader(text_va, text_end, text_data)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    presend_va = image_base + PRESEND_RVA
    print(f'[*] PreSendNewMessage VA = 0x{presend_va:08x}')

    # BFS
    graph = {}   # va -> {'depth', 'end_reason', 'calls': [{'from_va', 'tgt_va'}]}
    depth_of = {presend_va: 0}
    q = deque([presend_va])
    order = []

    while q:
        va = q.popleft()
        if va in graph:
            continue
        d = depth_of[va]
        if d > MAX_DEPTH:
            continue
        if not in_text(va, text_va, text_end):
            graph[va] = {'depth': d, 'end_reason': 'out_of_text', 'calls': []}
            continue
        calls, why = walk_function(md, read, va)
        graph[va] = {'depth': d, 'end_reason': why, 'calls': calls}
        order.append(va)
        if len(graph) % LOG_EVERY == 0:
            print(f'    walked {len(graph)} fns …', flush=True)
        if len(graph) >= MAX_TOTAL_FUNCS:
            print(f'    !! hit MAX_TOTAL_FUNCS={MAX_TOTAL_FUNCS}, stop', flush=True)
            break
        if d < MAX_DEPTH:
            for c in calls:
                t = c['tgt_va']
                if t not in depth_of and in_text(t, text_va, text_end):
                    depth_of[t] = d + 1
                    q.append(t)

    print(f'[+] discovered {len(graph)} unique functions across depth 0..{MAX_DEPTH}')

    # 深度分桶统计
    by_depth = {}
    for va, info in graph.items():
        by_depth.setdefault(info['depth'], []).append(va)
    for d in sorted(by_depth):
        print(f'    depth {d}: {len(by_depth[d])} fns')

    # 输出
    def rva(va): return va - image_base
    dump = {
        'meta': {
            'exe': str(WXWORK), 'image_base': image_base,
            'presend_rva': PRESEND_RVA, 'presend_va': presend_va,
            'max_depth': MAX_DEPTH, 'ts': ts,
            'total_fns': len(graph),
        },
        'functions': [
            {
                'va': va, 'rva': rva(va), 'depth': info['depth'],
                'end_reason': info['end_reason'],
                'n_calls': len(info['calls']),
                'calls': [
                    {'from_rva': rva(c['from_va']), 'tgt_rva': rva(c['tgt_va']),
                     'tgt_va': c['tgt_va']}
                    for c in info['calls']
                ],
            }
            for va, info in sorted(graph.items(), key=lambda x: (x[1]['depth'], x[0]))
        ],
    }
    json_path = OUT_DIR / f'callchain_{ts}.json'
    json_path.write_text(json.dumps(dump, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'[+] wrote {json_path}')

    # 扁平清单：hook 用（RVA，去重）
    flat_lines = ['# depth  rva          va']
    for va, info in sorted(graph.items(), key=lambda x: (x[1]['depth'], x[0])):
        flat_lines.append(f'{info["depth"]:>5}   0x{rva(va):08x}   0x{va:08x}')
    flat_path = OUT_DIR / f'callchain_{ts}_flat.txt'
    flat_path.write_text('\n'.join(flat_lines), encoding='utf-8')
    print(f'[+] wrote {flat_path}')

    # 打印 PreSend 的直接 callees（depth 1）
    presend_calls = graph[presend_va]['calls']
    print(f'\n=== PreSendNewMessage direct CALLs ({len(presend_calls)}) ===')
    for c in presend_calls[:40]:
        t = c['tgt_va']
        info = graph.get(t)
        print(f'  0x{c["from_va"]:08x} → 0x{t:08x}  (rva=0x{rva(t):08x})'
              + (f'   subcalls={len(info["calls"])}' if info else ''))


if __name__ == '__main__':
    main()
