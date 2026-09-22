#!/usr/bin/env python3
# 在 WXWork.exe 里搜 "[语音]" 各种编码形式，输出文件内偏移（不是 RVA）
import sys
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')

EXE = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
data = EXE.read_bytes()
print(f'[*] file size = {len(data):,}')

patterns = {
    '"[语音]" UTF-8'   : b'[\xe8\xaf\xad\xe9\x9f\xb3]',
    '"[语音]" UTF-16LE': '[语音]'.encode('utf-16-le'),
    '"语音" UTF-8'     : '语音'.encode('utf-8'),
    '"语音" UTF-16LE'  : '语音'.encode('utf-16-le'),
    '"Voice" ASCII'    : b'Voice',
    '"voice" ASCII'    : b'voice',
    '"[Voice]"'        : b'[Voice]',
    '"[voice]"'        : b'[voice]',
    '"unsupported"'    : b'unsupported',
    '"UnsupportedMsg"' : b'UnsupportedMsg',
    '"DowngradedMsg"'  : b'DowngradedMsg',
}

def find_all(hay, needle, cap=100):
    res=[]; start=0
    while True:
        i = hay.find(needle, start)
        if i<0: break
        res.append(i); start=i+1
        if len(res)>=cap: break
    return res

for name, needle in patterns.items():
    hits = find_all(data, needle, 50)
    print(f'\n[{name}]  needle_bytes={needle.hex()}  hits={len(hits)}')
    for h in hits[:10]:
        # 转成 RVA（近似 = 文件偏移 - image base + section RVA），先只输出文件偏移
        # 大部分 IDA 里 exe 的 .rdata / .data 段基本按顺序
        ctx = data[max(0,h-8):h+len(needle)+16]
        print(f'   @file+0x{h:08x}   ctx={ctx.hex()}')
