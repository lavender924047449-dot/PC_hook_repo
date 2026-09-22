# _hex_dump.py — 简易 hex + ASCII 双栏输出
import sys
from pathlib import Path

def dump(path, offset=0, length=None):
    data = Path(path).read_bytes()
    if length is None: length = len(data) - offset
    data = data[offset:offset+length]
    print(f'== {Path(path).name}  size={len(data)}  ==')
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f'{i:04x}  {h:<47}  {a}')

if __name__ == '__main__':
    for p in sys.argv[1:]:
        dump(p, 0, 512)
        print()
