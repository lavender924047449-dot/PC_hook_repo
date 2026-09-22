"""
差分验证：扫描当前 WXWork 内存，输出最近 30 分钟内三元组
用于与"发送消息后"的扫描结果对比
"""
import sys, importlib.util, pathlib, time
from datetime import datetime, timezone

spec = importlib.util.spec_from_file_location(
    'wecom_memory_reader',
    pathlib.Path('app/pc_wecom/wecom_memory_reader.py')
)
mod = importlib.util.module_from_spec(spec)
sys.modules['wecom_memory_reader'] = mod
spec.loader.exec_module(mod)

WeComMemoryReader = mod.WeComMemoryReader
find_wxwork_pid = mod.find_wxwork_pid

pid = find_wxwork_pid()
print(f'[{datetime.now().strftime("%H:%M:%S")}] WXWork PID: {pid}')

if not pid:
    print('企微未运行'); sys.exit(1)

reader = WeComMemoryReader(pid)
print('扫描最近 30 分钟三元组...')
t0 = time.time()
triplets = reader.scan_recent(minutes=30, max_results=50)
elapsed = time.time() - t0
print(f'完成（{elapsed:.1f}s），找到 {len(triplets)} 个三元组\n')

for t in triplets:
    dt = datetime.fromtimestamp(t.send_time_s, tz=timezone.utc).strftime('%H:%M:%S')
    print(f'  seq={t.sequence:6}  ts={dt}UTC  mid={t.message_id:<12}  addr={hex(t.memory_addr)}')

import json, pathlib
out = pathlib.Path('runtime/wecom_re/diff_before.json')
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({
    'pid': pid,
    'scanned_at': time.time(),
    'count': len(triplets),
    'triplets': [t.to_dict() for t in triplets]
}, indent=2, ensure_ascii=False), encoding='utf-8')
print(f'\n保存到 {out}')
print('\n>>> 请在企业微信「文件传输助手」发送 1-2 条消息，然后运行 diff_after.py <<<')
