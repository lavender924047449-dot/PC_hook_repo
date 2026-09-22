"""
差分验证 after：扫描发送消息后的三元组，与 diff_before.json 对比
"""
import sys, importlib.util, pathlib, time, json
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

reader = WeComMemoryReader(pid)
print('扫描最近 30 分钟三元组...')
t0 = time.time()
triplets = reader.scan_recent(minutes=30, max_results=100)
elapsed = time.time() - t0
print(f'完成（{elapsed:.1f}s），找到 {len(triplets)} 个三元组\n')

for t in triplets:
    dt = datetime.fromtimestamp(t.send_time_s, tz=timezone.utc).strftime('%H:%M:%S')
    print(f'  seq={t.sequence:6}  ts={dt}UTC  mid={t.message_id:<12}  addr={hex(t.memory_addr)}')

# 保存 after
out = pathlib.Path('runtime/wecom_re/diff_after.json')
out.parent.mkdir(parents=True, exist_ok=True)
after_data = {
    'pid': pid,
    'scanned_at': time.time(),
    'count': len(triplets),
    'triplets': [t.to_dict() for t in triplets]
}
out.write_text(json.dumps(after_data, indent=2, ensure_ascii=False), encoding='utf-8')

# 差分对比
before_path = pathlib.Path('runtime/wecom_re/diff_before.json')
if before_path.exists():
    before_data = json.loads(before_path.read_text(encoding='utf-8'))
    before_addrs = {t['memory_addr'] for t in before_data['triplets']}
    before_mids  = {t['message_id'] for t in before_data['triplets']}
    
    new_triplets = [t for t in triplets if hex(t.memory_addr) not in before_addrs]
    new_mids     = {t.message_id for t in new_triplets} - before_mids
    
    print(f'\n=== 差分结果 ===')
    print(f'  before: {before_data["count"]} 条  →  after: {len(triplets)} 条')
    print(f'  新增三元组地址: {len(new_triplets)} 个')
    print(f'  新增 message_id: {sorted(new_mids)}')
    
    if new_triplets:
        print('\n  新增三元组详情:')
        for t in new_triplets:
            dt = datetime.fromtimestamp(t.send_time_s, tz=timezone.utc).strftime('%H:%M:%S')
            marker = ' ← 新 mid' if t.message_id in new_mids else ''
            print(f'    seq={t.sequence}  ts={dt}UTC  mid={t.message_id}({hex(t.message_id)})  addr={hex(t.memory_addr)}{marker}')

print(f'\n保存到 {out}')
