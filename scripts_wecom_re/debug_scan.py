import sys, types, importlib.util, pathlib, time

# 直接加载模块
spec = importlib.util.spec_from_file_location(
    'wecom_memory_reader',
    pathlib.Path('app/pc_wecom/wecom_memory_reader.py')
)
mod = importlib.util.module_from_spec(spec)
sys.modules['wecom_memory_reader'] = mod
spec.loader.exec_module(mod)

find_wxwork_pid = mod.find_wxwork_pid
scan_message_triplets = mod.scan_message_triplets

pid = find_wxwork_pid()
print(f'WXWork PID: {pid}')
print(f'Current Unix time: {int(time.time())} ({__import__("datetime").datetime.utcnow().isoformat()} UTC)')

# 扫描所有时间范围
print('\n扫描全部时间范围（不限时间，max=500）...')
triplets = scan_message_triplets(pid, max_results=500)
print(f'找到 {len(triplets)} 个三元组')
# 找今天的
now_s = int(time.time())
today_triplets = [t for t in triplets if abs(t.send_time_s - now_s) < 86400]
print(f'\n今天的三元组（±24h）: {len(today_triplets)} 个')
for t in today_triplets:
    dt = t.send_time_dt.isoformat()
    print(f'  addr={hex(t.memory_addr)} seq={t.sequence:6} ts_s={t.send_time_s} ({dt}) mid={t.message_id}')
print('\n最后 5 个（按时间排序）:')
for t in triplets[-5:]:
    dt = t.send_time_dt.isoformat()
    print(f'  addr={hex(t.memory_addr)} seq={t.sequence:6} ts_s={t.send_time_s} ({dt}) mid={t.message_id}')
