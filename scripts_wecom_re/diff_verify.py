import sys, types, importlib.util, pathlib, time

spec = importlib.util.spec_from_file_location('wmr', pathlib.Path('app/pc_wecom/wecom_memory_reader.py'))
mod = importlib.util.module_from_spec(spec)
sys.modules['wmr'] = mod
spec.loader.exec_module(mod)

pid = mod.find_wxwork_pid()
utc = time.strftime('%H:%M:%S', time.gmtime())
print(f'PID={pid}  UTC={utc}')

reader = mod.WeComMemoryReader(pid)
print('scan_recent(minutes=120)...')
ts = reader.scan_recent(minutes=120, max_results=30)
print(f'找到 {len(ts)} 条 (最新5条):')
for t in ts[-5:]:
    utc_ts = t.send_time_dt.strftime('%Y-%m-%d %H:%M:%S')
    print(f'  {hex(t.memory_addr):12s}  seq={t.sequence:6}  ts={utc_ts} UTC  mid={t.message_id}({hex(t.message_id)})')

if ts:
    first, last = ts[0], ts[-1]
    print(f'\nmid 范围: {first.message_id} ~ {last.message_id}')
    print(f'序列号范围: {first.sequence} ~ {last.sequence}')
    unique_mids = len(set(t.message_id for t in ts))
    print(f'唯一 message_id 数: {unique_mids} / {len(ts)}')
