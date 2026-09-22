"""
分步调试扫描 - 捕获确切崩溃点
"""
import sys, importlib.util, pathlib, time

spec = importlib.util.spec_from_file_location(
    'wecom_memory_reader',
    pathlib.Path('app/pc_wecom/wecom_memory_reader.py')
)
mod = importlib.util.module_from_spec(spec)
sys.modules['wecom_memory_reader'] = mod
spec.loader.exec_module(mod)

pid = mod.find_wxwork_pid()
print(f'PID: {pid}')

try:
    t0 = time.time()
    triplets = mod.scan_message_triplets(pid, max_results=50, max_candidates=2000)
    print(f'扫描成功 ({time.time()-t0:.1f}s)，找到 {len(triplets)} 个三元组')
    for t in triplets[-5:]:
        print(f'  seq={t.sequence} ts_s={t.send_time_s} mid={t.message_id}')
except Exception as e:
    print(f'扫描异常: {type(e).__name__}: {e}')
    import traceback; traceback.print_exc()
