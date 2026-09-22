import sys, types, importlib.util, pathlib

# ── 直接加载 wecom_memory_reader（不走 __init__.py）──────────────────────────
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
print(f'WXWork PID: {pid}')

if pid:
    reader = WeComMemoryReader(pid)
    print('扫描最近 60 分钟内消息三元组（使用 scan_recent）...')
    triplets = reader.scan_recent(minutes=60, max_results=20)
    print(f'找到 {len(triplets)} 个三元组')
    for t in triplets:
        dt = t.send_time_dt.strftime('%Y-%m-%d %H:%M:%S')
        print(f'  addr={hex(t.memory_addr)} seq={t.sequence} ts={dt} UTC mid={t.message_id}({hex(t.message_id)})')

    # ── 加载 bubble_anchor（注入假 AssetLibrary）─────────────────────────────
    fake_asset = types.ModuleType('app.messaging.asset_library')
    class FakeAssetLibrary: pass
    fake_asset.AssetLibrary = FakeAssetLibrary
    sys.modules.setdefault('app', types.ModuleType('app'))
    sys.modules.setdefault('app.messaging', types.ModuleType('app.messaging'))
    sys.modules['app.messaging.asset_library'] = fake_asset

    spec2 = importlib.util.spec_from_file_location(
        'bubble_anchor',
        pathlib.Path('app/pc_wecom/bubble_anchor.py')
    )
    mod2 = importlib.util.module_from_spec(spec2)
    sys.modules['bubble_anchor'] = mod2
    spec2.loader.exec_module(mod2)
    AnchorRecord = mod2.AnchorRecord

    print('\n--- AnchorRecord 字段测试 ---')
    last = triplets[-1] if triplets else None
    rec = AnchorRecord(
        bubble_timestamp='2026-09-09T21:00:00',
        echo_message_id='echo_test_001',
        fingerprint_snippet='test_fp_12',
        sequence=last.sequence if last else 0,
        send_time_ms=last.send_time_ms if last else 0,
        wecom_message_id=last.message_id if last else 0,
    )
    print(f'  has_memory_anchor = {rec.has_memory_anchor}')
    print(f'  to_dict() = {rec.to_dict()}')

    # 验证 find_by_send_time
    if triplets:
        target_ms = triplets[-1].send_time_ms
        found = reader.find_by_send_time(target_ms, tolerance_ms=5000)
        print(f'\n--- find_by_send_time (target={target_ms}) ---')
        if found:
            print(f'  找到: seq={found.sequence} mid={found.message_id} ts={found.send_time_ms}')
        else:
            print('  未找到（可能被扫描结果数量限制）')
else:
    print('WXWork 未运行')
