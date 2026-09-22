"""验证 bind() 的 fast-path 是否生效"""
import sys, time, tempfile, pathlib
sys.path.insert(0, '.')

from app.messaging.asset_library import AssetLibrary
from app.messaging.types import MessageType
from app.pc_wecom.bubble_anchor import BubbleAnchorService

# 用临时库避免污染
tmp = pathlib.Path(tempfile.mkdtemp()) / 'lib.json'
lib = AssetLibrary(tmp)
entry = lib.register_forward(MessageType.LOCATION, "测试地点")
code = entry.material_code
print(f'新建素材: {code}')

# 无 memory_reader，只验证 fast-path 逻辑
svc = BubbleAnchorService(lib)  # 不注入 memory_reader

t0 = time.time()
res = svc.bind(
    code,
    'test_fingerprint_1234567890abcdef',
    echo_message_id='echo-test',
    send_time_ms=1789008224519,
    sequence=1,
    wecom_message_id=193405740,
)
elapsed = time.time() - t0
print(f'\nbind() 用时: {elapsed:.3f}s')
print(f'结果 current: {res["current"]}')

if elapsed >= 1.0:
    print(f'\n❌ fast-path 未生效！耗时 {elapsed}s')
    sys.exit(1)

cur = res['current']
assert cur.get('send_time_ms') == 1789008224519, f'send_time_ms 未保存: {cur}'
assert cur.get('sequence') == 1, f'sequence 未保存: {cur}'
assert cur.get('wecom_message_id') == 193405740, f'mid 未保存: {cur}'
print('\n✅ fast-path 生效！')
