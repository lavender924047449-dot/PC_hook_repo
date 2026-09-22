import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

for fname in [
    'plaintext_20260911_134541.json',
    'hook_frames_20260911_134321.json',
    'final_capture_20260911_141124.json',
]:
    print(f'\n==== {fname} ====')
    try:
        with open(fname, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict):
            print('keys:', list(data.keys()))
            for k, v in data.items():
                if isinstance(v, list):
                    print(f'  {k}: list({len(v)})')
                    if v:
                        item = v[0]
                        if isinstance(item, dict):
                            print(f'    item[0].keys: {list(item.keys())}')
                            for k2, v2 in item.items():
                                sv = str(v2)
                                print(f'      {k2}: {sv[:120]}')
                elif isinstance(v, str):
                    print(f'  {k}: {v[:100]}')
        elif isinstance(data, list):
            print(f'list({len(data)})')
            if data:
                it = data[0]
                print(f'  item[0] type={type(it).__name__}')
                if isinstance(it, dict):
                    print(f'  keys: {list(it.keys())}')
    except Exception as e:
        print(f'ERR: {e}')
