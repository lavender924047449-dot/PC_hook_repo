import json, re, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def load_caps(fname):
    with open(fname, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    for key in ['forward', 'captures', 'results', 'hits']:
        if key in data and isinstance(data[key], list):
            return data[key]
    return list(data.values())[0] if isinstance(data, dict) else []

# --- plaintext_20260911_134541.json ---
fname1 = 'plaintext_20260911_134541.json'
caps1 = load_caps(fname1)
print(f'=== {fname1}: {len(caps1)} caps ===')
for i, cap in enumerate(caps1[:30]):
    text = json.dumps(cap, ensure_ascii=False)
    if 'before' in text.lower() or '1001' in text:
        print(f'\n--- cap#{i} (before compress / 1001) ---')
        if isinstance(cap, dict):
            for k, v in cap.items():
                sv = str(v)
                print(f'  {k}: {sv[:200]}')

# --- payload_deep ---
print('\n\n=== payload_deep_20260911_135756.json ===')
caps2 = load_caps('payload_deep_20260911_135756.json')
print(f'{len(caps2)} caps')
for i, cap in enumerate(caps2[:3]):
    if isinstance(cap, dict):
        print(f'cap#{i}: {list(cap.keys())}')
        for k, v in cap.items():
            print(f'  {k}: {str(v)[:150]}')

# --- cgi_builder ---
print('\n\n=== cgi_builder_20260911_140433.json ===')
caps3 = load_caps('cgi_builder_20260911_140433.json')
print(f'{len(caps3)} caps')
for i, cap in enumerate(caps3[:3]):
    print(f'cap#{i}: {str(cap)[:200]}')
