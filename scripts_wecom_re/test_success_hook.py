"""
测试 0xb91204 是否被触发（无 gate，看是否被调用）
同时修复路径读取（宽字符）
"""
import frida, time, sys

PID = 20632
LOGGER_ADDR = '0xa3616d0'
SUCCESS_ADDR = '0xb91204'

sess = frida.attach(PID)
js = r"""
var logger_hits = 0;
var success_hits = 0;
var logger_paths = [];
var success_data = [];

function tryReadStr(p) {
  if (!p || p.isNull()) return '';
  try { var s = p.readUtf8String(200); if(s && s.length>2) return s; } catch(e) {}
  try { var s = p.readUtf16String(100); if(s && s.length>2) return s; } catch(e) {}
  try { var s = p.readAnsiString(200); if(s && s.length>2) return s; } catch(e) {}
  return '';
}

function u32(p) { try { return p.readU32()>>>0; } catch(e) { return 0; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e) { return ''; } }

Interceptor.attach(ptr('""" + LOGGER_ADDR + r"""'), {
  onEnter: function(args) {
    logger_hits++;
    if (logger_paths.length < 5) {
      var path = '';
      for (var i = 0; i < 8; i++) {
        try {
          if (!args[i].isNull()) {
            var s = tryReadStr(args[i]);
            if (s && (s.indexOf('db') >= 0 || s.indexOf('WXWork') >= 0 || s.indexOf('Data') >= 0)) {
              path = s.slice(0,120);
              break;
            }
          }
        } catch(e) {}
      }
      if (path) logger_paths.push(path);
    }
  }
});

// Test hook at SUCCESS_ADDR = 0xb91204
Interceptor.attach(ptr('""" + SUCCESS_ADDR + r"""'), {
  onEnter: function(args) {
    success_hits++;
    if (success_data.length < 10) {
      var esi = this.context.esi;
      var count28 = u32(esi.add(0x28));
      var dump = hd(esi.add(0x20), 64);
      success_data.push({
        ts: Date.now(),
        esi: '0x'+esi.toString(16),
        count28: count28,
        dump: dump
      });
    }
  }
});

var t = 0;
var iv = setInterval(function() {
  t++;
  send({t: t, logger_hits: logger_hits, success_hits: success_hits,
        logger_paths: logger_paths, success_data: success_data.slice(-3)});
  if (t >= 5) clearInterval(iv);
}, 5000);
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m.get('payload', {})))

try:
    script.load()
    print('Hooks loaded, waiting 25s. Please trigger WeChat Work operations!')
    sys.stdout.flush()
    time.sleep(27)
finally:
    try: script.unload()
    except: pass
    try: sess.detach()
    except: pass

for p in msgs:
    print(f'[t={p.get("t",0)*5}s] logger={p.get("logger_hits")} success_path={p.get("success_hits")}')
    if p.get('logger_paths'):
        print(f'  Logger paths: {p["logger_paths"]}')
    if p.get('success_data'):
        for s in p['success_data']:
            print(f'  SUCCESS HIT: ESI={s["esi"]} count28={s["count28"]}')
            for line in s['dump'].split('\n')[:4]:
                print(f'    {line}')
