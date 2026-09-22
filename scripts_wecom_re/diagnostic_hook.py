"""
双重诊断：
1. 验证 logger 是否仍触发
2. 在 0xb91204 裸 hook（无 gate），看是否被调用
"""
import frida, time, json, sys

PID = 20632
LOGGER_ADDR = '0xa3616d0'
SUCCESS_ADDR = '0xb91204'

sess = frida.attach(PID)
js = r"""
var LOGGER_ADDR = ptr('""" + LOGGER_ADDR + r"""');
var SUCCESS_ADDR = ptr('""" + SUCCESS_ADDR + r"""');
var logger_hits = 0;
var success_hits = 0;
var logger_samples = [];
var success_samples = [];

function u32(p) { try { return p.readU32()>>>0; } catch(e) { return 0; } }

// Hook logger
Interceptor.attach(LOGGER_ADDR, {
  onEnter: function(args) {
    logger_hits++;
    if (logger_samples.length < 5) {
      var path = '';
      for (var i = 0; i < 4; i++) {
        try { var s = args[i].readUtf8String(200); if(s && s.length < 200) { path = s; break; } } catch(e) {}
      }
      logger_samples.push(path.slice(0,80));
    }
  }
});

// Hook 0xb91204 - NO GATE
Interceptor.attach(SUCCESS_ADDR, {
  onEnter: function(args) {
    success_hits++;
    if (success_samples.length < 5) {
      var esi = this.context.esi;
      var count28 = u32(esi.add(0x28));
      success_samples.push({esi: '0x'+esi.toString(16), count28: count28});
    }
  }
});

// Also hook at 0xb9114b to see total hits there
var b9_hits = 0;
Interceptor.attach(ptr('0xb9114b'), {
  onEnter: function(args) {
    b9_hits++;
  }
});

// Report every 5 seconds
var t = 0;
var iv = setInterval(function() {
  t++;
  send({t: t, logger_hits: logger_hits, success_hits: success_hits, b9_hits: b9_hits,
        logger_samples: logger_samples, success_samples: success_samples});
  if (t >= 5) clearInterval(iv);
}, 5000);
"""

print('Diagnostic hook active for 25s...')
sys.stdout.flush()

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(27)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    t = p.get('t', 0)
    print(f'\n[t={t*5}s] logger={p.get("logger_hits")} success_path={p.get("success_hits")} b9114b={p.get("b9_hits")}')
    if p.get('logger_samples'):
        print(f'  Logger paths: {p["logger_samples"][:3]}')
    if p.get('success_samples'):
        print(f'  Success path hits: {p["success_samples"]}')
