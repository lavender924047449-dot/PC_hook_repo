"""
简单诊断：仅测试 logger hook，验证地址 0xa3616d0 是否仍然有效
"""
import frida, time, sys

PID = 20632
LOGGER_ADDR = '0xa3616d0'

sess = frida.attach(PID)
js = r"""
var logger_hits = 0;
var logger_samples = [];

Interceptor.attach(ptr('""" + LOGGER_ADDR + r"""'), {
  onEnter: function(args) {
    logger_hits++;
    if (logger_samples.length < 5) {
      var path = '';
      for (var i = 0; i < 4; i++) {
        try { var s = args[i].readUtf8String(200); if(s && s.length > 3 && s.length < 200) { path = s; break; } } catch(e) {}
      }
      logger_samples.push(path.slice(0, 80));
    }
  }
});

var t = 0;
var iv = setInterval(function() {
  t++;
  send({t: t, logger_hits: logger_hits, samples: logger_samples.slice(-3)});
  if (t >= 4) clearInterval(iv);
}, 5000);
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m.get('payload', {})))

try:
    script.load()
    print('Logger hook loaded, waiting 20s...')
    sys.stdout.flush()
    time.sleep(22)
finally:
    script.unload()
    sess.detach()

for p in msgs:
    print(f'[t={p.get("t",0)*5}s] logger_hits={p.get("logger_hits")} samples={p.get("samples")}')
