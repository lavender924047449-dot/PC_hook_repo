import frida, time, subprocess

def get_pid():
    out = subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for l in out.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script("""
var T = ptr(0x1023810);
var n = 0;
Interceptor.attach(T, {onEnter:function(args){
    if(++n <= 10) send({n:n, tid:this.threadId});
}});
send({t:'ready'});
""")
hits = []
def cb(m, d):
    p = m.get('payload', {})
    print(f'msg: {p}')
    if 'n' in p:
        hits.append(p)
sc.on('message', cb)
sc.load()
time.sleep(20)
print(f'done: {len(hits)} hits in 20s')
