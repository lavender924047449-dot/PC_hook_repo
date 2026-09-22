import frida, subprocess, time, sys
sys.stdout.reconfigure(encoding='utf-8')
o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
pid=[int(l.strip().split()[-1]) for l in o.splitlines() if ':9882' in l and 'LISTENING' in l][0]
print('pid=',pid)
s=frida.get_local_device().attach(pid)
sc=s.create_script('''
var m = Process.getModuleByName('WXWork.exe');
send({path:m.path, base:'0x'+m.base.toString(16), size:m.size});
''')
sc.on('message', lambda m,d: print(m))
sc.load(); time.sleep(1); s.detach()
