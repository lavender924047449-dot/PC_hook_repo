/**
 * ipc_socket_hook.js  v4
 *
 * 企微 IPC 抓包 — 简化版，避开 JS 保留词冲突。
 * - 服务端：hook accept 获取新连接 sock，再 hook recv/send
 * - 客户端：hook connect 过滤目标端口
 * - 捕获数据通过 send() 发回 Python
 */
'use strict';

const IPC_PORTS = [9882, 50010];
const DUMP_MAX  = 512;

// ── util ─────────────────────────────────────────────────────────────────────

function dumpBytes(buf, maxLen) {
    const b   = new Uint8Array(buf);
    const len = Math.min(b.length, maxLen);
    const rows = [];
    for (let r = 0; r < len; r += 16) {
        const end = Math.min(r + 16, len);
        let h = '', a = '';
        for (let i = r; i < end; i++) {
            h += ('0' + b[i].toString(16)).slice(-2) + ' ';
            a += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : '.';
        }
        rows.push(('000' + r.toString(16)).slice(-4) + '  ' + h.padEnd(48) + ' |' + a + '|');
    }
    if (b.length > maxLen) rows.push('  ... (' + b.length + ' bytes total)');
    return rows.join('\n');
}

function portFromSockaddr(ptr) {
    try {
        if (ptr.readU16() !== 2) return -1;   // AF_INET only
        const raw = ptr.add(2).readU16();
        return ((raw & 0xff) << 8) | (raw >> 8);  // ntohs
    } catch (_) { return -1; }
}

function emit(s) {
    try { send(s); } catch (_) {}
    console.log(s);
}

// ── state ─────────────────────────────────────────────────────────────────────
// sock(int) → port(int)
var sockPort = {};

function trackSock(sock, port) { sockPort[sock] = port; }
function untrackSock(sock)     { delete sockPort[sock]; }
function getPort(sock)         { return sockPort[sock]; }
function isTracked(sock)       { return sock in sockPort; }

// ── hook: accept ─────────────────────────────────────────────────────────────
// We pre-populate the listening sockets from netstat knowledge: 9882 & 50010.
// Since bind() was called before attach, we seed accept() by checking getsockname.
// Simpler: hook accept, and for each new sock call getsockname on the listening sock
// to learn its port.

var getsockname = new NativeFunction(
    Module.getExportByName('ws2_32.dll', 'getsockname'),
    'int', ['int', 'pointer', 'pointer']
);

function detectPort(sock) {
    var sa  = Memory.alloc(16);
    var sal = Memory.alloc(4);
    sal.writeInt(16);
    var r = getsockname(sock, sa, sal);
    if (r === 0) return portFromSockaddr(sa);
    return -1;
}

// Seed: we know the main WXWork.exe is listening on 9882 and 50010.
// Hook accept to learn the new connection socks.
var acceptFn = Module.findExportByName('ws2_32.dll', 'accept');
if (acceptFn) {
    Interceptor.attach(acceptFn, {
        onEnter: function(args) {
            this.listenSock = args[0].toInt32();
        },
        onLeave: function(ret) {
            var newSock = ret.toInt32();
            if (newSock <= 0) return;
            var listenSock = this.listenSock;
            var port = detectPort(listenSock);
            if (!IPC_PORTS.includes(port)) return;
            trackSock(newSock, port);
            emit('[accept] new_sock=' + newSock + ' port=' + port);
        }
    });
    emit('[hook] accept attached');
} else {
    emit('[hook] accept NOT FOUND in ws2_32');
}

// ── hook: connect (客户端侧) ──────────────────────────────────────────────────
var connectFn = Module.findExportByName('ws2_32.dll', 'connect');
if (connectFn) {
    Interceptor.attach(connectFn, {
        onEnter: function(args) {
            var port = portFromSockaddr(args[1]);
            if (IPC_PORTS.includes(port)) {
                trackSock(args[0].toInt32(), port);
                emit('[connect] sock=' + args[0].toInt32() + ' port=' + port);
            }
        }
    });
    emit('[hook] connect attached');
}

// ── hook: send ────────────────────────────────────────────────────────────────
var sendFn = Module.findExportByName('ws2_32.dll', 'send');
if (sendFn) {
    Interceptor.attach(sendFn, {
        onEnter: function(args) {
            var sock = args[0].toInt32();
            if (!isTracked(sock)) return;
            var len = args[2].toInt32();
            if (len <= 0) return;
            var data = args[1].readByteArray(Math.min(len, DUMP_MAX));
            emit('\n[SEND->port=' + getPort(sock) + '] sock=' + sock + ' len=' + len + '\n' + dumpBytes(data, DUMP_MAX));
        }
    });
    emit('[hook] send attached');
}

// ── hook: recv ────────────────────────────────────────────────────────────────
var recvFn = Module.findExportByName('ws2_32.dll', 'recv');
if (recvFn) {
    Interceptor.attach(recvFn, {
        onEnter: function(args) { this.sockArgs = args; },
        onLeave: function(ret) {
            var n = ret.toInt32();
            if (n <= 0) return;
            var sock = this.sockArgs[0].toInt32();
            if (!isTracked(sock)) return;
            var data = this.sockArgs[1].readByteArray(Math.min(n, DUMP_MAX));
            emit('\n[RECV<-port=' + getPort(sock) + '] sock=' + sock + ' len=' + n + '\n' + dumpBytes(data, DUMP_MAX));
        }
    });
    emit('[hook] recv attached');
}

// ── hook: closesocket ─────────────────────────────────────────────────────────
var closeFn = Module.findExportByName('ws2_32.dll', 'closesocket');
if (closeFn) {
    Interceptor.attach(closeFn, {
        onEnter: function(args) {
            var sock = args[0].toInt32();
            if (isTracked(sock)) {
                emit('[close] sock=' + sock + ' port=' + getPort(sock));
                untrackSock(sock);
            }
        }
    });
}

emit('[ipc_hook v4 ready] monitoring IPC ports: ' + IPC_PORTS.join(',') + '  pid=' + Process.id);
