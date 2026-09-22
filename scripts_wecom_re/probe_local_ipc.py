from __future__ import annotations

import argparse
import json
import socket
import ssl
import time


def try_plain(host: str, port: int, payload: bytes, timeout: float) -> dict:
    t0 = time.time()
    out = {"mode": "plain", "payload_hex": payload.hex(), "ok": False, "recv_hex": "", "error": ""}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            data = s.recv(256)
            out["recv_hex"] = data.hex()
            out["ok"] = True
    except Exception as e:
        out["error"] = str(e)
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    return out


def try_tls(host: str, port: int, timeout: float) -> dict:
    t0 = time.time()
    out = {"mode": "tls_client_hello", "ok": False, "error": "", "cipher": "", "version": ""}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                out["ok"] = True
                out["cipher"] = str(tls_sock.cipher())
                out["version"] = str(tls_sock.version())
    except Exception as e:
        out["error"] = str(e)
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    return out


def probe_port(host: str, port: int, timeout: float) -> dict:
    payloads = [
        b"",
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        b"\x00\x00\x00\x00",
    ]
    return {
        "host": host,
        "port": port,
        "results": [try_plain(host, port, p, timeout) for p in payloads] + [try_tls(host, port, timeout)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe WeCom local IPC ports safely.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ports", default="9882,9883,50010,50018")
    parser.add_argument("--timeout", type=float, default=1.2)
    args = parser.parse_args()

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    payload = {
        "target": args.host,
        "ports": [probe_port(args.host, p, args.timeout) for p in ports],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
