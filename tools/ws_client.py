"""Minimal WebSocket client (RFC 6455, text frames) without third-party libraries – for IS-12."""
from __future__ import annotations

import base64
import os
import socket
import struct
from urllib.parse import urlparse


class WebSocketError(Exception):
    pass


class WebSocket:
    def __init__(self, url: str, timeout: float = 5.0):
        u = urlparse(url)
        if u.scheme not in ("ws", "wss"):
            raise WebSocketError(f"only ws:// is supported: {url}")
        if u.scheme == "wss":
            raise WebSocketError("wss:// (TLS) is not supported")
        host, port = u.hostname, u.port or 80
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            resp += chunk
        head, _, rest = resp.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 101 " not in status:
            raise WebSocketError(f"handshake rejected: {status}")
        self.buf = rest
        self.closed = False

    # ---- Frames
    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WebSocketError("connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes):
        mask = os.urandom(4)
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def send(self, text: str):
        self._send_frame(0x1, text.encode("utf-8"))

    def recv(self, timeout: float | None = None) -> str | None:
        """Next text message; None on timeout. Ping/pong/close are handled internally."""
        self.sock.settimeout(timeout)
        message = b""
        try:
            while True:
                b1, b2 = self._recv_exact(2)
                fin, opcode = b1 & 0x80, b1 & 0x0F
                n = b2 & 0x7F
                if n == 126:
                    n = struct.unpack(">H", self._recv_exact(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", self._recv_exact(8))[0]
                mask = self._recv_exact(4) if b2 & 0x80 else None
                payload = self._recv_exact(n)
                if mask:
                    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                if opcode == 0x8:
                    self.closed = True
                    raise WebSocketError("peer closed the connection")
                if opcode == 0x9:
                    self._send_frame(0xA, payload); continue
                if opcode == 0xA:
                    continue
                message += payload
                if fin:
                    return message.decode("utf-8", errors="replace")
        except socket.timeout:
            return None

    def close(self):
        try:
            if not self.closed:
                self._send_frame(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        finally:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass
