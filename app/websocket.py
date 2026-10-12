"""Minimal RFC 6455 WebSocket server side for BaseHTTPRequestHandler (text messages, ping/pong, close)."""
from __future__ import annotations

import base64
import hashlib
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
MAX_MESSAGE = 4 * 1024 * 1024


class WebSocketClosed(Exception):
    pass


class ServerWebSocket:
    def __init__(self, handler):
        """handler: BaseHTTPRequestHandler whose request carries 'Upgrade: websocket'."""
        self.h = handler
        self.rfile, self.wfile = handler.rfile, handler.wfile
        self.send_lock = threading.Lock()
        self.closed = False
        self.peer = f"{handler.client_address[0]}:{handler.client_address[1]}"

    @staticmethod
    def is_upgrade(handler) -> bool:
        return (handler.headers.get("Upgrade", "").lower() == "websocket"
                and "upgrade" in handler.headers.get("Connection", "").lower())

    def accept(self):
        key = self.h.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.h.send_response(101, "Switching Protocols")
        self.h.send_header("Upgrade", "websocket")
        self.h.send_header("Connection", "Upgrade")
        self.h.send_header("Sec-WebSocket-Accept", accept)
        self.h.end_headers()
        self.h.wfile.flush()
        self.h.close_connection = True

    def _read_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.rfile.read(n - len(data))
            if not chunk:
                raise WebSocketClosed()
            data += chunk
        return data

    def _read_frame(self):
        b1, b2 = self._read_exact(2)
        fin, op = b1 & 0x80, b1 & 0x0F
        masked, ln = b2 & 0x80, b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._read_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._read_exact(8))[0]
        if ln > MAX_MESSAGE:
            raise WebSocketClosed()
        mask = self._read_exact(4) if masked else None
        payload = self._read_exact(ln)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return bool(fin), op, payload

    def recv(self) -> str:
        """Next text message (blocking). Answers pings, raises WebSocketClosed on close/EOF."""
        parts, first_op = [], None
        while True:
            fin, op, payload = self._read_frame()
            if op == OP_PING:
                self._send(OP_PONG, payload)
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                try:
                    self._send(OP_CLOSE, payload[:2])
                except OSError:
                    pass
                raise WebSocketClosed()
            if op != OP_CONT:
                first_op, parts = op, []
            parts.append(payload)
            if sum(len(p) for p in parts) > MAX_MESSAGE:
                raise WebSocketClosed()
            if fin:
                data = b"".join(parts)
                if first_op == OP_TEXT:
                    return data.decode("utf-8", errors="replace")
                # binary messages are not used by IS-12: ignore

    def _send(self, op: int, payload: bytes):
        hdr = bytes([0x80 | op])
        n = len(payload)
        if n < 126:
            hdr += bytes([n])
        elif n < 65536:
            hdr += bytes([126]) + struct.pack(">H", n)
        else:
            hdr += bytes([127]) + struct.pack(">Q", n)
        with self.send_lock:
            if self.closed:
                raise WebSocketClosed()
            self.wfile.write(hdr + payload)
            self.wfile.flush()

    def send(self, text: str):
        try:
            self._send(OP_TEXT, text.encode("utf-8"))
        except OSError as e:
            self.closed = True
            raise WebSocketClosed() from e

    def close(self):
        if not self.closed:
            try:
                self._send(OP_CLOSE, struct.pack(">H", 1000))
            except (OSError, WebSocketClosed):
                pass
            self.closed = True
