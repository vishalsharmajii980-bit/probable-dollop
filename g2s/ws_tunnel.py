"""
Reverse WebSocket Proxy Tunnel Server for TheDrunkBots G2S.

Allows Android phones (running the native Foreground Service APK) and PCs (running
the PC Tunnel Software) to establish an outbound WebSocket connection to `/api/tunnels/ws`.
For each connected device, the server binds a local HTTP/HTTPS forward proxy port
(`http://127.0.0.1:<port>`) and multiplexes TCP streams over the WebSocket using
4-byte big-endian stream IDs on binary frames.
"""
import asyncio
import json
import re
import struct
import time
from typing import Any

from aiohttp import WSMsgType, web


class WsDeviceSession:
    def __init__(self, device_id: str, ws: web.WebSocketResponse, manager: "WsTunnelManager"):
        self.device_id = device_id
        self.ws = ws
        self.manager = manager
        self.bridge_port: int = 0
        self.server: asyncio.AbstractServer | None = None
        self.streams: dict[int, asyncio.StreamWriter] = {}
        self.open_Waiters: dict[int, asyncio.Future] = {}
        self._next_sid = 1
        self.closed = False
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.total_requests = 0
        self._send_lock = asyncio.Lock()

    @property
    def local_proxy_url(self) -> str | None:
        if self.bridge_port and not self.closed:
            return f"http://127.0.0.1:{self.bridge_port}"
        return None

    async def start_local_proxy(self) -> int:
        self.server = await asyncio.start_server(
            lambda r, w: self._handle_local_client(r, w),
            host="127.0.0.1",
            port=self.bridge_port or 0,
        )
        socks = self.server.sockets or []
        self.bridge_port = socks[0].getsockname()[1] if socks else 0
        return self.bridge_port

    async def rebind_local_proxy(self) -> int:
        """Rebind the local TCP proxy server to the same port so hot-reloaded _handle_local_client takes effect."""
        if self.closed or not self.bridge_port:
            return self.bridge_port
        try:
            old_srv = self.server
            if old_srv is not None:
                old_srv.close()
                try:
                    await asyncio.wait_for(old_srv.wait_closed(), timeout=2.0)
                except Exception:
                    pass
            return await self.start_local_proxy()
        except Exception:
            return self.bridge_port

    async def send_json(self, data: dict):
        if self.closed or self.ws.closed:
            return
        async with self._send_lock:
            await self.ws.send_str(json.dumps(data))

    async def send_binary(self, sid: int, payload: bytes):
        if self.closed or self.ws.closed:
            return
        frame = struct.pack(">I", sid) + payload
        async with self._send_lock:
            await self.ws.send_bytes(frame)

    async def _handle_local_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        sid = self._next_sid
        self._next_sid = (self._next_sid % 2_000_000_000) + 1
        try:
            head_buf = b""
            while b"\r\n\r\n" not in head_buf:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=20.0)
                if not chunk:
                    writer.close()
                    return
                head_buf += chunk
                if len(head_buf) > 65536:
                    writer.close()
                    return

            head_bytes, rest = head_buf.split(b"\r\n\r\n", 1)
            lines = head_bytes.decode("latin-1", "ignore").split("\r\n")
            if not lines or not lines[0]:
                writer.close()
                return
            parts = lines[0].split(" ", 2)
            if len(parts) < 3:
                writer.close()
                return
            method, target, ver = parts[0], parts[1], parts[2]
            headers = lines[1:]

            init_payload = b""
            is_connect = method.upper() == "CONNECT"
            if is_connect:
                if ":" in target:
                    host, port_s = target.rsplit(":", 1)
                    port = int(port_s)
                else:
                    host, port = target, 443
                init_payload = rest
            else:
                m = re.match(r"^http://([^/:]+)(?::(\d+))?(/.*)?$", target, re.I)
                if not m:
                    writer.close()
                    return
                host = m.group(1)
                port = int(m.group(2) or 80)
                path = m.group(3) or "/"
                keep = [
                    h for h in headers
                    if not h.lower().startswith(("proxy-", "connection:"))
                ]
                req_head = (
                    f"{method} {path} {ver}\r\n"
                    + "\r\n".join(keep + ["Connection: close"])
                    + "\r\n\r\n"
                )
                init_payload = req_head.encode("latin-1", "ignore") + rest

            host_low = (host or "").strip().lower()
            is_direct_cdn = (
                host_low in ("www.google.com", "google.com", "recaptcha.net", "www.recaptcha.net", "cdnjs.cloudflare.com", "cdn.jsdelivr.net")
                or host_low.endswith((".gstatic.com", ".googleapis.com", ".recaptcha.net"))
            )
            if is_direct_cdn:
                rem_reader, rem_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=12.0
                )
                try:
                    if is_connect:
                        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        await writer.drain()
                    if init_payload:
                        rem_writer.write(init_payload)
                        await rem_writer.drain()

                    async def _pipe(r_in: asyncio.StreamReader, w_out: asyncio.StreamWriter):
                        try:
                            while not self.closed:
                                buf = await r_in.read(32768)
                                if not buf:
                                    break
                                w_out.write(buf)
                                await w_out.drain()
                        except Exception:
                            pass
                        finally:
                            try:
                                w_out.close()
                            except Exception:
                                pass

                    await asyncio.gather(_pipe(reader, rem_writer), _pipe(rem_reader, writer), return_exceptions=True)
                finally:
                    try:
                        rem_writer.close()
                    except Exception:
                        pass
                return

            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            self.open_Waiters[sid] = fut
            self.streams[sid] = writer
            self.total_requests += 1

            import base64
            await self.send_json({
                "type": "open",
                "stream_id": sid,
                "host": host,
                "port": port,
                "init_b64": base64.b64encode(init_payload).decode("ascii") if init_payload else "",
            })

            ok = await asyncio.wait_for(fut, timeout=22.0)
            if not ok:
                writer.close()
                return

            if is_connect:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

            while not self.closed and not writer.is_closing():
                data = await reader.read(32768)
                if not data:
                    break
                await self.send_binary(sid, data)
        except Exception:
            pass
        finally:
            self.open_Waiters.pop(sid, None)
            self.streams.pop(sid, None)
            try:
                await self.send_json({"type": "close", "stream_id": sid})
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

    async def on_binary_frame(self, data: bytes):
        if len(data) < 4:
            return
        sid = struct.unpack(">I", data[:4])[0]
        payload = data[4:]
        w = self.streams.get(sid)
        if not w or w.is_closing():
            return
        try:
            w.write(payload)
            await w.drain()
        except Exception:
            self.streams.pop(sid, None)
            try:
                w.close()
            except Exception:
                pass

    async def on_control_msg(self, msg: dict):
        self.last_seen = time.time()
        mtype = msg.get("type")
        sid = int(msg.get("stream_id") or 0)
        if mtype == "open_ok":
            fut = self.open_Waiters.pop(sid, None)
            if fut and not fut.done():
                fut.set_result(True)
        elif mtype == "open_err":
            fut = self.open_Waiters.pop(sid, None)
            if fut and not fut.done():
                fut.set_result(False)
        elif mtype == "close":
            fut = self.open_Waiters.pop(sid, None)
            if fut and not fut.done():
                fut.set_result(False)
            w = self.streams.pop(sid, None)
            if w:
                try:
                    w.close()
                except Exception:
                    pass

    async def close(self):
        if self.closed:
            return
        self.closed = True
        for fut in list(self.open_Waiters.values()):
            if not fut.done():
                fut.set_result(False)
        self.open_Waiters.clear()
        for w in list(self.streams.values()):
            try:
                w.close()
            except Exception:
                pass
        self.streams.clear()
        if self.server:
            try:
                self.server.close()
                await self.server.wait_closed()
            except Exception:
                pass
            self.server = None
        if not self.ws.closed:
            try:
                await self.ws.close()
            except Exception:
                pass


class WsTunnelManager:
    def __init__(self, db: Any):
        self.db = db
        self.sessions: dict[str, WsDeviceSession] = {}

    def get_session(self, device_id: str) -> WsDeviceSession | None:
        sess = self.sessions.get(device_id)
        if sess and not sess.closed and not sess.ws.closed:
            return sess
        return None

    async def handle_ws(self, req: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=25.0, max_msg_size=16 * 1024 * 1024)
        await ws.prepare(req)

        device_id: str | None = None
        session: WsDeviceSession | None = None
        peer_ip = (
            req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or req.remote
            or ""
        )

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except Exception:
                        continue
                    mtype = data.get("type")
                    if mtype == "hello":
                        device_id = str(data.get("device_id") or "").strip()
                        if not device_id:
                            await ws.close(code=4000, message=b"device_id required")
                            break
                        old = self.sessions.pop(device_id, None)
                        if old:
                            await old.close()
                        session = WsDeviceSession(device_id, ws, self)
                        port = await session.start_local_proxy()
                        self.sessions[device_id] = session

                        pinggy_px = (data.get("pinggy_proxy") or "").strip() or None
                        proxy_url = pinggy_px or session.local_proxy_url
                        await self.db.register_tunnel_device({
                            "device_id": device_id,
                            "device_name": data.get("device_name") or device_id,
                            "device_type": data.get("device_type") or "pc",
                            "platform_info": data.get("platform_info") or "",
                            "tunnel_mode": "hybrid" if pinggy_px else "ws",
                            "proxy_url": proxy_url,
                            "ws_bridge_url": session.local_proxy_url,
                            "pinggy_proxy": pinggy_px,
                            "public_ip": data.get("public_ip") or peer_ip,
                            "isp": data.get("isp") or "",
                            "country": data.get("country") or "",
                            "status": "online",
                            "ws_connected": True,
                        })
                        await session.send_json({
                            "type": "welcome",
                            "device_id": device_id,
                            "bridge_port": port,
                        })
                    elif mtype == "ping" and session and device_id:
                        session.last_seen = time.time()
                        pinggy_px = (data.get("pinggy_proxy") or "").strip() or None
                        proxy_url = pinggy_px or session.local_proxy_url
                        await self.db.heartbeat_tunnel_device(
                            device_id,
                            {
                                "proxy_url": proxy_url,
                                "ws_bridge_url": session.local_proxy_url,
                                "pinggy_proxy": pinggy_px,
                                "public_ip": data.get("public_ip") or peer_ip,
                                "isp": data.get("isp"),
                                "country": data.get("country"),
                                "status": "online",
                                "ws_connected": True,
                                "total_requests": max(
                                    int(data.get("conns") or 0), session.total_requests
                                ),
                            },
                        )
                        await session.send_json({"type": "pong", "ts": time.time()})
                    elif session:
                        await session.on_control_msg(data)
                elif msg.type == WSMsgType.BINARY and session:
                    session.last_seen = time.time()
                    await session.on_binary_frame(msg.data)
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        except Exception:
            pass
        finally:
            if session:
                await session.close()
            if device_id and self.sessions.get(device_id) is session:
                self.sessions.pop(device_id, None)
                try:
                    await self.db.mark_tunnel_ws_disconnected(device_id)
                except Exception:
                    pass
        return ws
