"""
TheDrunkBots — Auto Tunnel Maker & Sync Client for PC (Windows / macOS / Linux)
Zero external dependencies required (runs on pure Python 3 standard library;
also uses pymongo automatically if installed).

Features:
  1. Local authenticated HTTP/HTTPS CONNECT proxy server on 127.0.0.1:8899
  2. Automatic Pinggy TCP Tunnel creation & 50-minute auto-refresh (before 60m expiry)
     with automatic non-interactive SSH handling (never hangs on password prompt)
  3. Built-in RFC-6455 Reverse WebSocket Tunnel client to Backend (/api/tunnels/ws)
  4. Automatic Internet Connection Monitor (auto-pauses when offline, auto-reconnects
     and re-syncs as soon as internet is restored)
  5. Automatic real-time registration & 15s heartbeat sync with Backend Admin Panel
     (/api/tunnels/register & /api/tunnels/heartbeat) + direct MongoDB Atlas sync
  6. Modern Dark Tkinter GUI + Silent Background Mode (--background / start_background.vbs)
     + One-Click Windows Startup Auto-Run installer
"""
import base64
import hashlib
import json
import os
import platform
import random
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
CFG_FILE = os.path.join(HERE, "tunnel_config.json")

DEFAULT_MONGO_URI = (
    "mongodb+srv://shauryasharma9940_db_user:hi1OxTU3GdXFtRLf"
    "@g2sv2.fnvvosz.mongodb.net/?appName=G2SV2"
)


def _default_device_id() -> str:
    node = platform.node() or "pc"
    clean = re.sub(r"[^a-zA-Z0-9]+", "-", node).strip("-").lower()[:16] or "pc"
    mac = uuid.getnode()
    suffix = hashlib.sha1(f"{node}-{mac}".encode()).hexdigest()[:6]
    return f"pc-{clean}-{suffix}"


def load_config() -> dict:
    cfg = {
        "device_id": _default_device_id(),
        "device_name": f"{platform.node() or 'My-PC'} ({platform.system()})",
        "server_url": os.environ.get("G2S_SERVER_URL", "").strip(),
        "secret": os.environ.get("G2S_ADMIN_PASSWORD", "admin123").strip(),
        "mongo_uri": os.environ.get("G2S_MONGO_URI", DEFAULT_MONGO_URI).strip(),
        "local_port": int(os.environ.get("HP_PORT", "8899")),
        "proxy_user": "g2s",
        "proxy_pass": os.environ.get("HP_PASS") or secrets.token_hex(5),
        "auto_refresh_minutes": 50,
    }
    if os.path.exists(CFG_FILE):
        try:
            with open(CFG_FILE, encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    for k, v in saved.items():
                        if v not in (None, ""):
                            cfg[k] = v
        except Exception:
            pass
    save_config(cfg)
    return cfg


def save_config(cfg: dict):
    try:
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


class TunnelAgent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.running = True
        self.local_port = int(cfg.get("local_port") or 8899)
        self.user = cfg.get("proxy_user") or "g2s"
        self.password = cfg.get("proxy_pass") or secrets.token_hex(5)
        self.auth_token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()

        self.internet_online = True
        self.public_ip = ""
        self.isp = ""
        self.country = ""
        self.pinggy_url: str | None = None
        self.ws_connected = False
        self.ws_bridge_port = 0
        self.backend_synced = False
        self.last_sync_ts = 0.0
        self.tunnel_started_at = 0.0
        self.total_conns = 0
        self.status_text = "Initializing…"
        self.logs: list[str] = []

        self._ssh_proc: subprocess.Popen | None = None
        self._force_refresh_event = threading.Event()
        self._mongo_col = None
        self._mongo_settings_col = None
        self._init_mongo()

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self.logs.append(line)
        if len(self.logs) > 200:
            self.logs = self.logs[-200:]
        print(line, flush=True)

    def _init_mongo(self):
        uri = (self.cfg.get("mongo_uri") or "").strip()
        if not uri:
            return
        try:
            import pymongo
            client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=6000)
            db = client["g2sv2"]
            self._mongo_col = db["tunnels"]
            self._mongo_settings_col = db["settings"]
            doc = self._mongo_settings_col.find_one({"_id": "global"}) or {}
            if not self.cfg.get("server_url") and doc.get("public_server_url"):
                self.cfg["server_url"] = str(doc["public_server_url"]).strip()
            if doc.get("admin_password") and self.cfg.get("secret") == "admin123":
                self.cfg["secret"] = str(doc["admin_password"]).strip()
            save_config(self.cfg)
            self.log("Connected to MongoDB Atlas for automatic cloud sync")
        except Exception:
            self._mongo_col = None

    # ------------------------------------------------- 1. Local HTTP/HTTPS Proxy
    def _pipe(self, a: socket.socket, b: socket.socket):
        socks = [a, b]
        try:
            while self.running:
                r, _, x = select.select(socks, [], socks, 120)
                if x or not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            pass
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

    def _handle_proxy_client(self, c: socket.socket):
        try:
            c.settimeout(30)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(65536)
                if not chunk:
                    return c.close()
                buf += chunk
                if len(buf) > 65536:
                    return c.close()
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1", "ignore").split("\r\n")
            method, target, ver = lines[0].split(" ", 2)
            headers = lines[1:]
            auth = next(
                (h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("proxy-authorization:")),
                "",
            )
            if auth != f"Basic {self.auth_token}":
                c.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="g2s"\r\nContent-Length: 0\r\n\r\n'
                )
                return c.close()
            self.total_conns += 1
            if method.upper() == "CONNECT":
                host, port = target.rsplit(":", 1)
                up = socket.create_connection((host, int(port)), timeout=20)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                m = re.match(r"http://([^/:]+)(?::(\d+))?(/.*)?$", target, re.I)
                if not m:
                    return c.close()
                host, port, path = m.group(1), int(m.group(2) or 80), m.group(3) or "/"
                up = socket.create_connection((host, port), timeout=20)
                keep = [h for h in headers if not h.lower().startswith(("proxy-", "connection:"))]
                req = f"{method} {path} {ver}\r\n" + "\r\n".join(keep + ["Connection: close"]) + "\r\n\r\n"
                up.sendall(req.encode("latin-1", "ignore") + rest)
            c.settimeout(None)
            up.settimeout(None)
            self._pipe(c, up)
        except Exception:
            try:
                c.close()
            except OSError:
                pass

    def serve_local_proxy(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", self.local_port))
        except OSError:
            s.bind(("127.0.0.1", 0))
            self.local_port = s.getsockname()[1]
        s.listen(256)
        self.log(f"Local authenticated proxy listening on 127.0.0.1:{self.local_port}")
        while self.running:
            try:
                c, _ = s.accept()
                threading.Thread(target=self._handle_proxy_client, args=(c,), daemon=True).start()
            except Exception:
                time.sleep(0.5)

    # ------------------------------------------------- 2. Internet & IP Monitor
    def check_internet_and_ip(self) -> bool:
        try:
            req = urllib.request.Request(
                "https://ipinfo.io/json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                info = json.loads(resp.read().decode("utf-8", "ignore"))
                self.public_ip = info.get("ip") or self.public_ip
                self.isp = info.get("org") or self.isp
                city = info.get("city") or ""
                country = info.get("country") or ""
                self.country = f"{city}, {country}".strip(", ")
                self.internet_online = True
                return True
        except Exception:
            for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
                try:
                    with socket.create_connection((host, port), timeout=4):
                        self.internet_online = True
                        return True
                except Exception:
                    continue
            self.internet_online = False
            return False

    # ------------------------------------------------- 3. Sync with Backend & MongoDB
    def _build_device_payload(self, status: str = "online") -> dict:
        plat = f"{platform.system()} {platform.release()} ({platform.machine()})"
        mode = "hybrid" if (self.pinggy_url and self.ws_connected) else ("ws" if self.ws_connected else "pinggy")
        return {
            "device_id": self.cfg["device_id"],
            "device_name": self.cfg.get("device_name") or self.cfg["device_id"],
            "device_type": "pc",
            "platform_info": plat,
            "tunnel_mode": mode,
            "proxy_url": self.pinggy_url,
            "pinggy_proxy": self.pinggy_url,
            "public_ip": self.public_ip,
            "isp": self.isp,
            "country": self.country,
            "status": status,
            "total_requests": self.total_conns,
            "last_seen": time.time(),
        }

    def sync_now(self, status: str = "online", register: bool = False):
        payload = self._build_device_payload(status=status)
        synced = False

        # A. Direct MongoDB Atlas sync (works even without server_url!)
        if self._mongo_col is not None:
            try:
                existing = self._mongo_col.find_one({"_id": payload["device_id"]}) or {}
                doc = {
                    **existing,
                    **payload,
                    "enabled": existing.get("enabled", True),
                    "is_primary": existing.get("is_primary", False),
                    "connected_at": existing.get("connected_at") or time.time(),
                }
                if not payload.get("proxy_url") and existing.get("ws_bridge_url"):
                    doc["proxy_url"] = existing["ws_bridge_url"]
                self._mongo_col.update_one({"_id": payload["device_id"]}, {"$set": doc}, upsert=True)
                synced = True
            except Exception:
                pass

        # B. Backend HTTP API sync (/api/tunnels/register or /api/tunnels/heartbeat)
        srv = (self.cfg.get("server_url") or "").strip().rstrip("/")
        if srv:
            endpoint = "/api/tunnels/register" if register else "/api/tunnels/heartbeat"
            try:
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    f"{srv}{endpoint}",
                    data=body,
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.cfg.get('secret') or 'admin123'}",
                        "X-Tunnel-Secret": str(self.cfg.get("secret") or "admin123"),
                    },
                )
                with urllib.request.urlopen(req, timeout=10) as r:
                    if r.status == 200:
                        synced = True
            except Exception:
                pass

        self.backend_synced = synced
        if synced:
            self.last_sync_ts = time.time()

    def heartbeat_loop(self):
        first = True
        while self.running:
            try:
                online = self.check_internet_and_ip()
                if online:
                    self.sync_now(
                        status="online" if (self.pinggy_url or self.ws_connected) else "reconnecting",
                        register=first,
                    )
                    first = False
                else:
                    self.status_text = "Waiting for Internet Connection…"
            except Exception:
                pass
            time.sleep(15)

    # ------------------------------------------------- 4. Pinggy SSH Auto-Tunnel
    def force_refresh_tunnel(self):
        self._force_refresh_event.set()
        if self._ssh_proc and self._ssh_proc.poll() is None:
            try:
                self._ssh_proc.terminate()
            except Exception:
                pass

    def pinggy_tunnel_loop(self):
        refresh_sec = max(10, int(self.cfg.get("auto_refresh_minutes") or 50)) * 60
        while self.running:
            if not self.check_internet_and_ip():
                self.status_text = "No Internet — waiting to reconnect…"
                time.sleep(4)
                continue

            self._force_refresh_event.clear()
            null_known = "NUL" if os.name == "nt" else "/dev/null"
            cmd = [
                "ssh",
                "-p", "443",
                "-T",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", "ServerAliveInterval=25",
                "-o", "ServerAliveCountMax=3",
                "-o", "ConnectTimeout=15",
                "-o", f"UserKnownHostsFile={null_known}",
                f"-R0:127.0.0.1:{self.local_port}",
                "tcp@a.pinggy.io",
            ]
            self.status_text = "Opening Pinggy TCP tunnel…"
            self.log("Opening Pinggy TCP tunnel…")
            try:
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    creationflags=creationflags,
                )
                self._ssh_proc = proc
                try:
                    proc.stdin.write("\n")
                    proc.stdin.flush()
                except Exception:
                    pass

                def _watchdog(p=proc):
                    t_start = time.time()
                    while self.running and p.poll() is None:
                        if self._force_refresh_event.is_set() or (time.time() - t_start >= refresh_sec):
                            self.log("Auto-refreshing Pinggy tunnel before 60m expiry…")
                            try:
                                p.terminate()
                            except Exception:
                                pass
                            break
                        if not self.internet_online:
                            try:
                                p.terminate()
                            except Exception:
                                pass
                            break
                        time.sleep(3)

                threading.Thread(target=_watchdog, daemon=True).start()

                for line in proc.stdout:
                    m = re.search(r"tcp://([\w.-]+):(\d+)", line)
                    if m:
                        new_url = f"http://{self.user}:{self.password}@{m.group(1)}:{m.group(2)}"
                        if new_url != self.pinggy_url:
                            self.pinggy_url = new_url
                            self.tunnel_started_at = time.time()
                            self.status_text = "Connected & Active"
                            self.log(f"Tunnel Ready: {new_url}")
                            self.sync_now(status="online", register=True)
            except FileNotFoundError:
                self.log("OpenSSH client not found — using Reverse WebSocket Tunnel mode")
                time.sleep(30)
                continue
            except Exception as e:
                self.log(f"Pinggy tunnel error: {e}")

            self.pinggy_url = None
            if self.running:
                self.status_text = "Reconnecting tunnel in 3s…"
                time.sleep(3)

    # ------------------------------------------------- 5. Reverse WebSocket Tunnel
    def ws_tunnel_loop(self):
        while self.running:
            srv = (self.cfg.get("server_url") or "").strip().rstrip("/")
            if not srv or not self.internet_online:
                time.sleep(5)
                continue
            try:
                self._run_single_ws_session(srv)
            except Exception as e:
                self.ws_connected = False
                self.log(f"WebSocket tunnel disconnected ({e}) — retrying in 5s")
                time.sleep(5)

    def _run_single_ws_session(self, srv: str):
        from urllib.parse import urlparse
        p = urlparse(srv)
        use_tls = p.scheme.lower() == "https"
        host = p.hostname or "127.0.0.1"
        port = p.port or (443 if use_tls else 80)
        secret = str(self.cfg.get("secret") or "admin123")
        path = f"/api/tunnels/ws?key={urllib.parse.quote(secret)}"

        raw_sock = socket.create_connection((host, port), timeout=15)
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Authorization: Bearer {secret}\r\n"
            f"X-Tunnel-Secret: {secret}\r\n\r\n"
        )
        sock.sendall(handshake.encode("utf-8"))

        resp_buf = bytearray()
        while not resp_buf.endswith(b"\r\n\r\n"):
            ch = sock.recv(1)
            if not ch:
                raise ConnectionError("WebSocket handshake EOF")
            resp_buf.extend(ch)
            if len(resp_buf) > 8192:
                raise ConnectionError("WebSocket handshake header too large")
        status_line = bytes(resp_buf).split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket rejected: {status_line}")

        sock.settimeout(60.0)
        send_lock = threading.Lock()
        streams: dict[int, socket.socket] = {}

        def ws_send(opcode: int, payload: bytes):
            mask_key = os.urandom(4)
            header = bytearray([0x80 | (opcode & 0x0F)])
            length = len(payload)
            if length < 126:
                header.append(0x80 | length)
            elif length < 65536:
                header.append(0x80 | 126)
                header.extend(struct.pack(">H", length))
            else:
                header.append(0x80 | 127)
                header.extend(struct.pack(">Q", length))
            header.extend(mask_key)
            masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
            with send_lock:
                sock.sendall(bytes(header) + masked)

        def ws_send_json(obj: dict):
            ws_send(0x1, json.dumps(obj).encode("utf-8"))

        def ws_send_bin(sid: int, data: bytes):
            ws_send(0x2, struct.pack(">I", sid) + data)

        def _recv_exact(n: int) -> bytes:
            out = bytearray()
            while len(out) < n:
                chunk = sock.recv(n - len(out))
                if not chunk:
                    raise ConnectionError("WebSocket EOF")
                out.extend(chunk)
            return bytes(out)

        def _open_stream(sid: int, target_host: str, target_port: int, init_b64: str):
            try:
                up = socket.create_connection((target_host, int(target_port)), timeout=18)
                up.settimeout(120)
                if init_b64:
                    up.sendall(base64.b64decode(init_b64))
                streams[sid] = up
                self.total_conns += 1
                ws_send_json({"type": "open_ok", "stream_id": sid})
                while self.running:
                    data = up.recv(32768)
                    if not data:
                        break
                    ws_send_bin(sid, data)
            except Exception as e:
                try:
                    ws_send_json({"type": "open_err", "stream_id": sid, "error": str(e)})
                except Exception:
                    pass
            finally:
                up_s = streams.pop(sid, None)
                if up_s:
                    try:
                        up_s.close()
                    except Exception:
                        pass
                try:
                    ws_send_json({"type": "close", "stream_id": sid})
                except Exception:
                    pass

        # Send hello
        hello = self._build_device_payload(status="online")
        hello["type"] = "hello"
        ws_send_json(hello)
        self.ws_connected = True
        self.status_text = "Connected (WebSocket + Pinggy)" if self.pinggy_url else "Connected (WebSocket Tunnel)"
        self.log(f"Reverse WebSocket Tunnel connected to {srv}")

        def _ws_pinger():
            while self.running and self.ws_connected:
                time.sleep(20)
                if not self.ws_connected:
                    break
                try:
                    ws_send_json({
                        "type": "ping",
                        "public_ip": self.public_ip,
                        "isp": self.isp,
                        "country": self.country,
                        "pinggy_proxy": self.pinggy_url,
                        "conns": self.total_conns,
                    })
                except Exception:
                    break

        threading.Thread(target=_ws_pinger, daemon=True).start()

        try:
            while self.running:
                b0, b1 = _recv_exact(2)
                opcode = b0 & 0x0F
                masked = (b1 & 0x80) != 0
                length = b1 & 0x7F
                if length == 126:
                    length = struct.unpack(">H", _recv_exact(2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", _recv_exact(8))[0]
                mask_key = _recv_exact(4) if masked else b""
                payload = _recv_exact(length) if length else b""
                if masked:
                    payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))

                if opcode == 0x8:  # Close
                    break
                elif opcode == 0x9:  # Ping
                    ws_send(0xA, payload)
                elif opcode == 0x1:  # Text
                    msg = json.loads(payload.decode("utf-8", "ignore"))
                    mtype = msg.get("type")
                    if mtype == "welcome":
                        self.ws_bridge_port = int(msg.get("bridge_port") or 0)
                        self.backend_synced = True
                        self.last_sync_ts = time.time()
                    elif mtype == "open":
                        sid = int(msg.get("stream_id") or 0)
                        thost = str(msg.get("host") or "")
                        tport = int(msg.get("port") or 443)
                        ib64 = str(msg.get("init_b64") or "")
                        threading.Thread(
                            target=_open_stream,
                            args=(sid, thost, tport, ib64),
                            daemon=True,
                        ).start()
                    elif mtype == "close":
                        sid = int(msg.get("stream_id") or 0)
                        up_s = streams.pop(sid, None)
                        if up_s:
                            try:
                                up_s.close()
                            except Exception:
                                pass
                elif opcode == 0x2:  # Binary
                    if len(payload) >= 4:
                        sid = struct.unpack(">I", payload[:4])[0]
                        up_s = streams.get(sid)
                        if up_s:
                            try:
                                up_s.sendall(payload[4:])
                            except Exception:
                                streams.pop(sid, None)
                                try:
                                    up_s.close()
                                except Exception:
                                    pass
        finally:
            self.ws_connected = False
            for s in list(streams.values()):
                try:
                    s.close()
                except Exception:
                    pass
            streams.clear()
            try:
                sock.close()
            except Exception:
                pass

    def start_all_threads(self):
        threading.Thread(target=self.serve_local_proxy, daemon=True).start()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.pinggy_tunnel_loop, daemon=True).start()
        threading.Thread(target=self.ws_tunnel_loop, daemon=True).start()


def install_windows_autostart() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Windows Startup folder is only applicable on Windows."
    try:
        startup_dir = os.path.join(
            os.environ.get("APPDATA", ""),
            r"Microsoft\Windows\Start Menu\Programs\Startup",
        )
        os.makedirs(startup_dir, exist_ok=True)
        vbs_path = os.path.join(startup_dir, "TheDrunkBots_Tunnel_AutoStart.vbs")
        script_path = os.path.abspath(__file__)
        pyw = sys.executable.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pyw):
            pyw = sys.executable
        vbs_content = (
            'Set WshShell = CreateObject("WScript.Shell")\n'
            f'WshShell.CurrentDirectory = "{HERE}"\n'
            f'WshShell.Run """{pyw}"" ""{script_path}"" --background", 0, False\n'
        )
        with open(vbs_path, "w", encoding="utf-8") as f:
            f.write(vbs_content)
        return True, f"Installed auto-start script:\n{vbs_path}"
    except Exception as e:
        return False, str(e)


def run_gui(agent: TunnelAgent):
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("TheDrunkBots — PC Tunnel Maker & Auto-Sync")
    root.geometry("650x560")
    root.configure(bg="#0b0f19")

    hdr = tk.Frame(root, bg="#111827", padx=16, pady=12)
    hdr.pack(fill="x")
    tk.Label(
        hdr,
        text="🍹 TheDrunkBots — Auto Tunnel Maker (PC)",
        font=("Segoe UI", 14, "bold"),
        fg="#f8fafc",
        bg="#111827",
    ).pack(anchor="w")
    status_lbl = tk.Label(
        hdr,
        text="Status: Starting…",
        font=("Segoe UI", 10, "bold"),
        fg="#34d399",
        bg="#111827",
    )
    status_lbl.pack(anchor="w", pady=(2, 0))

    body = tk.Frame(root, bg="#0b0f19", padx=16, pady=12)
    body.pack(fill="both", expand=True)

    def _row(parent, label_text, default_val="", show=None):
        f = tk.Frame(parent, bg="#0b0f19", pady=4)
        f.pack(fill="x")
        tk.Label(
            f, text=label_text, width=18, anchor="w",
            font=("Segoe UI", 9, "bold"), fg="#94a3b8", bg="#0b0f19"
        ).pack(side="left")
        var = tk.StringVar(value=default_val)
        ent = tk.Entry(
            f, textvariable=var, show=show,
            font=("Consolas", 10), bg="#1e293b", fg="#f8fafc",
            insertbackground="#f8fafc", relief="flat"
        )
        ent.pack(side="left", fill="x", expand=True, ipady=4, padx=(6, 0))
        return var

    dev_name_var = _row(body, "Device Name:", agent.cfg.get("device_name", ""))
    srv_url_var = _row(body, "Backend Server URL:", agent.cfg.get("server_url", ""))
    secret_var = _row(body, "Admin Password:", agent.cfg.get("secret", ""), show="•")

    info_box = tk.Frame(body, bg="#111827", padx=12, pady=10)
    info_box.pack(fill="x", pady=(10, 8))

    ip_lbl = tk.Label(info_box, text="Public IP: detecting…", font=("Consolas", 9), fg="#cbd5e1", bg="#111827", anchor="w")
    ip_lbl.pack(fill="x")
    tun_lbl = tk.Label(info_box, text="Active Tunnel: opening…", font=("Consolas", 9), fg="#38bdf8", bg="#111827", anchor="w")
    tun_lbl.pack(fill="x", pady=(2, 0))
    sync_lbl = tk.Label(info_box, text="Cloud Sync: waiting…", font=("Consolas", 9), fg="#a78bfa", bg="#111827", anchor="w")
    sync_lbl.pack(fill="x", pady=(2, 0))

    btn_frame = tk.Frame(body, bg="#0b0f19", pady=6)
    btn_frame.pack(fill="x")

    def on_save_sync():
        agent.cfg["device_name"] = dev_name_var.get().strip() or agent.cfg["device_id"]
        agent.cfg["server_url"] = srv_url_var.get().strip().rstrip("/")
        agent.cfg["secret"] = secret_var.get().strip() or "admin123"
        save_config(agent.cfg)
        threading.Thread(target=lambda: agent.sync_now(status="online", register=True), daemon=True).start()
        agent.log("Saved configuration & triggered cloud sync.")

    def on_refresh():
        threading.Thread(target=agent.force_refresh_tunnel, daemon=True).start()

    def on_autostart():
        ok, msg = install_windows_autostart()
        if ok:
            messagebox.showinfo("Auto-Start Installed", msg)
        else:
            messagebox.showwarning("Auto-Start", msg)

    tk.Button(
        btn_frame, text="💾 Save & Sync Now", command=on_save_sync,
        bg="#6366f1", fg="#ffffff", font=("Segoe UI", 9, "bold"),
        relief="flat", padx=12, pady=6, cursor="hand2"
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btn_frame, text="🔄 Refresh Tunnel", command=on_refresh,
        bg="#0ea5e9", fg="#ffffff", font=("Segoe UI", 9, "bold"),
        relief="flat", padx=12, pady=6, cursor="hand2"
    ).pack(side="left", padx=(0, 8))

    if os.name == "nt":
        tk.Button(
            btn_frame, text="🚀 Run on Windows Boot", command=on_autostart,
            bg="#10b981", fg="#ffffff", font=("Segoe UI", 9, "bold"),
            relief="flat", padx=12, pady=6, cursor="hand2"
        ).pack(side="left")

    log_txt = tk.Text(
        body, height=11, bg="#090d16", fg="#94a3b8",
        font=("Consolas", 9), relief="flat", padx=8, pady=8
    )
    log_txt.pack(fill="both", expand=True, pady=(6, 0))

    last_log_len = [0]

    def _tick_ui():
        st = agent.status_text
        status_lbl.config(
            text=f"Status: {st}  •  Device ID: {agent.cfg['device_id']}  •  Requests: {agent.total_conns}",
            fg="#34d399" if (agent.pinggy_url or agent.ws_connected) else "#fbbf24",
        )
        ip_lbl.config(text=f"Public IP : {agent.public_ip or 'Detecting…'} ({agent.isp or 'ISP'} - {agent.country or ''})")
        tun_lbl.config(text=f"Tunnel URL: {agent.pinggy_url or ('WebSocket Tunnel Active' if agent.ws_connected else 'Connecting…')}")
        sync_lbl.config(
            text=f"Admin Sync: {'✔ Synced with Admin Panel & MongoDB' if agent.backend_synced else '⏳ Waiting for sync…'} "
                 f"(WS: {'Connected' if agent.ws_connected else 'Standby'})"
        )
        if len(agent.logs) != last_log_len[0]:
            last_log_len[0] = len(agent.logs)
            log_txt.delete("1.0", "end")
            log_txt.insert("end", "\n".join(agent.logs[-60:]))
            log_txt.see("end")
        root.after(1000, _tick_ui)

    _tick_ui()
    root.mainloop()


if __name__ == "__main__":
    cfg = load_config()
    agent = TunnelAgent(cfg)
    agent.start_all_threads()

    headless = (
        "--background" in sys.argv
        or "--headless" in sys.argv
        or "--no-gui" in sys.argv
        or (os.name != "nt" and not os.environ.get("DISPLAY"))
    )
    if not headless:
        try:
            run_gui(agent)
            sys.exit(0)
        except Exception as e:
            agent.log(f"GUI unavailable ({e}) — continuing in console/background mode")

    agent.log(f"Running in background mode (Device ID: {cfg['device_id']}). Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        agent.running = False
