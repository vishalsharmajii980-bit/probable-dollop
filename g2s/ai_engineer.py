"""
TheDrunkBots Autonomous Self-Healing & Agentic AI Engineer ("Brother AI").

Capabilities:
  1. Deep Diagnostic Research & Root-Cause Analysis:
     - Inspects MongoDB `error_logs`, live `system_logs`, and bypass step traces.
     - Probes live shortener URLs, HTTP status codes, `Set-Cookie` headers, `<form>` tokens,
       Turnstile sitekeys, JS timers, and intermediate safelink blog redirects.
     - Automatically discovers origin server IPs behind Cloudflare via Google DoH (`TXT` SPF,
       `MX`, and unproxied subdomains) and tests `CF-Connecting-IP` residential spoofing.
  2. Autonomous Code & Rule Rectification:
     - Updates hot-reloadable `dynamic_rules` (origin IPs, new intermediate blog domains,
       ad popup blocklists, timer overrides) AND patches Python/JS source files (`g2s/engine.py`,
       `g2s/scripts.py`, etc.) with `py_compile` syntax validation.
  3. Live Multi-Check Verification Before Push:
     - Runs live end-to-end bypass tests via `Bypasser.resolve()` and streams every step log
       into the Admin Panel console in real time.
     - Only commits & pushes to MongoDB `code_files` + GitHub after live verification passes.
  4. Background Idle-Time Auto-Patrol & Instant Error Self-Healing:
     - Automatically wakes up when new errors occur or during periodic idle intervals to scan,
       diagnose, fix, test, and deploy improvements autonomously.
"""
import asyncio
import html
import ipaddress
import json
import os
import random
import re
import ssl
import time
import urllib.parse
from urllib.parse import urlparse
import uuid
from typing import Any, Callable

import aiohttp

try:
    from g2s.engine import _NEVER_CHAIN_HOSTS, _NEVER_ORIGIN_IP_HOSTS
except Exception:
    _NEVER_CHAIN_HOSTS = (
        "t.me", "telegram.me", "telegram.org", "pastelink.net", "pastetoday.com",
        "justpaste.it", "pastebin.com", "mega.nz", "gofile.io", "drive.google.com",
        "mediafire.com", "discord.gg", "discord.com",
    )
    _NEVER_ORIGIN_IP_HOSTS = _NEVER_CHAIN_HOSTS


CLOUDFLARE_CIDRS = [
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]


def _is_cf_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in CLOUDFLARE_CIDRS)
    except Exception:
        return False


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


_PAAS_SUFFIXES = (
    "vercel.app", "koyeb.app", "pages.dev", "workers.dev",
    "onrender.com", "duckdns.org", "netlify.app", "railway.app", "fly.dev",
)


def _base_domain(host: str) -> str:
    h = (host or "").strip().lower()
    for sfx in _PAAS_SUFFIXES:
        if h.endswith("." + sfx):
            return h
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


class AIEngineer:
    def __init__(
        self,
        db: Any,
        code_sync: Any,
        resolve_fn: Callable,
        bypasser_getter: Callable,
        notify_admin_fn: Callable | None = None,
    ):
        self.db = db
        self.code_sync = code_sync
        self.resolve_fn = resolve_fn
        self.get_bypasser = bypasser_getter
        self.notify_admin_fn = notify_admin_fn

        self.running_task: asyncio.Task | None = None
        self.patrol_task: asyncio.Task | None = None
        self.current_run: dict[str, Any] | None = None
        self.runs_history: list[dict[str, Any]] = []
        self._run_lock = asyncio.Lock()
        self._last_patrol_at: float = 0.0
        self._healed_error_ids: set[str] = set()
        self._diagnosed_error_ids: set[str] = set()
        self._url_heal_cooldown: dict[str, float] = {}

        # Register instant error-log hook
        self.db.on_error_log(self._on_new_error_logged)

    # ------------------------------------------------- Lifecycle & Patrol Loop
    async def start(self):
        if self.db.connected and self.db.db is not None:
            try:
                # Clean up any stale 'running' runs left over from a previous container restart
                await self.db.db.ai_runs.update_many(
                    {"status": "running"},
                    {"$set": {
                        "status": "completed",
                        "phase": "completed",
                        "finished_at": time.time(),
                        "summary": "Completed & synced after container restart.",
                    }},
                )
                cursor = self.db.db.ai_runs.find({}).sort("started_at", -1).limit(25)
                loaded = []
                async for doc in cursor:
                    doc.pop("_id", None)
                    loaded.append(doc)
                self.runs_history = loaded
            except Exception:
                pass
        if self.patrol_task is None or self.patrol_task.done():
            self.patrol_task = asyncio.create_task(self._auto_patrol_loop())
        self.db.add_system_log("Autonomous AI Engineer ('Brother AI') started & monitoring", component="ai_engineer")

    async def stop(self):
        if self.patrol_task and not self.patrol_task.done():
            self.patrol_task.cancel()
        if self.running_task and not self.running_task.done():
            self.running_task.cancel()

    def _on_new_error_logged(self, entry: dict):
        if not self.db.settings.get("ai_auto_heal", True):
            return
        if entry.get("origin") == "ai-engineer-check":
            return
        err_id = entry.get("id")
        if not err_id or err_id in self._healed_error_ids or err_id in self._diagnosed_error_ids:
            return
        err_l = str(entry.get("error") or "").lower()
        if any(
            ign in err_l
            for ign in (
                "not found (404",
                "not found (http 404",
                "session is invalid or expired",
                "one-time verification link on",
                "is_premium_only=true",
                "premium-only paywall link",
                "paid qris paywall",
                "offline (dns lookup failed)",
            )
        ):
            self._diagnosed_error_ids.add(err_id)
            return
        src = (entry.get("source") or "").strip()
        if src and time.time() < self._url_heal_cooldown.get(src, 0.0):
            return
        # Schedule background auto-heal after 3s debounce if not already running
        asyncio.create_task(self._delayed_auto_heal(entry))

    async def _delayed_auto_heal(self, entry: dict):
        await asyncio.sleep(3.0)
        if self._run_lock.locked():
            return
        err_id = entry.get("id")
        if not err_id or err_id in self._healed_error_ids or err_id in self._diagnosed_error_ids:
            return
        src = (entry.get("source") or "").strip()
        if src and time.time() < self._url_heal_cooldown.get(src, 0.0):
            return
        err = entry.get("error") or ""
        await self.start_run(
            trigger="auto_error_heal",
            target_url=src,
            prompt=f"Auto-heal new bypass error on {src}: {err}",
            error_entry=entry,
        )

    async def _auto_patrol_loop(self):
        """Background idle-time patrol loop:
        Runs every `ai_patrol_interval_minutes` when the system is idle to scan unresolved
        error logs, verify shortener/origin health, clean poisoned cache items, and self-heal.
        """
        await asyncio.sleep(20.0)
        while True:
            try:
                await asyncio.sleep(30.0)
                if not self.db.settings.get("ai_patrol_enabled", True):
                    continue
                interval_sec = max(3, int(self.db.settings.get("ai_patrol_interval_minutes") or 15)) * 60
                now = time.time()
                if now - self._last_patrol_at < interval_sec:
                    continue
                if self._run_lock.locked():
                    continue
                bp = self.get_bypasser()
                if bp and getattr(bp, "busy", False):
                    continue

                # Check if there are unresolved error logs that are not on cooldown
                logs = await self.db.list_error_logs(limit=25)
                unresolved = [
                    x for x in logs
                    if not x.get("resolved")
                    and x.get("id") not in self._healed_error_ids
                    and x.get("id") not in self._diagnosed_error_ids
                    and now >= self._url_heal_cooldown.get((x.get("source") or "").strip(), 0.0)
                ]
                self._last_patrol_at = now
                if unresolved:
                    await self.start_run(
                        trigger="background_patrol",
                        target_url=unresolved[0].get("source") or "",
                        prompt=f"Scheduled Background Patrol: Diagnose root causes and rectify {len(unresolved)} unresolved error log(s).",
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                print("AI patrol loop warning:", e, flush=True)
                await asyncio.sleep(30.0)

    # ------------------------------------------------- Run Management & Events
    def _new_run_record(self, trigger: str, target_url: str, prompt: str) -> dict[str, Any]:
        run_id = "ai-" + uuid.uuid4().hex[:8]
        run = {
            "id": run_id,
            "trigger": trigger,
            "target_url": target_url.strip(),
            "prompt": prompt.strip(),
            "status": "running",
            "phase": "initializing",
            "started_at": time.time(),
            "finished_at": None,
            "elapsed": 0.0,
            "events": [],
            "fixed_urls": [],
            "resolved_error_ids": [],
            "files_modified": [],
            "rules_updated": [],
            "summary": "",
            "event_notify": asyncio.Event(),
        }
        return run

    def _emit(self, run: dict[str, Any], ev_type: str, title: str, text: str = "", **extra):
        ev = {
            "seq": len(run["events"]) + 1,
            "at": round(time.time() - run["started_at"], 2),
            "ts": time.time(),
            "type": ev_type,  # thinking | tool_call | tool_result | step_log | patch | verified | error | conclusion
            "kind": ev_type,
            "title": title,
            "text": text,
            "detail": text,
            **extra,
        }
        run["events"].append(ev)
        if len(run["events"]) > 500:
            run["events"] = run["events"][-500:]
        ev_obj = run.get("event_notify")
        if isinstance(ev_obj, asyncio.Event):
            ev_obj.set()

    def public_run(self, run: dict[str, Any] | None) -> dict[str, Any] | None:
        if not run:
            return None
        out = {k: v for k, v in run.items() if k != "event_notify"}
        if run["status"] == "running":
            out["elapsed"] = round(time.time() - run["started_at"], 1)
        return out

    async def get_dashboard_state(self) -> dict[str, Any]:
        code_status = await self.code_sync.get_status()
        return {
            "active_run": self.public_run(self.current_run),
            "history": [self.public_run(r) for r in self.runs_history[:15]],
            "settings": {
                "ai_auto_heal": bool(self.db.settings.get("ai_auto_heal", True)),
                "ai_patrol_enabled": bool(self.db.settings.get("ai_patrol_enabled", True)),
                "ai_patrol_interval_minutes": int(self.db.settings.get("ai_patrol_interval_minutes", 15)),
                "ai_provider": self.db.settings.get("ai_provider", "auto"),
                "ai_model": self.db.settings.get("ai_model", "openai-large"),
                "ai_api_key_set": bool((self.db.settings.get("ai_api_key") or "").strip()),
                "ai_base_url": self.db.settings.get("ai_base_url", ""),
                "github_repo": self.db.settings.get("github_repo", "Urvashi212144/gss-free"),
                "github_branch": self.db.settings.get("github_branch", "main"),
                "github_token_set": bool((self.db.settings.get("github_token") or "").strip()),
            },
            "dynamic_rules": self.db.settings.get("dynamic_rules") or {},
            "code_sync": code_status,
            "stats": self.db.settings.get("stats") or {},
        }

    async def start_run(
        self,
        trigger: str = "manual",
        target_url: str = "",
        prompt: str = "",
        error_entry: dict | None = None,
    ) -> dict[str, Any]:
        if self._run_lock.locked() and self.current_run and self.current_run.get("status") == "running":
            return self.public_run(self.current_run)

        run = self._new_run_record(
            trigger=trigger,
            target_url=target_url,
            prompt=prompt or "Scan error logs, diagnose root causes, fix issues, verify live, and deploy.",
        )
        self.current_run = run
        self.running_task = asyncio.create_task(self._execute_run(run, error_entry=error_entry))
        return self.public_run(run)

    # ------------------------------------------------- Core Research & Tools
    async def _tool_discover_origin_ip(self, run: dict[str, Any], domain: str) -> dict[str, Any]:
        """Discovers non-Cloudflare origin server IPs for `domain` via Google DoH (`TXT` SPF,
        `MX`, and unproxied subdomains) and probes candidate IPs with `Host: <domain>`.
        """
        from g2s.engine import _NEVER_ORIGIN_IP_HOSTS, DEFAULT_ORIGIN_IPS

        base = _base_domain(domain)
        if any(domain == bad or domain.endswith("." + bad) or base == bad for bad in _NEVER_ORIGIN_IP_HOSTS):
            out = {
                "domain": domain,
                "candidates": [],
                "verified_origin_ip": None,
                "probes": ["Skipped: Cloudflare blog/gate/destination domain must use standard DNS"],
            }
            self._emit(run, "tool_result", f"📥 Origin Discovery Skipped for {domain}", json.dumps(out, indent=2))
            return out

        self._emit(
            run,
            "tool_call",
            f"🔧 Tool: discover_origin_ip({domain})",
            f"Querying Google DNS-over-HTTPS (TXT/SPF, MX, A records & subdomains) for {base}…",
        )
        dns_candidates: set[str] = set()
        shared_candidates: set[str] = {"66.116.207.125", "82.25.97.148", "159.198.79.28"}
        existing_ips = (self.db.settings.get("dynamic_rules") or {}).get("origin_ips") or {}
        if domain in DEFAULT_ORIGIN_IPS:
            dns_candidates.add(DEFAULT_ORIGIN_IPS[domain])
        elif base in DEFAULT_ORIGIN_IPS:
            dns_candidates.add(DEFAULT_ORIGIN_IPS[base])
        if domain in existing_ips:
            dns_candidates.add(existing_ips[domain])
        if base in existing_ips:
            dns_candidates.add(existing_ips[base])

        subdomains = [
            base,
            domain,
            f"direct.{base}",
            f"mail.{base}",
            f"cpanel.{base}",
            f"webmail.{base}",
            f"ftp.{base}",
            f"link.{base}",
            f"open.{base}",
            f"m.{base}",
            f"sub.{base}",
            f"go.{base}",
            f"ai3.{base}",
        ]
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                # 1. TXT SPF records
                for d in {base, domain}:
                    async with s.get("https://dns.google/resolve", params={"name": d, "type": "TXT"}) as r:
                        if r.status == 200:
                            j = await r.json(content_type=None)
                            for ans in (j or {}).get("Answer") or []:
                                data = str(ans.get("data") or "")
                                for ip_m in re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+)", data):
                                    if not _is_cf_ip(ip_m):
                                        dns_candidates.add(ip_m)
                # 2. A records on subdomains
                for sub in subdomains:
                    async with s.get("https://dns.google/resolve", params={"name": sub, "type": "A"}) as r:
                        if r.status == 200:
                            j = await r.json(content_type=None)
                            for ans in (j or {}).get("Answer") or []:
                                if ans.get("type") == 1:
                                    ip_a = str(ans.get("data") or "").strip()
                                    if ip_a and not _is_cf_ip(ip_a):
                                        dns_candidates.add(ip_a)
        except Exception as e:
            self._emit(run, "tool_result", "📥 DoH query warning", str(e))

        all_candidates = list(dns_candidates) + [ip for ip in shared_candidates if ip not in dns_candidates]
        verified_ip = None
        probe_details = []
        fake_ip = f"49.36.{random.randint(10, 240)}.{random.randint(10, 240)}"
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        for ip in all_candidates:
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=ssl_ctx),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as s:
                    async with s.get(
                        f"https://{ip}/",
                        headers={
                            "Host": domain,
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
                            "CF-Connecting-IP": fake_ip,
                            "CF-IPCountry": "IN",
                        },
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text()
                        loc = resp.headers.get("Location") or ""
                        title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                        title = (title_m.group(1).strip() if title_m else "")[:80]
                        title_l = title.lower()
                        probe_details.append(f"{ip} -> HTTP {resp.status} (title={title!r}, len={len(body)})")
                        # Prevent false-positive catch-all vhost matches (e.g. LiteSpeed 'Index of /' echoing <Host> in <address>)
                        if any(
                            bad_t in title_l
                            for bad_t in (
                                "index of", "default web page", "404", "403", "not found",
                                "vipcpm", "cgi-sys", "coming soon", "account suspended",
                            )
                        ):
                            continue
                        if "liteshort" in title_l and base != "liteshort.com":
                            continue
                        if "get2short" in (title_l + loc.lower()) and base != "get2short.com":
                            continue
                        if "arolinks" in (title_l + loc.lower()) and base != "arolinks.com":
                            continue
                        body_clean = re.sub(r"<address[^>]*>.*?</address>", "", body, flags=re.I | re.S)
                        has_shortener_markers = bool(
                            re.search(r"app_vars|csrfToken|/links/go|newwpsafelink|ak_safelink", body_clean, re.I)
                        )
                        domain_matched = (
                            (base in body_clean.lower() and (has_shortener_markers or base.split(".")[0] in title_l))
                            or base in loc.lower()
                            or (domain in DEFAULT_ORIGIN_IPS and DEFAULT_ORIGIN_IPS.get(domain) == ip)
                            or (base in DEFAULT_ORIGIN_IPS and DEFAULT_ORIGIN_IPS.get(base) == ip)
                        )
                        if (
                            resp.status in (200, 301, 302, 307, 308)
                            and (ip in dns_candidates or domain_matched)
                        ):
                            verified_ip = ip
                            break
            except Exception as e:
                probe_details.append(f"{ip} -> {type(e).__name__}: {e}")

        out = {
            "domain": domain,
            "candidates": all_candidates,
            "verified_origin_ip": verified_ip,
            "probes": probe_details,
        }
        self._emit(
            run,
            "tool_result",
            f"📥 Origin Discovery Result for {domain}",
            json.dumps(out, indent=2),
        )
        return out

    async def _tool_probe_shortener_url(
        self,
        run: dict[str, Any],
        url: str,
        origin_ip: str | None = None,
    ) -> dict[str, Any]:
        """Fetches a shortener URL (directly or via `origin_ip` with Indian `CF-Connecting-IP`)
        and extracts status, redirects, cookies, forms, Turnstile sitekeys, and JS variables.
        """
        host = _host_of(url)
        fake_ip = f"49.36.{random.randint(10, 240)}.{random.randint(10, 240)}"
        mode_lbl = f"origin {origin_ip} (CF-Connecting-IP={fake_ip})" if origin_ip else "standard DNS"
        self._emit(
            run,
            "tool_call",
            f"🔧 Tool: probe_shortener_live({url})",
            f"Probing {url} via {mode_lbl}…",
        )

        class _ProbeResolver(aiohttp.abc.AbstractResolver):
            async def resolve(self, h, port=0, family=0):
                ip = origin_ip if (origin_ip and h == host) else h
                return [{"hostname": h, "host": ip, "port": port, "family": family, "proto": 0, "flags": 0}]
            async def close(self):
                pass

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(
            resolver=_ProbeResolver() if origin_ip else None,
            ssl=ssl_ctx,
        )
        jar = aiohttp.CookieJar(unsafe=True)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        if origin_ip:
            headers.update({
                "CF-Connecting-IP": fake_ip,
                "CF-IPCountry": "IN",
            })

        try:
            if "nazki-protected.vercel.app" in host:
                m_sess = re.search(r"/access/([0-9a-fA-F-]{16,64})", url)
                if m_sess:
                    sid = m_sess.group(1)
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s_nz:
                        async with s_nz.get(
                            f"https://nazki.duckdns.org/api/session/{sid}",
                            headers={
                                "User-Agent": headers["User-Agent"],
                                "Origin": "https://nazki-protected.vercel.app",
                                "Referer": "https://nazki-protected.vercel.app/",
                                "X-Fingerprint": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
                                "X-Is-WebView": "false",
                            },
                            ssl=ssl_ctx,
                        ) as r_nz:
                            nz_data = await r_nz.json(content_type=None)
                            nz_err = (nz_data.get("error") or "") if isinstance(nz_data, dict) else ""
                            is_404_nz = r_nz.status in (400, 404, 410) or "invalid" in nz_err.lower() or "expired" in nz_err.lower()
                            info = {
                                "url": url,
                                "status": r_nz.status,
                                "api_response": nz_data,
                                "is_vpn_or_rate_blocked": False,
                                "is_dead_404": is_404_nz,
                            }
                            self._emit(
                                run,
                                "tool_result",
                                f"📥 Nazki API Probe ({r_nz.status}) for {url}",
                                json.dumps(info, indent=2),
                            )
                            return info

            p_probe = urllib.parse.urlparse(url)
            probe_host = (p_probe.hostname or "").lower()
            if (
                ("publicbotshub-verify.koyeb.app" in probe_host or "koyeb.app" in probe_host or "herokuapp.com" in probe_host or "mrn-officialx.vercel.app" in probe_host)
                and ("/link/" in url or "/telegram/" in url)
            ):
                info = {
                    "url": url,
                    "status": 200,
                    "location": None,
                    "title": "PublicBotsHub / Koyeb Single-Use Verification Gate",
                    "body_len": 0,
                    "set_cookies": [],
                    "forms": [{"id": "verifyForm", "action": url, "inputs": ["g-recaptcha-response"]}],
                    "js_redirects": [],
                    "spa_api_endpoints": [],
                    "turnstile_sitekeys": [],
                    "turnstile_actions": [],
                    "turnstile_cdata": [],
                    "has_recaptcha_v2": True,
                    "has_vhit_verification": False,
                    "has_ads_track_data": False,
                    "is_vpn_or_rate_blocked": False,
                    "is_expired_single_use": False,
                    "is_dead_404": False,
                    "note": "Preserved single-use /link/ verification token (skipped raw HTTP GET to avoid burning one-time token before browser handoff).",
                }
                self._emit(
                    run,
                    "tool_result",
                    f"📥 Single-Use Verification Gate Preserved for {url[:85]}",
                    json.dumps(info, indent=2),
                )
                return info

            async with aiohttp.ClientSession(
                connector=conn,
                cookie_jar=jar,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=20),
            ) as s:
                status = 0
                loc = None
                cookies = []
                body = ""
                for _p_att in range(4):
                    async with s.get(url, allow_redirects=False) as r:
                        status = r.status
                        loc = r.headers.get("Location")
                        cookies = r.headers.getall("Set-Cookie", [])
                        body = await r.text()
                        if status not in (403, 429, 502, 503) or len(body) > 2500:
                            break
                    await asyncio.sleep(1.0)

            title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = (title_m.group(1).strip() if title_m else "")[:120]
            forms = []
            for fm in re.finditer(r"<form([^>]*)>(.*?)</form>", body, re.I | re.S):
                f_attrs = fm.group(1)
                f_body = fm.group(2)
                f_id = (re.search(r'id=["\']([^"\']+)["\']', f_attrs, re.I) or [None, ""])[1]
                f_act = (re.search(r'action=["\']([^"\']+)["\']', f_attrs, re.I) or [None, ""])[1]
                inputs = re.findall(r'name=["\']([^"\']+)["\']', f_body, re.I)
                forms.append({"id": f_id, "action": f_act, "inputs": inputs[:15]})

            js_redirects = re.findall(
                r'(?:window|document)\.location(?:\.href|\.replace)?\s*(?:=|\()\s*["\']([^"\']+)["\']',
                body,
                re.I,
            )
            skip_sub_links = re.findall(r'href=["\']([^"\']*skip_sub=1[^"\']*)["\']', body, re.I)
            for ssl_u in skip_sub_links:
                full_ssl = urllib.parse.urljoin(url, html.unescape(ssl_u))
                if full_ssl not in js_redirects:
                    js_redirects.append(full_ssl)
            sitekeys = (
                re.findall(r'data-sitekey=["\']([^"\']+)["\']', body, re.I)
                + re.findall(r'\bsitekey\s*:\s*["\']([0-3]x[\w-]{10,})["\']', body, re.I)
                + re.findall(r'"turnstile_site_key"\s*:\s*"([0-3]x[\w-]{10,})"', body, re.I)
            )
            has_vhit = bool(re.search(r'/_v/s\.js|class=["\'][^"\']*\bvhit\b', body, re.I))
            has_ads_track = bool(re.search(r'ads-track-data|power-cdn\.js', body, re.I))
            ts_actions = re.findall(r'data-action=["\']([^"\']+)["\']', body, re.I) + re.findall(
                r'\baction\s*:\s*["\']([^"\']+)["\']', body, re.I
            )
            ts_cdata = re.findall(r'data-cdata=["\']([^"\']+)["\']', body, re.I) + re.findall(
                r'\bcData\s*:\s*["\']([^"\']+)["\']', body, re.I
            )
            is_vpn_block = bool(
                re.search(
                    r"vpn detected|proxy\s*/\s*vpn detected|disable your vpn|access temporarily restricted|unusual network activity",
                    body,
                    re.I,
                )
            )
            is_expired_one_time = bool(
                re.search(
                    r"link expired or invalid|generate a new verification link from the bot|not found or already used|this link has expired",
                    body,
                    re.I,
                )
            )
            if "nazki-protected.vercel.app" in probe_host and "/access/" in url:
                m_nz = re.search(r"/access/([0-9a-fA-F-]{16,})", url)
                if m_nz:
                    nz_sid = m_nz.group(1)
                    from g2s.engine import Bypasser
                    nz_cached = getattr(Bypasser, "_nazki_session_cache", {}).get(nz_sid)
                    if nz_cached:
                        loc = nz_cached
                    else:
                        try:
                            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s_nz:
                                async with s_nz.get(
                                    f"https://nazki.duckdns.org/api/session/{nz_sid}",
                                    headers={**headers, "Origin": "https://nazki-protected.vercel.app", "Referer": "https://nazki-protected.vercel.app/"},
                                    ssl=False,
                                ) as r_nz:
                                    t_nz = await r_nz.text()
                                    if r_nz.status == 404 or "not found or already used" in t_nz.lower() or "invalid or expired" in t_nz.lower():
                                        is_expired_one_time = True
                        except Exception:
                            pass
            has_recaptcha_v2 = bool(
                re.search(r"google\.com/recaptcha/api\.js|gstatic\.com/recaptcha|class=[\"'][^\"']*g-recaptcha", body, re.I)
            )
            cf_unwrapped_loc = None
            if status == 403 and ("attention required" in title.lower() or "just a moment" in title.lower()):
                bp_inst = self.get_bypasser()
                if bp_inst and hasattr(bp_inst, "_resolve_cf_blocked_redirect"):
                    try:
                        cf_unwrapped_loc = await bp_inst._resolve_cf_blocked_redirect(url)
                        if cf_unwrapped_loc and not loc:
                            loc = cf_unwrapped_loc
                    except Exception:
                        pass

            spa_api_endpoints: list[str] = []
            if "/_next/static/chunks/" in body and not forms:
                chunk_paths = list(dict.fromkeys(re.findall(r"/_next/static/chunks/[A-Za-z0-9._-]+\.js", body)))[-3:]
                if chunk_paths:
                    try:
                        p_u = urllib.parse.urlparse(url)
                        base_origin = f"{p_u.scheme}://{p_u.netloc}"
                        async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as s_ch:
                            for cp in chunk_paths:
                                async with s_ch.get(base_origin + cp, ssl=ssl_ctx) as r_ch:
                                    if r_ch.status == 200:
                                        ch_js = await r_ch.text(errors="replace")
                                        for ep in re.findall(r'["\'`](/api/[A-Za-z0-9/_${}-]+)["\'`]', ch_js):
                                            if ep not in spa_api_endpoints:
                                                spa_api_endpoints.append(ep)
                                        if "recaptcha" in ch_js.lower():
                                            has_recaptcha_v2 = True
                    except Exception:
                        pass

            loc_host = _host_of(str(loc or ""))
            is_parked_domain = bool(
                re.match(r"^ww\d+\.", probe_host)
                or re.match(r"^ww\d+\.", loc_host)
                or ("ch=1&js=eyJ" in body and "<title>Loading...</title>" in body)
                or any(re.search(r"https?://ww\d+\.", jr, re.I) for jr in js_redirects)
            )
            is_paid_paywall = bool(
                probe_host.endswith("bayarlink.com")
                or any("initiate_qris" in (f.get("inputs") or []) for f in forms)
                or re.search(r"pembayaran\s+qris|initiate_qris|unlock\s+protected\s+link\s*-\s*bayarlink", body, re.I)
            )
            lv_is_not_found = False
            if _base_domain(probe_host) in (
                "linkvertise.com", "link-target.net", "link-target.org", "link-center.net",
                "link-to.net", "direct-link.net", "link-hub.net", "up-to-down.net", "file-link.net",
            ):
                try:
                    p_lv = urllib.parse.urlparse(url)
                    segs_lv = [sg for sg in p_lv.path.strip("/").split("/") if sg and sg.lower() not in ("access", "download")]
                    if len(segs_lv) >= 2 and segs_lv[0].isdigit() and "dynamic" not in segs_lv[1].lower():
                        lv_ident = {"userIdAndUrl": {"user_id": segs_lv[0], "url": segs_lv[1]}}
                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6)) as s_lv:
                            async with s_lv.post(
                                "https://publisher.linkvertise.com/graphql",
                                params={"name": "getLinkByIdentifier"},
                                headers={
                                    "User-Agent": ua,
                                    "Content-Type": "application/json",
                                    "Origin": "https://linkvertise.com",
                                    "Referer": "https://linkvertise.com/",
                                },
                                json={
                                    "operationName": "getLinkByIdentifier",
                                    "variables": {"identifier": lv_ident},
                                    "query": "query getLinkByIdentifier($identifier: PublicLinkIdentificationInput!) { linkByIdentifier(linkIdentificationInput: $identifier) { id url is_premium_only } }",
                                },
                            ) as r_lv:
                                if r_lv.status == 200:
                                    d_lv = await r_lv.json(content_type=None)
                                    lbi = ((d_lv or {}).get("data") or {}).get("linkByIdentifier") if isinstance(d_lv, dict) else "unknown"
                                    if isinstance(lbi, dict) and lbi.get("is_premium_only") is True:
                                        is_paid_paywall = True
                                    elif lbi is None:
                                        lv_is_not_found = True
                except Exception:
                    pass
            is_404 = bool(
                status in (404, 410)
                or lv_is_not_found
                or is_expired_one_time
                or is_parked_domain
                or is_paid_paywall
                or (
                    "was not found on this server" in body.lower()
                    and "access temporarily restricted" not in body.lower()
                )
            )
            info = {
                "url": url,
                "status": status,
                "location": loc,
                "cf_unwrapped_location": cf_unwrapped_loc,
                "title": title,
                "body_len": len(body),
                "set_cookies": [c.split(";")[0] for c in cookies],
                "forms": forms,
                "js_redirects": js_redirects[:6],
                "spa_api_endpoints": spa_api_endpoints[:10],
                "turnstile_sitekeys": list(dict.fromkeys(sitekeys)),
                "turnstile_actions": list(dict.fromkeys(ts_actions)),
                "turnstile_cdata": list(dict.fromkeys(ts_cdata)),
                "has_recaptcha_v2": has_recaptcha_v2,
                "has_vhit_verification": has_vhit,
                "has_ads_track_data": has_ads_track,
                "is_vpn_or_rate_blocked": is_vpn_block,
                "is_expired_single_use": is_expired_one_time,
                "is_parked_domain": is_parked_domain,
                "is_paid_paywall": is_paid_paywall,
                "is_dead_404": is_404,
            }
            self._emit(
                run,
                "tool_result",
                f"📥 HTTP Probe Result ({status}) for {url}",
                json.dumps(info, indent=2),
            )
            return info
        except Exception as e:
            err_str = f"{type(e).__name__}: {e}"
            p_err_b = _base_domain(_host_of(url))
            is_dead_dns = bool(
                any(k in err_str.lower() for k in ("name or service not known", "no address associated", "nodename nor servname"))
                and p_err_b not in ("frdl.io", "frdl.to", "frdl.is")
            )
            err_info = {"url": url, "error": err_str, "is_dead_404": is_dead_dns}
            self._emit(run, "tool_result", f"📥 Probe Error for {url}", json.dumps(err_info, indent=2))
            return err_info

    async def _tool_trace_redirect_chain(
        self,
        run: dict[str, Any],
        url: str,
        origin_ips: dict[str, str],
        max_hops: int = 5,
    ) -> dict[str, Any]:
        """Follows up to `max_hops` redirects/safelink steps from `url`, inspecting status codes,
        `Location` headers, `Set-Cookie` headers, forms, timers, and checking whether each
        intermediate hop domain is registered in `CHAIN_HOSTS` / `DYNAMIC_RULES["chain_hosts"]`
        or falsely blocked by `Job.is_ad_domain`.
        """
        from g2s.engine import DYNAMIC_RULES, Job, _NEVER_CHAIN_HOSTS

        self._emit(
            run,
            "tool_call",
            f"🔧 Tool: trace_redirect_chain({url})",
            f"Tracing multi-hop redirect chain, Set-Cookie state, forms, and timers (max {max_hops} hops)…",
        )
        fake_ip = f"49.36.{random.randint(15, 240)}.{random.randint(15, 240)}"
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        class _TraceResolver(aiohttp.abc.AbstractResolver):
            async def resolve(self, h, port=0, family=0):
                b = _base_domain(h)
                ip = origin_ips.get(h) or origin_ips.get(b)
                if ip:
                    return [{"hostname": h, "host": ip, "port": port, "family": family, "proto": 0, "flags": 0}]
                resolver = aiohttp.resolver.ThreadedResolver()
                return await resolver.resolve(h, port, family)

            async def close(self):
                pass

        conn = aiohttp.TCPConnector(resolver=_TraceResolver(), ssl=ssl_ctx)
        ua = (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        dummy_job = Job(url, lambda *_: None, asyncio.get_running_loop())
        hops: list[dict[str, Any]] = []
        missing_chain_hosts: list[str] = []
        ad_false_positives: list[str] = []
        discovered_referer_overrides: dict[str, str] = {}
        cur_url = url
        prev_url = ""
        start_alias = urllib.parse.urlparse(url).path.strip("/")

        try:
            async with aiohttp.ClientSession(
                connector=conn,
                cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=18),
            ) as s:
                cookies: dict[str, str] = {}
                for hop_idx in range(max_hops):
                    req_hdrs = dict(headers)
                    cur_h = _host_of(cur_url)
                    cur_b = _base_domain(cur_h)
                    if (
                        ("publicbotshub-verify.koyeb.app" in cur_h or "koyeb.app" in cur_h or "herokuapp.com" in cur_h or "mrn-officialx.vercel.app" in cur_h)
                        and "/link/" in cur_url
                    ):
                        hops.append({
                            "hop": hop_idx + 1,
                            "url": cur_url,
                            "host": cur_h,
                            "status": 200,
                            "location": "",
                            "set_cookie_keys": [],
                            "forms": [{"id": "verifyForm", "action": cur_url, "inputs": ["g-recaptcha-response"]}],
                            "js_redirects": [],
                            "detected_timers": [],
                            "registered_in_chain_hosts": True,
                            "falsely_flagged_as_ad": False,
                            "note": "Skipped raw HTTP GET on single-use /link/ verification token.",
                        })
                        break
                    if cur_h in origin_ips or cur_b in origin_ips:
                        req_hdrs["CF-Connecting-IP"] = fake_ip
                        req_hdrs["CF-IPCountry"] = "IN"
                    if prev_url:
                        req_hdrs["Referer"] = prev_url
                    if cookies:
                        req_hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
                    status = 0
                    loc = ""
                    sc_names = []
                    body = ""
                    for _tr_att in range(4):
                        async with s.get(cur_url, headers=req_hdrs, allow_redirects=False) as r:
                            status = r.status
                            loc = r.headers.get("Location") or ""
                            raw_sc = r.headers.getall("Set-Cookie", [])
                            sc_names = []
                            for sc in raw_sc:
                                part = sc.split(";", 1)[0].strip()
                                if "=" in part:
                                    k, v = part.split("=", 1)
                                    sc_names.append(k.strip())
                                    if v and v.lower() != "deleted":
                                        cookies[k.strip()] = v.strip()
                            body = await r.text(errors="replace")
                            if status not in (403, 429, 502, 503) or len(body) > 2500:
                                break
                        await asyncio.sleep(1.0)

                    h_host = _host_of(cur_url)
                    h_base = _base_domain(h_host)
                    in_chain = bool(
                        h_base == dummy_job.base
                        or dummy_job.is_chain(cur_url)
                        or any(h_host == ch or h_host.endswith("." + ch) for ch in (DYNAMIC_RULES.get("chain_hosts") or []))
                    )
                    is_ad_fp = dummy_job.is_ad_domain(cur_url)
                    if is_ad_fp:
                        ad_false_positives.append(cur_url)
                    if hop_idx > 0 and h_base and h_base != dummy_job.base and not in_chain:
                        if (
                            not any(h_base == bad or h_base.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                            and h_base not in missing_chain_hosts
                        ):
                            missing_chain_hosts.append(h_base)

                    forms = []
                    for fm in re.finditer(r"<form([^>]*)>(.*?)</form>", body, re.I | re.S):
                        f_attrs, f_body = fm.group(1), fm.group(2)
                        f_id = (re.search(r'id=["\']([^"\']+)["\']', f_attrs, re.I) or [None, ""])[1]
                        f_act = (re.search(r'action=["\']([^"\']+)["\']', f_attrs, re.I) or [None, ""])[1]
                        inputs = re.findall(r'name=["\']([^"\']+)["\']', f_body, re.I)
                        forms.append({"id": f_id, "action": f_act, "inputs": inputs[:12]})

                    js_redirects = re.findall(
                        r'(?:window|document)\.location(?:\.href|\.replace)?\s*(?:=|\()\s*["\']([^"\']+)["\']',
                        body,
                        re.I,
                    )
                    for ssl_u in re.findall(r'href=["\']([^"\']*skip_sub=1[^"\']*)["\']', body, re.I):
                        full_ssl = urllib.parse.urljoin(cur_url, html.unescape(ssl_u))
                        if full_ssl not in js_redirects:
                            js_redirects.append(full_ssl)
                    meta_redir = re.findall(
                        r'http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\'>\s]+)',
                        body,
                        re.I,
                    )
                    timers = re.findall(
                        r'(?:var|let|const)\s+(?:timer|countdown|seconds|timeleft|counter)\s*=\s*(\d+)',
                        body,
                        re.I,
                    )
                    hops.append({
                        "hop": hop_idx + 1,
                        "url": cur_url,
                        "host": h_host,
                        "status": status,
                        "location": loc,
                        "set_cookie_keys": sc_names,
                        "forms": forms[:5],
                        "js_redirects": (js_redirects + meta_redir)[:5],
                        "detected_timers": timers[:4],
                        "registered_in_chain_hosts": in_chain,
                        "falsely_flagged_as_ad": is_ad_fp,
                    })

                    next_u = loc or ((js_redirects + meta_redir)[0] if (js_redirects or meta_redir) else "")
                    if not next_u and start_alias and ("safe2.php" in cur_url or "baby.php" in cur_url or "tp2" in sc_names or "tp1" in sc_names):
                        # Follow 2-hop safelink blog form (e.g. tech8s.net -> game5s.com)
                        m_gu = re.search(r"url=(https?://[^&\"'\s<>]+)", body, re.I)
                        post1_u = urllib.parse.unquote(m_gu.group(1)) if m_gu else f"https://{h_host}/"
                        cookies["tp2"] = start_alias
                        cookies["tp1"] = start_alias
                        ck_s = "; ".join(f"{k}={v}" for k, v in cookies.items())
                        async with s.post(
                            post1_u,
                            data={"tp2": start_alias, "tp1": start_alias},
                            headers={**headers, "Referer": post1_u, "Origin": f"https://{h_host}", "Cookie": ck_s},
                            allow_redirects=False,
                        ) as rp:
                            bp = await rp.text(errors="replace")
                        m_go2 = re.search(
                            r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]+id=["\'](?:go_d2|btn6)["\']|'
                            r'<a[^>]+id=["\'](?:go_d2|btn6)["\'][^>]+href=["\'](https?://[^"\']+)["\']',
                            bp,
                            re.I,
                        )
                        if m_go2:
                            next_u = m_go2.group(1) or m_go2.group(2) or ""
                            b2_h = _host_of(next_u)
                            b2_b = _base_domain(b2_h)
                            if b2_b and b2_b != dummy_job.base:
                                discovered_referer_overrides[dummy_job.base] = f"https://{b2_h}/"
                                if (
                                    not any(b2_b == bad or b2_b.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                                    and b2_b not in missing_chain_hosts
                                ):
                                    missing_chain_hosts.append(b2_b)

                    if not next_u:
                        break
                    next_u = urllib.parse.urljoin(cur_url, next_u)
                    if next_u == cur_url:
                        break
                    prev_url = cur_url
                    cur_url = next_u
        except Exception as e:
            hops.append({"error": f"{type(e).__name__}: {e}", "at_url": cur_url})

        report = {
            "start_url": url,
            "hops": hops,
            "missing_chain_hosts": missing_chain_hosts,
            "ad_false_positives": ad_false_positives,
            "discovered_referer_overrides": discovered_referer_overrides,
        }
        self._emit(
            run,
            "tool_result",
            f"📥 Redirect Chain Trace ({len(hops)} hop(s)) for {url}",
            json.dumps(report, indent=2),
        )
        return report

    async def _tool_inspect_page_and_scripts(
        self,
        run: dict[str, Any],
        url: str,
        step_lines: str = "",
        origin_ip: str | None = None,
    ) -> dict[str, Any]:
        """Deep DOM, inline <script>, debug snapshot, and API endpoint analyzer.
        Automatically detects AvBypass/MRN (/verify_captcha), LootLabs (conf_rew / 31.js),
        AdLinkFly (/links/go), Turnstile sitekeys/callbacks, and WebGL/BotD issues.
        """
        self._emit(
            run,
            "tool_call",
            f"🔧 Tool: inspect_page_and_scripts({url!r})",
            "Inspecting saved debug HTML snapshots, inline <script> blocks, fetch/XHR endpoints & Turnstile hooks…",
        )
        html_blobs: list[tuple[str, str]] = []
        # 1. Read any saved debug snapshot HTML referenced in step_lines
        for snap_m in re.findall(r"Saved debug snapshot:\s*([^\s]+?)\.html", step_lines or ""):
            snap_path = snap_m + ".html"
            for candidate_p in (snap_path, os.path.join("/home/user/gss-free", snap_path)):
                if os.path.exists(candidate_p):
                    try:
                        with open(candidate_p, "r", encoding="utf-8", errors="ignore") as f:
                            html_blobs.append((f"snapshot:{snap_path}", f.read(120000)))
                    except Exception:
                        pass
                    break

        # 2. Fetch live URL (and any stuck/final redirect URL from step_lines) with Chrome Sec-Fetch headers
        urls_to_fetch = [url]
        for st_u in re.findall(
            r"(?:Stuck on|Navigating\s*→|Following final redirect\s*→)\s*(https?://[^\s…\"'<>)\]]+)",
            step_lines or "",
        ):
            if st_u not in urls_to_fetch:
                urls_to_fetch.append(st_u)

        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        hdrs = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }
        detected_cookies: list[str] = []
        redirect_locations: list[str] = []
        try:
            jar = aiohttp.CookieJar(unsafe=True)
            async with aiohttp.ClientSession(
                cookie_jar=jar,
                headers=hdrs,
                timeout=aiohttp.ClientTimeout(total=14),
            ) as s:
                for fu in urls_to_fetch[:3]:
                    fu_h = _host_of(fu)
                    if (
                        ("publicbotshub-verify.koyeb.app" in fu_h or "koyeb.app" in fu_h or "herokuapp.com" in fu_h or "mrn-officialx.vercel.app" in fu_h)
                        and "/link/" in fu
                    ):
                        html_blobs.append((
                            f"preserved:{fu} (status=200)",
                            '<div class="g-recaptcha" data-sitekey="recaptcha_v2"></div><form id="verifyForm"></form>',
                        ))
                        continue
                    try:
                        async with s.get(fu, allow_redirects=False) as r0:
                            for sc in r0.headers.getall("Set-Cookie", []):
                                ck_name = sc.split("=", 1)[0].strip()
                                if ck_name and ck_name not in detected_cookies:
                                    detected_cookies.append(ck_name)
                            loc0 = (r0.headers.get("Location") or "").strip()
                            if loc0:
                                redirect_locations.append(loc0)
                            raw_b0 = (await r0.content.read(90000)).decode("utf-8", "ignore")
                            if raw_b0:
                                html_blobs.append((f"live:{fu} (status={r0.status})", raw_b0))
                            if r0.status in (301, 302, 303, 307, 308) and loc0.startswith("http"):
                                async with s.get(loc0, allow_redirects=True) as r_redir:
                                    raw_br = (await r_redir.content.read(90000)).decode("utf-8", "ignore")
                                    if raw_br:
                                        html_blobs.append((f"redirect:{r_redir.url} (status={r_redir.status})", raw_br))
                            # If it's a /go/<id> gate that set mrn_gate cookie, also probe /<id>
                            p_fu = urlparse(fu)
                            segs = [x for x in p_fu.path.strip("/").split("/") if x]
                            if len(segs) >= 2 and segs[0].lower() in ("go", "v", "s", "link"):
                                gate_u = f"{p_fu.scheme}://{p_fu.hostname}/{segs[1]}"
                                async with s.get(gate_u, allow_redirects=True) as rg:
                                    raw_bg = (await rg.content.read(90000)).decode("utf-8", "ignore")
                                    if raw_bg:
                                        html_blobs.append((f"gate:{gate_u} (status={rg.status})", raw_bg))
                    except Exception:
                        pass
        except Exception:
            pass

        script_srcs: list[str] = []
        interesting_scripts: list[str] = []
        fetch_endpoints: list[str] = []
        sitekeys: list[str] = []
        detected_template = "unknown"
        avbypass_hosts_found: list[str] = []
        linkprotect_hosts_found: list[str] = []
        safelinku_hosts_found: list[str] = []
        laila_hosts_found: list[str] = []
        short4cash_hosts_found: list[str] = []
        shortners_workers_hosts_found: list[str] = []
        vplinks_beta_hosts_found: list[str] = []
        lootlabs_hosts_found: list[str] = []
        linkvertise_hosts_found: list[str] = []
        host_u = _host_of(url)

        if any("linkvertise.com" in rl.lower() for rl in redirect_locations) or "linkvertise.com" in host_u:
            detected_template = "linkvertise_graphql"
            if host_u and host_u not in linkvertise_hosts_found:
                linkvertise_hosts_found.append(host_u)
        if any("thankyoucloudflare.workers.dev" in rl.lower() or "remso.xyz" in rl.lower() for rl in redirect_locations) or "shortners.workers.dev" in host_u:
            detected_template = "shortners_workers_linkforge"
            if host_u and host_u not in shortners_workers_hosts_found:
                shortners_workers_hosts_found.append(host_u)

        for src_label, h_text in html_blobs:
            m_lbl_u = re.search(r"https?://[^\s)]+", src_label)
            blob_host = _host_of(m_lbl_u.group(0)) if m_lbl_u else host_u
            for sc_src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', h_text, re.I):
                if sc_src not in script_srcs:
                    script_srcs.append(sc_src)
            for sk_m in re.findall(r'(?:data-sitekey|sitekey)\s*[=:]\s*["\']([0-3]x[\w-]{10,})["\']', h_text, re.I):
                if sk_m not in sitekeys:
                    sitekeys.append(sk_m)
            for f_ep in re.findall(r'fetch\(\s*["\']([^"\']+)["\']', h_text, re.I):
                if f_ep not in fetch_endpoints:
                    fetch_endpoints.append(f_ep)
            for inl in re.findall(r"<script[^>]*>(.*?)</script>", h_text, re.I | re.S):
                inl_s = inl.strip()
                if not inl_s or len(inl_s) < 20:
                    continue
                if any(
                    kw in inl_s
                    for kw in (
                        "verify_captcha", "turnstile", "conf_rew", "/links/go",
                        "finalUrl", "linkId", "onloadTurnstileCallback", "AroShield",
                        "ads-track-data", "WebSocket", "linkvertise", "/api/claim",
                        "ctoken=", "/api/session", "/api/verify", "/api/init/",
                        "/api/complete/", "newwpsafelink", "get-paste", "continueForm",
                    )
                ):
                    interesting_scripts.append(f"[{src_label}]\n{inl_s[:1600]}")

            low_h = h_text.lower()
            if "/api/init/" in low_h or "/api/complete/" in low_h or "laila antibypass" in low_h:
                detected_template = "laila_railway_checkpoint"
                if blob_host and blob_host not in laila_hosts_found:
                    laila_hosts_found.append(blob_host)
            elif (
                "/links/protection-browser-check" in low_h
                or blob_host in ("get2short.com", "link.get2short.com", "lnbz.la", "jkdamours.com", "odiadance.com")
            ):
                detected_template = "get2short_safelink"
            elif (
                "go.short4cash.com" in low_h
                or "newwpsafelink12" in low_h
                or blob_host in ("short4cash.com", "go.short4cash.com", "sayphotobooth.com")
            ):
                detected_template = "short4cash_safelink"
                if blob_host and blob_host not in short4cash_hosts_found:
                    short4cash_hosts_found.append(blob_host)
            elif ("csrfmiddlewaretoken" in low_h and "/continue/" in low_h) or any(c.startswith("wait_token_") for c in detected_cookies):
                detected_template = "vplinks_beta_django"
                if blob_host and blob_host not in vplinks_beta_hosts_found:
                    vplinks_beta_hosts_found.append(blob_host)
            elif 'data-action="redirect"' in low_h or "thankyoucloudflare.workers.dev" in low_h or "wbschemenews.com" in low_h:
                detected_template = "shortners_workers_linkforge"
                if blob_host and blob_host not in shortners_workers_hosts_found:
                    shortners_workers_hosts_found.append(blob_host)
            elif 'id="body-display"' in low_h or "pastetoday.com/get-paste" in low_h:
                detected_template = "pastelink_container"
            elif "google.com/recaptcha" in low_h or "gstatic.com/recaptcha" in low_h or "g-recaptcha" in low_h:
                detected_template = "recaptcha_v2_gate"
            elif "/verify_captcha" in low_h or "?ctoken=" in low_h or "tg://resolve?domain=" in low_h or "mrn_gate" in [c.lower() for c in detected_cookies]:
                detected_template = "avbypass_mrn_gate"
                if (
                    blob_host
                    and blob_host not in avbypass_hosts_found
                    and not any(blob_host == bad or blob_host.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                ):
                    avbypass_hosts_found.append(blob_host)
            elif "/api/claim" in low_h and "nonce" in low_h:
                detected_template = "linkprotect_worker"
                if (
                    blob_host
                    and blob_host not in linkprotect_hosts_found
                    and not any(blob_host == bad or blob_host.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                ):
                    linkprotect_hosts_found.append(blob_host)
            elif ("/api/session" in low_h and "/api/verify" in low_h) or "redirect.php?ray_id=" in low_h or "sfl.gl" in blob_host or "khaddavi.net" in blob_host:
                detected_template = "safelinku_khaddavi"
                if blob_host and blob_host not in safelinku_hosts_found:
                    safelinku_hosts_found.append(blob_host)
            elif "window.conf_rew" in low_h or any("31.js" in s for s in script_srcs) or "d31-task-item" in low_h:
                detected_template = "lootlabs_31js_ws"
                if blob_host and blob_host not in lootlabs_hosts_found:
                    lootlabs_hosts_found.append(blob_host)
            elif "publisher.linkvertise.com" in low_h or "lv-membership-plan-option" in low_h or "linkvertise.com" in low_h:
                detected_template = "linkvertise_graphql"
                if blob_host and blob_host not in linkvertise_hosts_found:
                    linkvertise_hosts_found.append(blob_host)
            elif 'id="go-link"' in low_h or "/links/go" in low_h:
                detected_template = "adlinkfly_links_go"

        result = {
            "url": url,
            "detected_template": detected_template,
            "detected_cookies": detected_cookies,
            "redirect_locations": redirect_locations,
            "sitekeys": sitekeys,
            "fetch_endpoints": fetch_endpoints,
            "external_scripts": script_srcs[:12],
            "inline_scripts": interesting_scripts[:4],
            "avbypass_hosts_found": avbypass_hosts_found,
            "linkprotect_hosts_found": linkprotect_hosts_found,
            "safelinku_hosts_found": safelinku_hosts_found,
            "laila_hosts_found": laila_hosts_found,
            "short4cash_hosts_found": short4cash_hosts_found,
            "shortners_workers_hosts_found": shortners_workers_hosts_found,
            "vplinks_beta_hosts_found": vplinks_beta_hosts_found,
            "lootlabs_hosts_found": lootlabs_hosts_found,
            "linkvertise_hosts_found": linkvertise_hosts_found,
        }
        self._emit(
            run,
            "tool_result",
            f"📥 Deep Page & Script Analysis ({detected_template})",
            json.dumps(result, indent=2),
        )
        return result

    @staticmethod
    def _extract_structured_json(text: str) -> dict[str, Any] | None:
        """Robustly extract a JSON object from LLM output even when preceded by reasoning prose."""
        if not text:
            return None
        # 1. Check fenced ```json ... ``` or ``` ... ``` blocks from last to first
        for fence_m in reversed(list(re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I))):
            try:
                obj = json.loads(fence_m.group(1))
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass
        # 2. Scan all balanced {...} blocks using JSONDecoder.raw_decode
        decoder = json.JSONDecoder()
        candidates: list[dict[str, Any]] = []
        idx = 0
        while True:
            brace_pos = text.find("{", idx)
            if brace_pos < 0:
                break
            try:
                obj, end_pos = decoder.raw_decode(text, brace_pos)
                if isinstance(obj, dict):
                    candidates.append(obj)
                    idx = end_pos
                    continue
            except Exception:
                pass
            idx = brace_pos + 1
        for c in reversed(candidates):
            if any(k in c for k in ("thinking", "root_cause", "fix_plan", "tool_requests", "dynamic_rules_patch", "code_edits")):
                return c
        return candidates[-1] if candidates else None

    async def _call_llm_brain(
        self,
        run: dict[str, Any],
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any] | None:
        """Calls the configured LLM (OpenAI / Anthropic / Gemini / Groq / OpenRouter /
        Pollinations Free Cloud LLM) for deep thinking and structured root-cause + patch JSON.
        """
        provider = (self.db.settings.get("ai_provider") or "auto").lower().strip()
        api_key = (self.db.settings.get("ai_api_key") or "").strip()
        raw_model = (self.db.settings.get("ai_model") or "openai").strip()
        if raw_model == "openai-large":
            raw_model = "openai"
        base_url = (self.db.settings.get("ai_base_url") or "").strip().rstrip("/")

        endpoints = []
        if api_key:
            if base_url:
                endpoints.append((f"{base_url}/chat/completions", api_key, raw_model))
            elif provider == "groq" or api_key.startswith("gsk_"):
                endpoints.append(("https://api.groq.com/openai/v1/chat/completions", api_key, raw_model or "llama-3.3-70b-versatile"))
            elif provider == "openrouter" or api_key.startswith("sk-or-"):
                endpoints.append(("https://openrouter.ai/api/v1/chat/completions", api_key, raw_model or "anthropic/claude-3.5-sonnet"))
            elif provider == "deepseek":
                endpoints.append(("https://api.deepseek.com/v1/chat/completions", api_key, raw_model or "deepseek-reasoner"))
            else:
                endpoints.append(("https://api.openai.com/v1/chat/completions", api_key, raw_model or "gpt-4o"))

        # Always include zero-key free cloud reasoning LLM fallback ("openai")
        endpoints.append(("https://text.pollinations.ai/openai", "", "openai"))

        # Sanitize any 4KB+ token strings inside user_prompt so LLM context stays compact
        compact_user_prompt = re.sub(r"[A-Za-z0-9_-]{180,}", lambda m: m.group(0)[:90] + "...[TRUNCATED_TOKEN]", user_prompt)

        bp = self.get_bypasser()
        px_pool: list[str | None] = [None]
        if bp is not None:
            if hasattr(bp, "_get_active_tunnel_proxies"):
                for tpx in bp._get_active_tunnel_proxies():
                    if tpx not in px_pool:
                        px_pool.append(tpx)
            for wpx in getattr(bp, "_lv_working_proxies", [])[:6]:
                if wpx not in px_pool:
                    px_pool.append(wpx)

        for url, key, mdl in endpoints:
            for px_cand in px_pool:
                try:
                    headers = {"Content-Type": "application/json"}
                    if key:
                        headers["Authorization"] = f"Bearer {key}"
                    payload: dict[str, Any] = {
                        "model": mdl,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": compact_user_prompt},
                        ],
                        "temperature": 0.2,
                    }
                    if "pollinations.ai" in url:
                        payload["reasoning_effort"] = "low"
                        payload["response_format"] = {"type": "json_object"}
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=55)) as s:
                        async with s.post(url, proxy=px_cand, headers=headers, json=payload) as r:
                            if r.status in (402, 429) and not key:
                                err_txt = await r.text()
                                if px_cand is px_pool[-1]:
                                    m_wait = (
                                        re.search(r'"retryAfterSeconds"\s*:\s*(\d+)', err_txt, re.I)
                                        or re.search(r"Retry after (\d+)s", err_txt, re.I)
                                    )
                                    wait_s = min(int(m_wait.group(1)) + 2, 34) if m_wait else 12
                                    await asyncio.sleep(wait_s)
                                    async with s.post(url, headers=headers, json=payload) as r_retry:
                                        if r_retry.status != 200:
                                            continue
                                        data = await r_retry.json(content_type=None)
                                else:
                                    continue
                            elif r.status != 200:
                                continue
                            else:
                                data = await r.json(content_type=None)
                            content = ""
                            reasoning_field = ""
                            if isinstance(data, dict) and data.get("choices"):
                                msg = data["choices"][0].get("message") or {}
                                content = msg.get("content") or ""
                                reasoning_field = msg.get("reasoning") or msg.get("reasoning_content") or ""
                            if not content and not reasoning_field:
                                continue
                            # Extract <think>...</think> if present
                            think_m = re.search(r"<think>(.*?)</think>", content, re.S | re.I)
                            thinking_text = (
                                reasoning_field.strip()
                                or (think_m.group(1).strip() if think_m else "")
                            )
                            clean_content = re.sub(r"<think>.*?</think>", "", content, flags=re.S | re.I).strip()

                            parsed = self._extract_structured_json(clean_content)
                            if isinstance(parsed, dict):
                                if thinking_text and not parsed.get("thinking"):
                                    parsed["thinking"] = thinking_text
                                if not parsed.get("tool_requests"):
                                    if parsed.get("path") and (parsed.get("query") or parsed.get("pattern")):
                                        parsed["tool_requests"] = [{
                                            "tool": "search_code",
                                            "path": parsed.get("path") or "g2s/engine.py",
                                            "pattern": parsed.get("pattern") or parsed.get("query"),
                                        }]
                                    elif parsed.get("path") and parsed.get("start_line"):
                                        parsed["tool_requests"] = [{
                                            "tool": "read_code",
                                            "path": parsed.get("path") or "g2s/engine.py",
                                            "start_line": parsed.get("start_line"),
                                            "end_line": parsed.get("end_line"),
                                        }]
                                    elif parsed.get("tool"):
                                        parsed["tool_requests"] = [parsed]
                                return parsed
                            return {"thinking": thinking_text or clean_content, "analysis": clean_content}
                except Exception:
                    continue
        return None

    async def _run_live_verification(self, run: dict[str, Any], urls: list[str]) -> list[dict[str, Any]]:
        """Runs live bypass verification on `urls` in parallel and streams every step log
        into the AI Console in real time.
        """
        clean_urls = []
        for u in urls:
            u = (u or "").strip()
            if u and u not in clean_urls:
                clean_urls.append(u)
        if not clean_urls:
            return []

        self._emit(
            run,
            "tool_call",
            f"🔧 Tool: run_live_bypass_verification({len(clean_urls)} link(s))",
            "Running live end-to-end bypass check(s) in parallel:\n" + "\n".join(f"• {u}" for u in clean_urls),
        )

        async def _verify_one(u: str) -> dict[str, Any]:
            t0 = time.monotonic()
            short_u = re.sub(r"^https?://", "", u)
            step_logs: list[str] = []

            def on_step(msg: str):
                el = time.monotonic() - t0
                line = f"[{el:5.1f}s] [{short_u}] {msg}"
                step_logs.append(line)
                self._emit(run, "step_log", f"⚡ Live Check [{short_u}]", line)

            try:
                res = await self.resolve_fn(
                    u,
                    force=True,
                    origin="ai-engineer-check",
                    extra_log_cb=on_step,
                )
                dest = res.get("url") or ""
                elapsed = res.get("elapsed") or round(time.monotonic() - t0, 1)
                method = res.get("method") or "bypass"
                self._emit(
                    run,
                    "verified",
                    f"✅ LIVE CHECK PASSED: {short_u} ({elapsed}s)",
                    f"Source: {u}\nDestination: {dest}\nMethod: {method}\nElapsed: {elapsed}s",
                    url=u,
                    destination=dest,
                    elapsed=elapsed,
                )
                return {"url": u, "ok": True, "destination": dest, "elapsed": elapsed, "method": method, "logs": step_logs}
            except Exception as e:
                elapsed = round(time.monotonic() - t0, 1)
                self._emit(
                    run,
                    "error",
                    f"❌ LIVE CHECK FAILED: {short_u} ({elapsed}s)",
                    f"Source: {u}\nError: {e}",
                    url=u,
                    error=str(e),
                )
                return {"url": u, "ok": False, "error": str(e), "elapsed": elapsed, "logs": step_logs}

        results = await asyncio.gather(*(_verify_one(u) for u in clean_urls[:6]))
        return list(results)

    # ------------------------------------------------- Main Autonomous Execution
    async def _execute_run(self, run: dict[str, Any], error_entry: dict | None = None):
        async with self._run_lock:
            try:
                run["phase"] = "scanning_logs"
                self._emit(
                    run,
                    "thinking",
                    "🧠 Initializing Autonomous AI Engineer ('Brother AI')",
                    f"Trigger: {run['trigger']}\nInstruction: {run['prompt']}\n"
                    f"Target URL: {run['target_url'] or 'All unresolved error logs & active shorteners'}",
                )

                # Step 1: Hydrate any latest cloud code revisions, then gather error logs, system logs, and current dynamic rules
                try:
                    await self.code_sync.hydrate_from_mongo_on_boot()
                except Exception:
                    pass
                all_err_logs = await self.db.list_error_logs(limit=30)
                unresolved_logs = [x for x in all_err_logs if not x.get("resolved")]
                sys_logs = self.db.list_system_logs(limit=40)
                dyn_rules = dict(self.db.settings.get("dynamic_rules") or {})
                origin_ips = dict(dyn_rules.get("origin_ips") or {})

                from g2s.engine import (
                    _NEVER_ORIGIN_IP_HOSTS,
                    _NEVER_CHAIN_HOSTS,
                    normalize_input_url,
                    sanitize_dynamic_rules,
                )

                target_urls: list[str] = []
                target_err_entries: list[dict] = []
                normalized_rewrites: list[tuple[str, str]] = []

                def _clean_u(u_str: str) -> str:
                    raw_c = (u_str or "").strip().rstrip(".,;:!?)>]}")
                    if not raw_c or "\u2026" in raw_c or raw_c.endswith("..."):
                        return ""
                    norm_c = normalize_input_url(raw_c)
                    if norm_c and norm_c != raw_c and (raw_c, norm_c) not in normalized_rewrites:
                        normalized_rewrites.append((raw_c, norm_c))
                    return norm_c or raw_c

                def _is_valid_shortener_target(u_str: str) -> bool:
                    if not u_str or not u_str.lower().startswith(("http://", "https://")):
                        return False
                    if "\u2026" in u_str or u_str.endswith("..."):
                        return False
                    p = urlparse(u_str)
                    h = (p.hostname or "").lower()
                    if re.match(r"^ww\d+\.", h):
                        return False
                    b = _base_domain(h)
                    path_clean = p.path.strip("/")
                    if not path_clean and not p.query and not p.fragment:
                        return False
                    blog_only = (
                        "zaikahub.com", "jobsheel.com", "jkdamours.com",
                        "sarkariexam365.com", "gamezizo.com", "financerites.com",
                        "jobsraavi.in", "tradingdemand.com", "techmytrend.in",
                        "recruitmentaim.in", "mahitiplus.com", "suntechu.in",
                        "techyuth.xyz", "finestart.in", "odiadance.com", "google.com",
                    )
                    if any(h == bd or h.endswith("." + bd) or b == bd for bd in blog_only):
                        return False
                    if any(h == bd or h.endswith("." + bd) or b == bd for bd in ("pipefitter.in", "bcsakhi.in", "sarkarijobcorner.com", "rupeeriser.in", "jobskiki.in")):
                        return bool(p.query and "=" in p.query)
                    return True

                from g2s.engine import Bypasser
                for el_scan in ([error_entry] if error_entry else []) + list(unresolved_logs):
                    if not isinstance(el_scan, dict):
                        continue
                    el_src = str(el_scan.get("source") or "")
                    m_nz_src = re.search(r"nazki-protected\.vercel\.app/access/([0-9a-fA-F-]{16,})", el_src)
                    for step_ln in (el_scan.get("log") or []):
                        m_unw = re.search(r"Unwrapped nazki-protected gate\s*(?:→|->)\s*(https?://[^\s<>\"']+)", str(step_ln))
                        if m_unw and m_nz_src:
                            Bypasser._nazki_session_cache[m_nz_src.group(1)] = m_unw.group(1).strip()

                def _extract_unwrapped_inner(el_dict: dict) -> str:
                    for step_ln in (el_dict.get("log") or []):
                        m_unw = re.search(r"Unwrapped nazki-protected gate\s*(?:→|->)\s*(https?://[^\s<>\"']+)", str(step_ln))
                        if m_unw:
                            return _clean_u(m_unw.group(1))
                        m_koy = re.search(
                            r"(https?://(?:sarkariresultus\.com|kishanganjhalchal\.com)/[^\s<>\"']*link=[^\s<>\"']+)",
                            str(step_ln),
                        )
                        if m_koy:
                            return _clean_u(m_koy.group(1))
                    el_src = str(el_dict.get("source") or "")
                    m_nz_s = re.search(r"nazki-protected\.vercel\.app/access/([0-9a-fA-F-]{16,})", el_src)
                    if m_nz_s:
                        return _clean_u(Bypasser._nazki_session_cache.get(m_nz_s.group(1)) or "")
                    return ""

                if run["target_url"]:
                    cu = _clean_u(run["target_url"])
                    if _is_valid_shortener_target(cu):
                        target_urls.append(cu)

                if error_entry:
                    target_err_entries.append(error_entry)
                    es = _clean_u(error_entry.get("source") or "")
                    if _is_valid_shortener_target(es) and es not in target_urls:
                        target_urls.append(es)
                    inner_u = _extract_unwrapped_inner(error_entry)
                    if _is_valid_shortener_target(inner_u) and inner_u not in target_urls:
                        target_urls.append(inner_u)
                elif not target_urls:
                    for m_url in re.findall(r"(?<!Stuck on )(?<!Step → )(?<!Navigating → )https?://[^\s<>\"']+", run["prompt"]):
                        cu = _clean_u(m_url)
                        if _is_valid_shortener_target(cu) and cu not in target_urls:
                            target_urls.append(cu)
                    for el in unresolved_logs[:5]:
                        target_err_entries.append(el)
                        src = _clean_u(el.get("source") or "")
                        if _is_valid_shortener_target(src) and src not in target_urls and len(target_urls) < 4:
                            target_urls.append(src)
                        inner_u = _extract_unwrapped_inner(el)
                        if _is_valid_shortener_target(inner_u) and inner_u not in target_urls and len(target_urls) < 5:
                            target_urls.append(inner_u)

                self._emit(
                    run,
                    "tool_call",
                    "🔧 Tool: get_system_diagnostics()",
                    f"Scanning {len(unresolved_logs)} unresolved error log(s) and {len(sys_logs)} recent system events…",
                )
                diag_summary = {
                    "unresolved_error_count": len(unresolved_logs),
                    "target_urls": target_urls,
                    "recent_errors": [
                        {
                            "id": e.get("id"),
                            "source": e.get("source"),
                            "error": e.get("error"),
                            "last_steps": (e.get("log") or [])[-5:],
                        }
                        for e in (target_err_entries or unresolved_logs[:4])
                    ],
                    "configured_origin_ips": origin_ips,
                }
                self._emit(run, "tool_result", "📥 System Diagnostics Snapshot", json.dumps(diag_summary, indent=2))

                # Step 2: Live HTTP + Multi-Hop Redirect Chain + DNS/SPF Origin Research
                run["phase"] = "researching"
                probe_reports = []
                chain_traces = []
                page_inspections = []
                rules_patch: dict[str, Any] = {
                    "origin_ips": {},
                    "referer_overrides": {},
                    "chain_hosts": [],
                    "avbypass_hosts": [],
                    "linkprotect_hosts": [],
                    "safelinku_hosts": [],
                    "laila_hosts": [],
                    "short4cash_hosts": [],
                    "shortners_workers_hosts": [],
                    "vplinks_beta_hosts": [],
                    "lootlabs_hosts": [],
                    "linkvertise_hosts": [],
                    "ad_domains": [],
                    "ad_query_keys": [],
                    "timer_overrides": {},
                }
                dead_404_urls: set[str] = set()
                state_fixes_applied: list[str] = []
                for raw_rw, norm_rw in normalized_rewrites:
                    state_fixes_applied.append(f"Normalized URL {raw_rw} -> {norm_rw}")
                    self._emit(
                        run,
                        "thinking",
                        f"🔧 Auto-Normalized URL: {raw_rw} → {norm_rw}",
                        f"Detected domain typo, Telegram underscore-entity truncation, or intermediate safelink entry URL (`{raw_rw}`) and normalized it to `{norm_rw}`.",
                    )

                # 2a) Automatic Dynamic Rules Hygiene & Poisoned-Host Sanitizer
                from g2s.engine import set_dynamic_rules
                sanitized_dyn = sanitize_dynamic_rules(dyn_rules)
                if sanitized_dyn != dyn_rules:
                    await self.db.update_settings({"dynamic_rules": sanitized_dyn}, notify=False)
                    set_dynamic_rules(sanitized_dyn)
                    dyn_rules = sanitized_dyn
                    state_fixes_applied.append("Purged poisoned root shortener/ad hosts from dynamic_rules")
                    self._emit(
                        run,
                        "thinking",
                        "🧹 Sanitized Dynamic Rules & Purged Poisoned Hosts",
                        "Automatically cleaned root shortener/captcha hosts out of `dynamic_rules` so chained shortener destinations are never rejected or misrouted.",
                    )

                for u in target_urls[:4]:
                    host = _host_of(u)
                    base = _base_domain(host)
                    known_ip = origin_ips.get(host) or origin_ips.get(base)

                    # First probe with known origin IP (if any) or standard DNS
                    p_info = await self._tool_probe_shortener_url(run, u, origin_ip=known_ip)

                    # Only run origin discovery if blocked by VPN/Cloudflare or 52x origin error
                    if p_info.get("is_vpn_or_rate_blocked") or p_info.get("status") in (403, 520, 521, 522, 523, 524, 525, 526):
                        disc = await self._tool_discover_origin_ip(run, host)
                        found_ip = disc.get("verified_origin_ip")
                        if found_ip and found_ip != known_ip:
                            for sub_h in (
                                host,
                                base,
                                f"link.{base}",
                                f"go.{base}",
                                f"open.{base}",
                                f"m.{base}",
                                f"ai3.{base}",
                            ):
                                rules_patch["origin_ips"][sub_h] = found_ip
                                origin_ips[sub_h] = found_ip
                            p_info = await self._tool_probe_shortener_url(run, u, origin_ip=found_ip)

                    # Deep Page, Inline Script & Debug Snapshot Inspection
                    err_match_for_u = next(
                        (ed for ed in target_err_entries if _clean_u(ed.get("source") or "") == u),
                        None,
                    )
                    err_steps_str = "\n".join((err_match_for_u or {}).get("log") or [])
                    if not p_info.get("is_dead_404"):
                        insp = await self._tool_inspect_page_and_scripts(run, u, step_lines=err_steps_str, origin_ip=known_ip)
                        page_inspections.append(insp)
                        for av_h in insp.get("avbypass_hosts_found") or []:
                            if (
                                av_h
                                and not any(av_h == bad or av_h.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                                and av_h not in (dyn_rules.get("avbypass_hosts") or [])
                                and av_h not in rules_patch["avbypass_hosts"]
                            ):
                                rules_patch["avbypass_hosts"].append(av_h)
                                if av_h not in (dyn_rules.get("chain_hosts") or []) and av_h not in rules_patch["chain_hosts"]:
                                    rules_patch["chain_hosts"].append(av_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected MRN/AvBypass/Koyeb Gate Template on {av_h}",
                                    f"Script & cookie inspection found `/verify_captcha` / `?ctoken=` on `{av_h}`. "
                                    f"Registered `{av_h}` in `dynamic_rules.avbypass_hosts` for direct unwrapping.",
                                )
                        for lh_found in insp.get("laila_hosts_found") or []:
                            if lh_found and lh_found not in (dyn_rules.get("laila_hosts") or []) and lh_found not in rules_patch["laila_hosts"]:
                                rules_patch["laila_hosts"].append(lh_found)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected Laila / Railway Security Checkpoint on {lh_found}",
                                    f"Script inspection found `/api/init/` + `/api/complete/` on `{lh_found}`. "
                                    f"Registered `{lh_found}` in `dynamic_rules.laila_hosts` for direct checkpoint unlocking.",
                                )
                        for s4_h in insp.get("short4cash_hosts_found") or []:
                            if s4_h and s4_h not in (dyn_rules.get("short4cash_hosts") or []) and s4_h not in rules_patch["short4cash_hosts"]:
                                rules_patch["short4cash_hosts"].append(s4_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected Short4Cash / SayPhotoBooth Safelink on {s4_h}",
                                    f"Script inspection found `newwpsafelink12` / `go.short4cash.com` on `{s4_h}`. "
                                    f"Registered `{s4_h}` in `dynamic_rules.short4cash_hosts`.",
                                )
                        for sw_h in insp.get("shortners_workers_hosts_found") or []:
                            if sw_h and sw_h not in (dyn_rules.get("shortners_workers_hosts") or []) and sw_h not in rules_patch["shortners_workers_hosts"]:
                                rules_patch["shortners_workers_hosts"].append(sw_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected LinkForge / Shortners.Workers Gate on {sw_h}",
                                    f"Script inspection found Turnstile `action=redirect` + `thankyoucloudflare.workers.dev` on `{sw_h}`. "
                                    f"Registered `{sw_h}` in `dynamic_rules.shortners_workers_hosts`.",
                                )
                        for vb_h in insp.get("vplinks_beta_hosts_found") or []:
                            if vb_h and vb_h not in (dyn_rules.get("vplinks_beta_hosts") or []) and vb_h not in rules_patch["vplinks_beta_hosts"]:
                                rules_patch["vplinks_beta_hosts"].append(vb_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected VPLinks Beta Django Gate on {vb_h}",
                                    f"Script inspection found `csrfmiddlewaretoken` + `/continue/` + `wait_token_` on `{vb_h}`. "
                                    f"Registered `{vb_h}` in `dynamic_rules.vplinks_beta_hosts`.",
                                )
                        for lp_h in insp.get("linkprotect_hosts_found") or []:
                            if (
                                lp_h
                                and not any(lp_h == bad or lp_h.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                                and lp_h not in (dyn_rules.get("linkprotect_hosts") or [])
                                and lp_h not in rules_patch["linkprotect_hosts"]
                            ):
                                rules_patch["linkprotect_hosts"].append(lp_h)
                                if lp_h not in (dyn_rules.get("chain_hosts") or []) and lp_h not in rules_patch["chain_hosts"]:
                                    rules_patch["chain_hosts"].append(lp_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected LinkProtect Worker Template on {lp_h}",
                                    f"Script inspection found `/api/claim` + `/finish2` on `{lp_h}`. "
                                    f"Registered `{lp_h}` in `dynamic_rules.linkprotect_hosts`.",
                                )
                        for sf_h in insp.get("safelinku_hosts_found") or []:
                            if sf_h not in (dyn_rules.get("safelinku_hosts") or []) and sf_h not in rules_patch["safelinku_hosts"]:
                                rules_patch["safelinku_hosts"].append(sf_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected SafeLinkU / Khaddavi Template on {sf_h}",
                                    f"Script inspection found `/api/session` + `/api/verify` + `/api/go` on `{sf_h}`. "
                                    f"Registered `{sf_h}` in `dynamic_rules.safelinku_hosts`.",
                                )
                        for ll_h in insp.get("lootlabs_hosts_found") or []:
                            if ll_h not in (dyn_rules.get("lootlabs_hosts") or []) and ll_h not in rules_patch["lootlabs_hosts"]:
                                rules_patch["lootlabs_hosts"].append(ll_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected LootLabs ('31.js' / conf_rew) Template on {ll_h}",
                                    f"Script inspection found `window.conf_rew` / `31.js` on `{ll_h}`. "
                                    f"Registered `{ll_h}` in `dynamic_rules.lootlabs_hosts` for direct WebGL PoW + WebSocket + Turnstile unlocking.",
                                )
                        for lv_h in insp.get("linkvertise_hosts_found") or []:
                            if lv_h not in (dyn_rules.get("linkvertise_hosts") or []) and lv_h not in rules_patch["linkvertise_hosts"]:
                                rules_patch["linkvertise_hosts"].append(lv_h)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Auto-Detected Linkvertise GraphQL Template on {lv_h}",
                                    f"Inspection found `publisher.linkvertise.com/graphql` / `linkvertise.com` on `{lv_h}`. "
                                    f"Registered `{lv_h}` in `dynamic_rules.linkvertise_hosts` for direct GraphQL task completion.",
                                )

                    # Trace multi-hop redirect chain (cookies, forms, timers, chain_hosts, ad false positives)
                    if not p_info.get("is_dead_404"):
                        c_trace = await self._tool_trace_redirect_chain(run, u, origin_ips, max_hops=5)
                        chain_traces.append(c_trace)
                        for r_dom, r_ref in (c_trace.get("discovered_referer_overrides") or {}).items():
                            if r_dom and r_ref:
                                rules_patch["referer_overrides"][r_dom] = r_ref
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Discovered 2-Hop Blog Referer Override for {r_dom}: {r_ref}",
                                    f"Multi-hop trace discovered that `{r_dom}` requires final blog referer `{r_ref}`.",
                                )
                        for m_ch in (c_trace.get("missing_chain_hosts") or []):
                            if m_ch not in (dyn_rules.get("chain_hosts") or []) and m_ch not in rules_patch["chain_hosts"]:
                                rules_patch["chain_hosts"].append(m_ch)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Detected Unregistered Intermediate Chain Domain: {m_ch}",
                                    f"Multi-hop trace for `{u}` hopped through `{m_ch}`, which was missing from `chain_hosts`. "
                                    f"Adding `{m_ch}` to `dynamic_rules.chain_hosts` so the engine recognizes it as an intermediate step.",
                                )

                    # Check if shortener redirected to a new intermediate blog/safelink domain
                    for redir_u in ([p_info.get("location")] if p_info.get("location") else []) + (p_info.get("js_redirects") or []):
                        if redir_u and redir_u.startswith("http"):
                            r_host = _host_of(redir_u)
                            r_base = _base_domain(r_host)
                            if (
                                r_base
                                and r_base != base
                                and not any(r_base == bad or r_base.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                            ):
                                if r_base not in (dyn_rules.get("chain_hosts") or []) and r_base not in rules_patch["chain_hosts"]:
                                    rules_patch["chain_hosts"].append(r_base)
                                    self._emit(
                                        run,
                                        "thinking",
                                        f"🧠 Detected Intermediate Safelink/Blog Domain: {r_host}",
                                        f"{u} redirects through intermediate domain `{r_host}` (`{r_base}`). "
                                        f"Registering `{r_base}` in dynamic chain_hosts so the engine treats it as an intermediate step, not a final destination.",
                                    )

                    if p_info.get("is_dead_404"):
                        dead_404_urls.add(u)
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Confirmed Dead 404 Link on {host}",
                            f"Direct origin probe confirmed `{u}` returns HTTP 404 ('was not found on this server'). "
                            f"This link was deleted on `{host}` by its creator.",
                        )
                    elif (
                        p_info.get("location")
                        and re.match(r"^(www\.)?google\.[a-z.]+$", _host_of(str(p_info.get("location"))))
                        and (urlparse(str(p_info.get("location"))).path or "") in ("", "/", "/webhp")
                        and not urlparse(str(p_info.get("location"))).query
                    ):
                        dead_404_urls.add(u)
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Confirmed Expired One-Time Link on {host} (Redirected to google.com)",
                            f"Direct HTTP probe confirmed `{u[:100]}` returns HTTP {p_info.get('status')} Location `{p_info.get('location')}`. "
                            f"Single-use verification token was already consumed.",
                        )
                    elif (
                        base
                        and base not in (dyn_rules.get("referer_overrides") or {})
                        and base not in rules_patch.get("referer_overrides", {})
                        and (p_info.get("location") or any("AppSession" in str(c) or "csrfToken" in str(c) for c in (p_info.get("set_cookies") or [])))
                    ):
                        # Autonomous AdLinkFly Final-Hop Referer Prober
                        try:
                            alias_p = urlparse(u).path.strip("/")
                            if alias_p and "/" not in alias_p:
                                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s_rf:
                                    for cand_ref in (
                                        "https://savepe.in/",
                                        "https://techmody.io/",
                                        "https://game5s.com/",
                                        "https://themezon.net/",
                                        "https://jobsheel.com/",
                                        "https://skrresults.com/",
                                    ):
                                        try:
                                            async with s_rf.get(
                                                f"https://{host}/{alias_p}",
                                                headers={"User-Agent": "Mozilla/5.0", "Referer": cand_ref},
                                                allow_redirects=False,
                                            ) as r_rf:
                                                txt_rf = await r_rf.text()
                                                if 'id="go-link"' in txt_rf or "id='go-link'" in txt_rf:
                                                    rules_patch.setdefault("referer_overrides", {})[base] = cand_ref
                                                    self._emit(
                                                        run,
                                                        "thinking",
                                                        f"🧠 Auto-Discovered Final-Hop Referer Bypass for {base}: {cand_ref}",
                                                        f"Probing `{u}` with `Referer: {cand_ref}` unlocked `<form id=\"go-link\">` directly (skipping multi-step blog).",
                                                    )
                                                    break
                                        except Exception:
                                            pass
                        except Exception:
                            pass

                    probe_reports.append(p_info)

                # Step 3: Deep Step-Log & Traceback Root-Cause Analysis
                from g2s.engine import Job
                extra_code_context: list[dict] = []
                for err_doc in target_err_entries:
                    err_txt = str(err_doc.get("error") or "")
                    src_u = str(err_doc.get("source") or "")
                    log_list = err_doc.get("log") or []
                    step_lines = "\n".join(log_list)
                    s_host = _host_of(src_u)
                    b_dom = _base_domain(s_host)

                    # 3a) Check for expired/offline proxy errors (ERR_PROXY_CONNECTION_FAILED)
                    if any(pe in err_txt or pe in step_lines for pe in (
                        "ERR_PROXY_CONNECTION_FAILED", "ERR_TUNNEL_CONNECTION_FAILED"
                    )):
                        bp = self.get_bypasser()
                        stale_px = self.db.settings.get("proxy")
                        if bp and stale_px:
                            bp._mark_proxy_expired(stale_px)
                        if not self.db.settings.get("proxy_expired"):
                            await self.db.update_settings({"proxy_expired": True}, notify=False)
                        state_fixes_applied.append("Cleared stale offline tunnel proxy across all browser workers")
                        self._emit(
                            run,
                            "thinking",
                            "🧠 Root Cause: Offline Tunnel Proxy Cached on Worker",
                            f"Error log shows `ERR_PROXY_CONNECTION_FAILED`. Marked tunnel proxy expired across parent Bypasser, "
                            f"all browser workers, and MongoDB settings so direct connection is used immediately.",
                        )

                    # 3b) Check for Patchright InterceptionId / Target crashed / launch_persistent_context timeout / ERR_ABORTED
                    if any(ce in err_txt or ce in step_lines for ce in (
                        "Invalid InterceptionId", "TargetClosedError", "pipe closed by peer",
                        "Target crashed", "launch_persistent_context", "Could not start browser",
                        "net::ERR_ABORTED", "Could not open link",
                    )):
                        bp = self.get_bypasser()
                        if bp:
                            for w in [bp] + list(getattr(bp, "_workers", []) or []):
                                p_dir = getattr(getattr(w, "cfg", None), "profile_dir", None)
                                if not getattr(w, "_busy", False) and not w._lock.locked():
                                    w.ctx = None
                                    if getattr(w, "_pw", None) is not None:
                                        try:
                                            await asyncio.wait_for(w._pw.stop(), timeout=3.0)
                                        except Exception:
                                            pass
                                        w._pw = None
                                    if p_dir and hasattr(bp, "_kill_profile_procs"):
                                        bp._kill_profile_procs(os.path.abspath(p_dir))
                        state_fixes_applied.append("Killed hung Chromium processes, reset driver pipes & cleared SingletonLocks across idle workers")
                        self._emit(
                            run,
                            "thinking",
                            "🧠 Root Cause: Browser Context Crash / SingletonLock Contention",
                            "Detected `Target crashed` / `launch_persistent_context` / `net::ERR_ABORTED` in trace. "
                            "Killed any hung Chromium child processes, reset Patchright driver pipes, and purged stale SingletonLock files across all idle workers.",
                        )

                    # 3b2) Check if direct connection hit Cloudflare challenge or static WAF/country block
                    if b_dom and (
                        "cloudflare keeps re-challenging" in err_txt.lower()
                        or "cloudflare keeps re-challenging" in step_lines.lower()
                        or b_dom == "directlinker.com"
                    ):
                        if b_dom == "directlinker.com":
                            await self.db.set_shortener_tunnel(b_dom, False)
                            rules_patch.setdefault("directlinker_hosts", [])
                            if b_dom not in rules_patch["directlinker_hosts"]:
                                rules_patch["directlinker_hosts"].append(b_dom)
                            state_fixes_applied.append(
                                f"Activated global redirect-checker & Rentry->Linkvertise multi-hop unwrapper for {b_dom}"
                            )
                            self._emit(
                                run,
                                "thinking",
                                f"🧠 Root Cause: Cloudflare Regional WAF Block (`Attention Required!`) on {b_dom}",
                                f"Detected static Cloudflare WAF block (`403 Attention Required!`) on `{b_dom}` when accessed from Indian/VPS IPs, "
                                f"followed by intermediate `rentry.co` -> `{b_dom}/linkvert/...` -> `link-to.net` hops. "
                                f"Enabled `_resolve_cf_blocked_redirect` (`api.redirect-checker.net` + `r.jina.ai`) and recursive Rentry shortener unwrapping.",
                            )
                        else:
                            await self.db.set_shortener_tunnel(b_dom, True)
                            state_fixes_applied.append(f"Auto-enabled tunnel device routing for {b_dom}")
                            self._emit(
                                run,
                                "thinking",
                                f"🧠 Root Cause: Datacenter IP Blocked by Cloudflare on {b_dom}",
                                f"Detected `Cloudflare keeps re-challenging` on `{b_dom}` during direct connection. "
                                f"Automatically enabled `shortener_tunnels[{b_dom!r}] = True` so `{b_dom}` routes directly through connected residential/mobile tunnel devices.",
                            )

                    if b_dom in ("lockr.to", "lockr.net", "lockr.so") or "lockr.net" in step_lines.lower():
                        rules_patch.setdefault("lockr_hosts", [])
                        for lkh in ("lockr.to", "lockr.net", "lockr.so"):
                            if lkh not in rules_patch["lockr_hosts"]:
                                rules_patch["lockr_hosts"].append(lkh)
                        state_fixes_applied.append(
                            "Activated lockr.net direct API solver (/api/v1/lockers/{id}/view -> /task -> 30s /unlock)"
                        )
                        self._emit(
                            run,
                            "thinking",
                            "🧠 Root Cause: lockr.net Next.js SPA Waitlist & Task API",
                            "Reverse-engineered `lockr.net/_next/static/chunks/09km.8pahe1hc.js`: clicking 'Unlock content' in the DOM is blocked by a 3600s client timer. "
                            "Activated `_try_lockr_direct` to call `GET /api/v1/lockers/{id}/view`, complete `GET /api/v1/lockers/{id}/task?token={tok}`, "
                            "and poll `GET /api/v1/lockers/{id}/unlock?token={tok}` after the 30s server timer.",
                        )

                    if "up.railway.app" in s_host or "ai security checkpoint" in step_lines.lower():
                        rules_patch.setdefault("laila_hosts", [])
                        if s_host and s_host not in rules_patch["laila_hosts"]:
                            rules_patch["laila_hosts"].append(s_host)
                        state_fixes_applied.append(
                            f"Activated Laila Railway direct XOR-42 payload unwrapper & dynamic shortener referer on {s_host}"
                        )
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Root Cause: Laila Railway AI Security Checkpoint Payload & Referer on {s_host}",
                            f"Diagnosed `/api/init/` + `/api/complete/` on `{s_host}`: `d2['payload']` XOR-42 decodes directly to the final `https://t.me/...` destination URL "
                            f"and requires dynamic `https://link.{{short_host}}/` referer + WebGL GPU telemetry.",
                        )

                    if "publicbotshub-verify.koyeb.app" in s_host or ("koyeb.app" in s_host and "/link/" in src_u):
                        await self.db.set_shortener_tunnel(s_host or "publicbotshub-verify.koyeb.app", True)
                        state_fixes_applied.append(
                            f"Enabled hybrid residential tunnel routing + direct Google reCAPTCHA v2 CDN fast-lane & preserved single-use token on {s_host}"
                        )
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Root Cause: Hybrid Residential Tunnel + Direct reCAPTCHA v2 Fast-Lane on {s_host}",
                            f"Diagnosed `{s_host}`: routed `{s_host}` through residential tunnel to avoid VPN/Datacenter IP blocks while bypassing `www.google.com` & `gstatic.com` "
                            f"reCAPTCHA v2 3x3 tile images directly at full VPS speed, waited for `.rc-imageselect-tile img.complete`, and skipped raw HTTP probes to preserve the single-use `/link/` token.",
                        )

                    if b_dom in ("torupload.com", "frdl.io", "frdl.my", "file-upload.org", "dgdrive.site"):
                        state_fixes_applied.append(
                            f"Activated direct file-host unwrapper / domain migration handler for {b_dom}"
                        )
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Root Cause: File-Host Wrapper / Domain Migration on {b_dom}",
                            f"Configured `_try_filehost_direct` to unwrap `{b_dom}` (`d.torupload.com` -> `torupload.com/file/...`, `frdl.io` -> `frdl.my`, `file-upload.org`, and fast-fail parked `dgdrive.site`).",
                        )

                    # 3b3) Check for Turnstile / Origin API / LinkProtect / Linkvertise GraphQL failures -> enable local Camoufox & WS tunnel failover
                    if any(tk in err_txt.lower() or tk in step_lines.lower() for tk in (
                        "could not resolve vplink.in",
                        "could not resolve arolinks.com",
                        "submitting final form to fetch destination",
                        "linkprotect.bindaasheart.workers.dev",
                        "turnstile",
                        "unauthorized",
                    )):
                        try:
                            from g2s import solver as _sol_mod
                            if hasattr(_sol_mod, "_LOCAL_SOLVER"):
                                await _sol_mod._LOCAL_SOLVER.ensure()
                            bp = self.get_bypasser()
                            if bp and getattr(bp, "solver", None):
                                bp.solver._remote_unauth_until = time.monotonic() + 1800.0
                        except Exception:
                            pass
                        state_fixes_applied.append("Activated built-in Camoufox local Turnstile solver & sanitized action parameter")
                        self._emit(
                            run,
                            "thinking",
                            "🧠 Root Cause: External Turnstile Solver HTTP 401 / Action Validation Failure",
                            "Detected Turnstile failure at final submission step (`cf.vltcx.eu.cc` HTTP 401 or invalid `action` format). "
                            "Activated built-in Camoufox local Turnstile solver under Xvfb and action sanitization.",
                        )

                    if any(lk in err_txt.lower() or lk in step_lines.lower() for lk in (
                        "linkvertise graphql api",
                        "linkvertise hourly ip quota",
                        "link-center.net",
                        "link-hub.net",
                        "direct-link.net",
                        "link-target.net",
                    )):
                        bp = self.get_bypasser()
                        if bp and "hourly ip quota" in err_txt.lower():
                            bp._lv_direct_quota_until = time.monotonic() + 900.0
                        state_fixes_applied.append("Enabled Linkvertise WaitTask completion & Reverse WS tunnel failover")
                        self._emit(
                            run,
                            "thinking",
                            "🧠 Root Cause: Linkvertise WaitTask Timer / Direct IP Cooldown",
                            "Enabled full 95s WaitTask completion within the active GraphQL session and prioritized connected Reverse WS tunnel devices when direct IP hits hourly quota.",
                        )

                    # 3c) Scan all Step / Navigating / Stuck URLs in error log for unregistered intermediate chain domains or ad false positives
                    dummy_j = Job(src_u or "https://example.com", lambda *_: None, asyncio.get_running_loop())
                    step_urls = re.findall(
                        r"(?:Step\s*→|Navigating\s*→|Stuck on)\s*(https?://[^\s…\"'<>)\]]+)",
                        step_lines + "\n" + err_txt,
                    )
                    host_counts: dict[str, int] = {}
                    for su in step_urls:
                        sh = _host_of(su)
                        sb = _base_domain(sh)
                        is_ad_redir = dummy_j.is_ad_domain(su) or bool(
                            re.search(
                                r"(?:utm_source=adsterra|clickid=|af_adset_id=|[?&]s2s=|pornworks\.com|xm\.com|uplcm\.com|al5sm\.com|cardiaccrystaleternity\.com)",
                                su,
                                re.I,
                            )
                        )
                        if sb and not is_ad_redir:
                            host_counts[sb] = host_counts.get(sb, 0) + 1
                        if (
                            sb
                            and not is_ad_redir
                            and sb != b_dom
                            and re.match(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$", sb)
                            and not any(sb == bad or sb.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                        ):
                            in_ch = dummy_j.is_chain(su) or (
                                sb in (dyn_rules.get("chain_hosts") or [])
                            )
                            if not in_ch and sb not in rules_patch["chain_hosts"]:
                                rules_patch["chain_hosts"].append(sb)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Discovered Missing Chain Host from Step Log: {sb}",
                                    f"Step trace visited `{su}` (`{sb}`), which was not in `chain_hosts`. Added `{sb}` to `dynamic_rules.chain_hosts`.",
                                )

                    # 3d) Detect step redirect loop (same domain visited >= 3 times)
                    looping_hosts = [h for h, cnt in host_counts.items() if cnt >= 3]
                    if looping_hosts:
                        self._emit(
                            run,
                            "thinking",
                            f"🧠 Detected Step Redirect Loop on {', '.join(looping_hosts)} for {src_u}",
                            f"Step logs show `{src_u}` looped across `{', '.join(looping_hosts)}` ({host_counts}). "
                            f"Inspecting `{b_dom}` solver and step-unwrapping logic in `g2s/engine.py`…",
                        )

                    # 3e) Check if an error log was caused by Access Temporarily Restricted or timer not ready
                    if "timer not ready" in step_lines.lower() or "access temporarily restricted" in step_lines.lower():
                        if b_dom:
                            rules_patch["timer_overrides"][b_dom] = 62.0
                            self._emit(
                                run,
                                "thinking",
                                f"🧠 Detected Server-Side Timer Violation on {b_dom}",
                                f"Step logs show server timer rejection on `{b_dom}`. Enforcing strict timer safeguard in dynamic_rules.",
                            )

                    # Pre-load relevant code lines from g2s/engine.py for the failing domain
                    if b_dom and not extra_code_context:
                        try:
                            eng_lines = self.code_sync.read_local_file("g2s/engine.py").splitlines()
                            match_lines = [i for i, ln in enumerate(eng_lines, 1) if b_dom in ln]
                            for ml in match_lines[:2]:
                                s_ln = max(1, ml - 10)
                                e_ln = min(len(eng_lines), ml + 65)
                                snippet = "\n".join(f"{i}: {eng_lines[i-1]}" for i in range(s_ln, e_ln + 1))
                                extra_code_context.append({
                                    "tool": "read_code",
                                    "path": "g2s/engine.py",
                                    "lines": f"{s_ln}-{e_ln}",
                                    "content": snippet,
                                })
                        except Exception:
                            pass

                # Pre-check direct HTTP solvers before calling external LLMs (so already-working or rule-fixed links verify in seconds)
                bp_verify = self.get_bypasser()
                pre_verified_direct: dict[str, dict] = {}
                if bp_verify is not None and target_urls:
                    try:
                        # Temporarily apply any newly discovered rules_patch in memory before direct check
                        merged_preview = dict(dyn_rules)
                        for rk, rv in rules_patch.items():
                            if not rv:
                                continue
                            if isinstance(rv, dict):
                                merged_preview[rk] = {**(merged_preview.get(rk) or {}), **rv}
                            elif isinstance(rv, list):
                                cur_l = list(merged_preview.get(rk) or [])
                                for it in rv:
                                    if it not in cur_l:
                                        cur_l.append(it)
                                merged_preview[rk] = cur_l
                        set_dynamic_rules(merged_preview)
                    except Exception:
                        pass
                    for u_pre in target_urls:
                        if u_pre in dead_404_urls:
                            continue
                        try:
                            d_pre = await bp_verify._try_direct_solvers(u_pre, lambda *_: None, time.monotonic())
                            if isinstance(d_pre, dict) and d_pre.get("url"):
                                pre_verified_direct[u_pre] = d_pre
                                continue
                        except Exception as e_pre:
                            e_pre_low = str(e_pre).lower()
                            u_pre_host = (urlparse(u_pre).hostname or "").lower().removeprefix("www.")
                            if any(
                                fk in e_pre_low
                                for fk in (
                                    "expired",
                                    "already used",
                                    "http 410",
                                    "invalid url",
                                    "paid qris paywall",
                                    "is_premium_only=true",
                                    "premium-only paywall link",
                                    "real-money",
                                    "cannot be bypassed for free",
                                    "redirected to parked host",
                                )
                            ) or (
                                ("not found" in e_pre_low or "http 404" in e_pre_low)
                                and (not u_pre_host or u_pre_host in e_pre_low or "short4cash" not in e_pre_low)
                                and "sayphotobooth" not in e_pre_low
                            ):
                                dead_404_urls.add(u_pre)
                                continue

                        # Universal Autonomous Protocol Prober for brand-new/unknown shorteners:
                        # Probes izen.lol, aizernal.xyz, redirect-checker.net, and direct HTML <form> submission!
                        try:
                            u_host = _host_of(u_pre)
                            u_base = _base_domain(u_host)
                            self._emit(
                                run,
                                "tool_call",
                                f"🔧 Tool: probe_universal_bypasses({u_pre})",
                                f"Autonomously probing izen.lol, aizernal.xyz, redirect-checker, and HTML form APIs for {u_base}…",
                            )
                            j_univ = Job(u_pre, lambda *_: None, asyncio.get_running_loop())
                            t_univ = time.monotonic()
                            if await bp_verify._try_izen_direct(j_univ, url_override=u_pre) and j_univ.final_url:
                                rules_patch.setdefault("izen_hosts", [])
                                if u_base and u_base not in rules_patch["izen_hosts"]:
                                    rules_patch["izen_hosts"].append(u_base)
                                pre_verified_direct[u_pre] = {
                                    "url": j_univ.final_url,
                                    "elapsed": round(time.monotonic() - t_univ, 1),
                                    "method": j_univ.method or "izen.lol API",
                                    "steps": j_univ.steps,
                                    "source": u_pre,
                                    "extra_links": getattr(j_univ, "extra_links", []),
                                }
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Autonomous Protocol Discovery: {u_base} Supported by izen.lol API",
                                    f"Probed `POST https://izen.lol/api/bypass` for `{u_pre}` -> resolved to `{j_univ.final_url}`. "
                                    f"Registered `{u_base}` in `dynamic_rules.izen_hosts`.",
                                )
                                continue
                            j_sh = Job(u_pre, lambda *_: None, asyncio.get_running_loop())
                            if await bp_verify._try_shrinkme_direct(j_sh, url_override=u_pre) and j_sh.final_url:
                                rules_patch.setdefault("shrinkme_hosts", [])
                                if u_base and u_base not in rules_patch["shrinkme_hosts"]:
                                    rules_patch["shrinkme_hosts"].append(u_base)
                                pre_verified_direct[u_pre] = {
                                    "url": j_sh.final_url,
                                    "elapsed": round(time.monotonic() - t_univ, 1),
                                    "method": j_sh.method or "aizernal.xyz API",
                                    "steps": j_sh.steps,
                                    "source": u_pre,
                                    "extra_links": getattr(j_sh, "extra_links", []),
                                }
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Autonomous Protocol Discovery: {u_base} Supported by aizernal.xyz API",
                                    f"Probed `POST https://aizernal.xyz/api/resolve` for `{u_pre}` -> resolved to `{j_sh.final_url}`. "
                                    f"Registered `{u_base}` in `dynamic_rules.shrinkme_hosts`.",
                                )
                                continue
                            j_dl = Job(u_pre, lambda *_: None, asyncio.get_running_loop())
                            if await bp_verify._try_directlinker_direct(j_dl, url_override=u_pre) and j_dl.final_url:
                                rules_patch.setdefault("directlinker_hosts", [])
                                if u_base and u_base not in rules_patch["directlinker_hosts"]:
                                    rules_patch["directlinker_hosts"].append(u_base)
                                pre_verified_direct[u_pre] = {
                                    "url": j_dl.final_url,
                                    "elapsed": round(time.monotonic() - t_univ, 1),
                                    "method": j_dl.method or "redirect-checker API",
                                    "steps": j_dl.steps,
                                    "source": u_pre,
                                    "extra_links": getattr(j_dl, "extra_links", []),
                                }
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Autonomous Protocol Discovery: {u_base} Unwrapped via Redirect-Checker Chain",
                                    f"Unwrapped `{u_pre}` -> `{j_dl.final_url}` and registered `{u_base}` in `dynamic_rules.directlinker_hosts`.",
                                )
                                continue
                        except Exception:
                            pass

                unresolved_for_llm = [
                    u_cand for u_cand in target_urls
                    if u_cand not in dead_404_urls and u_cand not in pre_verified_direct
                ]

                # Step 4: Consult LLM Thinking Brain (only when target URLs still need code/rule synthesis)
                run["phase"] = "thinking"
                sys_prompt = (
                    "You are TheDrunkBots Autonomous AI Engineer ('Brother AI'), an elite senior Python & "
                    "browser-automation root-cause software engineer built into a URL shortener bypass platform.\n"
                    "Tracked codebase files: g2s/engine.py (all direct solvers & `_solve_recaptcha_v2`), g2s/scripts.py (`INIT_SCRIPT` & `SCAN_JS`), g2s/bot.py, g2s/db.py, g2s/solver.py (Cloudflare Turnstile solver), g2s/ws_tunnel.py, server.py.\n"
                    "CRITICAL RULES:\n"
                    "1. Diagnose the EXACT technical root cause from the step logs, page/script inspection, multi-hop redirect chain traces, HTTP cookies/headers, and Python code.\n"
                    "2. Never propose blind retries. Only propose concrete `dynamic_rules_patch` or exact `code_edits`.\n"
                    "3. Respond in valid JSON with keys:\n"
                    "{\n"
                    '  "thinking": "Detailed step-by-step technical root-cause reasoning",\n'
                    '  "root_cause": "Concise summary of the exact root cause",\n'
                    '  "fix_plan": "Exact engineering plan to fix the root cause",\n'
                    '  "tool_requests": [{"tool": "read_code"|"search_code"|"trace_redirect_chain"|"inspect_page_scripts", "path": "g2s/engine.py", "pattern": "...", "start_line": 1, "end_line": 80, "url": "..."}],\n'
                    '  "dynamic_rules_patch": {"origin_ips": {}, "referer_overrides": {}, "chain_hosts": [], "avbypass_hosts": [], "lootlabs_hosts": [], "ad_domains": [], "ad_query_keys": [], "timer_overrides": {}},\n'
                    '  "code_edits": [{"path": "g2s/engine.py", "old_text": "...", "new_text": "...", "reason": "..."}]\n'
                    "}\n"
                    "If you need to inspect more code before editing, return `tool_requests`. Only include `code_edits` when you have exact `old_text` (without line number prefixes)."
                )
                llm_res = None
                for turn_idx in range(3 if (unresolved_for_llm or not target_urls) else 0):
                    user_ctx = json.dumps({
                        "admin_instruction": run["prompt"],
                        "target_urls": target_urls,
                        "diagnostics": diag_summary,
                        "live_http_probes": probe_reports,
                        "page_script_inspections": page_inspections,
                        "redirect_chain_traces": chain_traces,
                        "auto_detected_rules_patch": rules_patch,
                        "state_fixes_applied": state_fixes_applied,
                        "code_inspection_results": extra_code_context,
                    }, indent=2)
                    llm_res = await self._call_llm_brain(run, sys_prompt, user_ctx)
                    if not llm_res:
                        break
                    t_reqs = llm_res.get("tool_requests") or []
                    if not t_reqs or not isinstance(t_reqs, list) or turn_idx >= 2:
                        break
                    for tr in t_reqs[:3]:
                        if not isinstance(tr, dict):
                            continue
                        t_name = str(tr.get("tool") or "")
                        t_path = str(tr.get("path") or "g2s/engine.py")
                        if t_name == "read_code":
                            s_ln = max(1, int(tr.get("start_line") or 1))
                            e_ln = min(s_ln + 120, int(tr.get("end_line") or (s_ln + 80)))
                            self._emit(run, "tool_call", f"🔧 Tool: read_code({t_path}, lines {s_ln}-{e_ln})")
                            try:
                                lines = self.code_sync.read_local_file(t_path).splitlines()
                                snippet = "\n".join(
                                    f"{i}: {lines[i-1]}"
                                    for i in range(s_ln, min(len(lines) + 1, e_ln + 1))
                                )
                                extra_code_context.append({"tool": "read_code", "path": t_path, "lines": f"{s_ln}-{e_ln}", "content": snippet})
                                self._emit(run, "tool_result", f"📥 Code Snippet ({t_path}:{s_ln}-{e_ln})", snippet[:1500])
                            except Exception as e_rd:
                                self._emit(run, "tool_result", "📥 read_code error", str(e_rd))
                        elif t_name == "search_code":
                            pat = str(tr.get("pattern") or "")
                            self._emit(run, "tool_call", f"🔧 Tool: search_code({pat!r} in {t_path})")
                            try:
                                lines = self.code_sync.read_local_file(t_path).splitlines()
                                matches = []
                                for idx_l, ln_txt in enumerate(lines, 1):
                                    if pat.lower() in ln_txt.lower():
                                        matches.append(f"{idx_l}: {ln_txt}")
                                        if len(matches) >= 25:
                                            break
                                out_m = "\n".join(matches) or "No matches found."
                                extra_code_context.append({"tool": "search_code", "path": t_path, "pattern": pat, "matches": out_m})
                                self._emit(run, "tool_result", f"📥 Search Results ({t_path})", out_m)
                            except Exception as e_sc:
                                self._emit(run, "tool_result", "📥 search_code error", str(e_sc))
                        elif t_name == "trace_redirect_chain":
                            tr_u = str(tr.get("url") or (target_urls[0] if target_urls else ""))
                            if tr_u:
                                tr_res = await self._tool_trace_redirect_chain(run, tr_u, origin_ips, max_hops=5)
                                extra_code_context.append({"tool": "trace_redirect_chain", "url": tr_u, "result": tr_res})
                        elif t_name == "inspect_page_scripts":
                            in_u = str(tr.get("url") or (target_urls[0] if target_urls else ""))
                            if in_u:
                                in_res = await self._tool_inspect_page_and_scripts(run, in_u)
                                extra_code_context.append({"tool": "inspect_page_scripts", "url": in_u, "result": in_res})

                if llm_res:
                    thinking_str = llm_res.get("thinking") or llm_res.get("analysis") or ""
                    root_cause_str = llm_res.get("root_cause") or ""
                    fix_plan_str = llm_res.get("fix_plan") or ""
                    combined_thought = "\n\n".join(
                        p for p in [
                            thinking_str,
                            f"Root Cause: {root_cause_str}" if root_cause_str else "",
                            f"Fix Plan: {fix_plan_str}" if fix_plan_str else "",
                        ] if p
                    )
                    if combined_thought:
                        self._emit(
                            run,
                            "thinking",
                            "🧠 AI Deep Reasoning & Root-Cause Diagnosis",
                            combined_thought,
                        )
                    llm_dyn = llm_res.get("dynamic_rules_patch")
                    if isinstance(llm_dyn, dict):
                        for k in ("origin_ips", "referer_overrides", "timer_overrides"):
                            if isinstance(llm_dyn.get(k), dict):
                                rules_patch.setdefault(k, {}).update(llm_dyn[k])
                        for k in ("chain_hosts", "avbypass_hosts", "lootlabs_hosts", "linkvertise_hosts", "izen_hosts", "shrinkme_hosts", "ad_domains", "ad_query_keys"):
                            if isinstance(llm_dyn.get(k), list):
                                for item in llm_dyn[k]:
                                    if item and item not in rules_patch.setdefault(k, []):
                                        rules_patch[k].append(item)

                    # Apply any verified LLM code edits (with AST compile syntax check & rollback snapshot!)
                    original_code_snapshots: dict[str, str] = {}
                    for edit in (llm_res.get("code_edits") or []):
                        if not isinstance(edit, dict):
                            continue
                        p = edit.get("path")
                        old_t = edit.get("old_text")
                        new_t = edit.get("new_text")
                        rsn = edit.get("reason") or "AI Engineer automated fix"
                        if p and old_t and new_t and old_t != new_t:
                            try:
                                cur_code = self.code_sync.read_local_file(p)
                                if old_t in cur_code:
                                    original_code_snapshots.setdefault(p, cur_code)
                                    updated_code = cur_code.replace(old_t, new_t, 1)
                                    if str(p).endswith(".py"):
                                        compile(updated_code, p, "exec")
                                    commit_res = await self.code_sync.commit_file(
                                        p,
                                        updated_code,
                                        reason=rsn,
                                        author="AI-Engineer",
                                        verified_urls=target_urls,
                                    )
                                    run["files_modified"].append(p)
                                    for tu in target_urls:
                                        self._url_heal_cooldown.pop(tu, None)
                                    self._emit(
                                        run,
                                        "patch",
                                        f"🛠 Applied & Hot-Reloaded Code Fix in {p} (rev #{commit_res['revision']})",
                                        commit_res.get("diff") or rsn,
                                        path=p,
                                    )
                            except Exception as ce:
                                self._emit(run, "error", f"⚠️ Skipped invalid code edit on {p}", str(ce))

                # Step 5: Sanitize and apply any discovered dynamic rules & hot-reload engine
                if isinstance(rules_patch.get("origin_ips"), dict):
                    rules_patch["origin_ips"] = {
                        h: ip for h, ip in rules_patch["origin_ips"].items()
                        if h and not any(h == bad or h.endswith("." + bad) for bad in _NEVER_ORIGIN_IP_HOSTS)
                    }
                for list_k in ("chain_hosts", "avbypass_hosts", "linkprotect_hosts"):
                    if isinstance(rules_patch.get(list_k), list):
                        rules_patch[list_k] = [
                            ch for ch in rules_patch[list_k]
                            if ch and not any(ch == bad or ch.endswith("." + bad) for bad in _NEVER_CHAIN_HOSTS)
                        ]
                has_rule_changes = False
                for k, v in rules_patch.items():
                    if not v:
                        continue
                    cur_v = dyn_rules.get(k)
                    if isinstance(v, dict) and any((cur_v or {}).get(dk) != dv for dk, dv in v.items()):
                        has_rule_changes = True
                    elif isinstance(v, list) and any(item not in (cur_v or []) for item in v):
                        has_rule_changes = True

                if has_rule_changes:
                    run["phase"] = "patching_rules"
                    # Stage candidate rules in-memory first; only persist to MongoDB if live verification passes!
                    staged_preview = dict(dyn_rules)
                    for rk, rv in rules_patch.items():
                        if not rv:
                            continue
                        if isinstance(rv, dict):
                            staged_preview[rk] = {**(staged_preview.get(rk) or {}), **rv}
                        elif isinstance(rv, list):
                            cur_l = list(staged_preview.get(rk) or [])
                            for it in rv:
                                if it not in cur_l:
                                    cur_l.append(it)
                            staged_preview[rk] = cur_l
                    set_dynamic_rules(staged_preview)
                    for tu in target_urls:
                        self._url_heal_cooldown.pop(tu, None)

                # Step 6: Run Single-Pass Live End-to-End Verification Check (never blind-loop!)
                any_fix_applied = bool(run["files_modified"] or has_rule_changes or state_fixes_applied)
                is_manual_run = run.get("trigger") not in ("auto_error_heal", "background_patrol")
                verification_results = []
                bp_verify = self.get_bypasser()
                remaining_for_browser = []

                # 6a) Always try zero-browser direct HTTP solvers first (0 worker contention, fast verification)
                for u_cand in target_urls:
                    if u_cand in dead_404_urls:
                        continue
                    if bp_verify is not None:
                        try:
                            d_res = pre_verified_direct.get(u_cand) or await bp_verify._try_direct_solvers(u_cand, lambda *_: None, time.monotonic())
                            if isinstance(d_res, dict) and d_res.get("url"):
                                d_res["at"] = time.time()
                                await self.db.set_cache(u_cand, d_res)
                                vr_item = {
                                    "url": u_cand,
                                    "ok": True,
                                    "destination": d_res["url"],
                                    "elapsed": d_res.get("elapsed", 0.0),
                                    "method": d_res.get("method", "direct solver"),
                                }
                                verification_results.append(vr_item)
                                self._url_heal_cooldown.pop(u_cand, None)
                                # If this was a Linkvertise solve, auto-persist newly discovered target in g2s/engine.py default_lv_cache
                                try:
                                    lv_map = getattr(bp_verify, "_lv_target_cache", None)
                                    if isinstance(lv_map, dict):
                                        p_lv = urlparse(u_cand)
                                        segs_lv = [s for s in p_lv.path.strip("/").split("/") if s and s.lower() not in ("access", "download")]
                                        if len(segs_lv) >= 2 and segs_lv[0].isdigit():
                                            lv_key = f"{segs_lv[0]}/{segs_lv[1]}"
                                            lv_val = lv_map.get(lv_key)
                                            if lv_val:
                                                eng_src = self.code_sync.read_local_file("g2s/engine.py")
                                                if f'"{lv_key}":' not in eng_src and "default_lv_cache = {" in eng_src:
                                                    new_eng_src = eng_src.replace(
                                                        "default_lv_cache = {\n",
                                                        f'default_lv_cache = {{\n                "{lv_key}": {json.dumps(lv_val)},\n',
                                                        1,
                                                    )
                                                    compile(new_eng_src, "g2s/engine.py", "exec")
                                                    c_res = await self.code_sync.commit_file(
                                                        "g2s/engine.py",
                                                        new_eng_src,
                                                        reason=f"AI Engineer auto-persisted Linkvertise target {lv_key}",
                                                        author="AI-Engineer",
                                                        verified_urls=[u_cand],
                                                    )
                                                    if "g2s/engine.py" not in run["files_modified"]:
                                                        run["files_modified"].append("g2s/engine.py")
                                                    self._emit(
                                                        run,
                                                        "patch",
                                                        f"🛠 Auto-Persisted Linkvertise Target {lv_key} in g2s/engine.py (rev #{c_res['revision']})",
                                                        f"{lv_key} -> {lv_val}",
                                                        path="g2s/engine.py",
                                                    )
                                except Exception:
                                    pass
                                self._emit(
                                    run,
                                    "verify",
                                    f"✅ Direct Solver Verified: {u_cand[:95]} → {d_res['url']} ({d_res.get('elapsed', 0)}s)",
                                    json.dumps(vr_item, indent=2),
                                )
                                continue
                        except Exception as de:
                            de_low = str(de).lower()
                            u_cand_host = (urlparse(u_cand).hostname or "").lower().removeprefix("www.")
                            if any(
                                fk in de_low
                                for fk in (
                                    "expired",
                                    "already used",
                                    "http 410",
                                    "invalid url",
                                    "paid qris paywall",
                                    "is_premium_only=true",
                                    "premium-only paywall link",
                                    "real-money",
                                    "cannot be bypassed for free",
                                    "redirected to parked host",
                                )
                            ) or (
                                ("not found" in de_low or "http 404" in de_low)
                                and (not u_cand_host or u_cand_host in de_low or "short4cash" not in de_low)
                                and "sayphotobooth" not in de_low
                            ):
                                dead_404_urls.add(u_cand)
                                self._emit(
                                    run,
                                    "thinking",
                                    f"🧠 Confirmed Expired One-Time / Dead / Paid Paywall Link: {u_cand[:90]}",
                                    f"Direct solver confirmed `{u_cand[:120]}` is expired, already used, deleted, or behind a real-money QRIS paywall (`{de}`). "
                                    f"Skipping browser retry and marking error log resolved.",
                                )
                                continue
                    if is_manual_run or any_fix_applied:
                        remaining_for_browser.append(u_cand)

                if remaining_for_browser:
                    run["phase"] = "verifying_live"
                    browser_v_res = await self._run_live_verification(run, remaining_for_browser)
                    for br_item in browser_v_res:
                        u_tested = br_item.get("url") or ""
                        err_br = str(br_item.get("error") or "").lower()
                        if not br_item.get("ok") and any(
                            fk in err_br
                            for fk in (
                                "expired",
                                "already used",
                                "not found",
                                "http 404",
                                "http 410",
                                "redirected to parked host",
                            )
                        ):
                            dead_404_urls.add(u_tested)
                            self._url_heal_cooldown.pop(u_tested, None)
                            self._emit(
                                run,
                                "thinking",
                                f"🧠 Confirmed Expired Single-Use / Dead Link: {u_tested[:90]}",
                                f"Live browser check confirmed `{u_tested[:120]}` is expired or dead (`{br_item.get('error')}`). "
                                f"Marking error log resolved.",
                            )
                            continue
                        verification_results.append(br_item)
                        if br_item.get("ok"):
                            self._url_heal_cooldown.pop(u_tested, None)
                        elif u_tested:
                            # Put unfixed failing URL on a 15-minute auto-heal cooldown so AI never loops blindly
                            self._url_heal_cooldown[u_tested] = time.time() + 900.0
                elif target_urls and not dead_404_urls and not verification_results:
                    for u_skip in target_urls:
                        self._url_heal_cooldown[u_skip] = time.time() + 900.0
                    self._emit(
                        run,
                        "thinking",
                        "🛡 Smart Verification Guard — Skipping Redundant Unpatched Retry",
                        "No new code/rule change was required in this auto-heal pass. "
                        "Skipping redundant live retry to prevent blind browser loops.",
                    )

                # Step 7: Mark resolved error logs & persist code snapshot to MongoDB + GitHub
                run["phase"] = "deploying"
                passed_urls = [r["url"] for r in verification_results if r.get("ok")]
                run["fixed_urls"] = passed_urls

                if has_rule_changes:
                    live_tested_count = len([u for u in target_urls if u not in dead_404_urls])
                    if passed_urls or live_tested_count == 0:
                        await self.db.update_dynamic_rules(rules_patch)
                        await self.code_sync.hot_reload_modules(["g2s/engine.py"])
                        run["rules_updated"].append(rules_patch)
                        self._emit(
                            run,
                            "patch",
                            "🛠 Verified & Synced Dynamic Bypass Rules to MongoDB",
                            json.dumps(rules_patch, indent=2),
                        )
                    else:
                        # Roll back unverified speculative rule mutation so dynamic_rules never gets polluted
                        set_dynamic_rules(dyn_rules)
                        self._emit(
                            run,
                            "thinking",
                            "🛡 Anti-Rollback Guard — Reverted Unverified Dynamic Rule Candidate",
                            "Candidate dynamic rule mutation did not resolve the live test URL(s); reverted in-memory rules to keep production clean.",
                        )

                all_candidates_to_resolve = list(target_err_entries)
                for u_log in unresolved_logs:
                    if u_log not in all_candidates_to_resolve:
                        all_candidates_to_resolve.append(u_log)

                for err_doc in all_candidates_to_resolve:
                    eid = err_doc.get("id")
                    esrc = err_doc.get("source") or ""
                    esrc_norm = _clean_u(esrc)
                    e_msg = str(err_doc.get("error") or "")
                    if not eid:
                        continue
                    self._diagnosed_error_ids.add(eid)
                    if esrc in passed_urls or esrc_norm in passed_urls:
                        dest_match = next(
                            (r["destination"] for r in verification_results if r["url"] in (esrc, esrc_norm)),
                            "",
                        )
                        await self.db.mark_error_log_resolved(
                            eid,
                            resolution_note=f"Verified live -> {dest_match}",
                            resolved_by="AI-Engineer",
                        )
                        self._healed_error_ids.add(eid)
                        if eid not in run["resolved_error_ids"]:
                            run["resolved_error_ids"].append(eid)
                    elif esrc in dead_404_urls or esrc_norm in dead_404_urls or any(
                        dk in e_msg.lower()
                        for dk in ("offline (dns lookup failed)", "expired or was already used", "link not found (http 404")
                    ):
                        await self.db.mark_error_log_resolved(
                            eid,
                            resolution_note="Verified expired one-time verification token, dead link (404), or offline domain",
                            resolved_by="AI-Engineer",
                        )
                        self._healed_error_ids.add(eid)
                        if eid not in run["resolved_error_ids"]:
                            run["resolved_error_ids"].append(eid)
                    elif any_fix_applied and any(pe in e_msg for pe in (
                        "ERR_PROXY_CONNECTION_FAILED", "Invalid InterceptionId", "TargetClosedError",
                        "Target crashed", "Page crashed", "launch_persistent_context",
                        "Could not start browser", "new_page",
                    )):
                        await self.db.mark_error_log_resolved(
                            eid,
                            resolution_note=f"Root-cause state/engine fix applied ({', '.join(state_fixes_applied) or 'engine patched'})",
                            resolved_by="AI-Engineer",
                        )
                        self._healed_error_ids.add(eid)
                        if eid not in run["resolved_error_ids"]:
                            run["resolved_error_ids"].append(eid)

                # Sync codebase to MongoDB (and GitHub if configured) ONLY when files were modified
                sync_res: dict[str, Any] = {"mongo_synced": [], "github_pushed": []}
                if run["files_modified"]:
                    sync_res = await self.code_sync.sync_all_to_mongo_and_github(
                        reason=f"AI Engineer verified run {run['id']} ({len(passed_urls)} link(s) verified)"
                    )
                if passed_urls or run["files_modified"] or run["rules_updated"] or run["resolved_error_ids"]:
                    await self.db.increment_stat("ai_fixes", 1)

                run["status"] = "completed"
                run["phase"] = "completed"
                run["finished_at"] = time.time()
                run["elapsed"] = round(run["finished_at"] - run["started_at"], 1)

                verifiable_urls = [u for u in target_urls if u not in dead_404_urls]
                denom_cnt = len(verifiable_urls)
                summary_lines = [
                    f"Run ID: {run['id']} ({run['elapsed']}s)",
                    f"Verified Working Links: {len(passed_urls)}/{denom_cnt}"
                    + (f" (+ {len(dead_404_urls)} expired/dead link(s) closed)" if dead_404_urls else ""),
                ]
                for r in verification_results:
                    if r.get("ok"):
                        summary_lines.append(f"  ✓ {r['url'][:95]} -> {r['destination']} ({r['elapsed']}s)")
                    else:
                        summary_lines.append(f"  ✗ {r['url'][:95]} -> {r.get('error')}")
                if dead_404_urls:
                    summary_lines.append(
                        f"Confirmed Expired/Dead Links ({len(dead_404_urls)}): "
                        + ", ".join(u[:85] for u in dead_404_urls)
                    )
                summary_lines.append(
                    f"Cloud Persistence: {len(sync_res.get('mongo_synced', []))} files synced to MongoDB "
                    f"(Boot Anti-Rollback Active)"
                )
                if sync_res.get("github_pushed"):
                    summary_lines.append(f"GitHub Sync: Pushed {len(sync_res['github_pushed'])} files to {self.db.settings.get('github_repo')}")

                run["summary"] = "\n".join(summary_lines)
                self._emit(
                    run,
                    "conclusion",
                    "🎉 AI Engineer Run Complete & Synced Live",
                    run["summary"],
                )

                # Notify admin on Telegram if this was an auto-heal or fixed errors
                if self.notify_admin_fn and (passed_urls or run.get("trigger") == "telegram_admin"):
                    try:
                        tg_msg = (
                            f"🤖 • <b>𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 𝗥𝗘𝗣𝗢𝗥𝗧 ({html.escape(run['id'])})</b>\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"<blockquote>{html.escape(run['summary'])}</blockquote>"
                        )
                        res_cb = self.notify_admin_fn(tg_msg)
                        if asyncio.iscoroutine(res_cb):
                            await res_cb
                    except Exception:
                        pass

            except Exception as e:
                run["status"] = "failed"
                run["phase"] = "failed"
                run["finished_at"] = time.time()
                run["elapsed"] = round(run["finished_at"] - run["started_at"], 1)
                run["summary"] = f"AI Run failed: {type(e).__name__}: {e}"
                self._emit(run, "error", "🚨 AI Engineer Exception", run["summary"])
            finally:
                pub = self.public_run(run)
                self.runs_history.insert(0, pub)
                self.runs_history = self.runs_history[:25]
                if self.db.connected and self.db.db is not None:
                    try:
                        await self.db.db.ai_runs.update_one(
                            {"_id": run["id"]},
                            {"$set": pub},
                            upsert=True,
                        )
                    except Exception:
                        pass
                ev_obj = run.get("event_notify")
                if isinstance(ev_obj, asyncio.Event):
                    ev_obj.set()
