"""
TheDrunkBots G2S — Password-Protected Web Admin Panel, Cloud API & Telegram Bot Runner.

Features:
  - Unified MongoDB Atlas + config.json real-time sync
  - Telegram Bot runner with live progress bar, Force-Subscribe, and in-bot Admin Panel
  - Password-protected Web Admin Panel (live preview disabled; full CRUD on Tunnel/Proxy,
    Cloud Cache, Force-Sub Channels, Error Logs, Bot Users, Broadcast, and Credentials)
  - Automatic Owner notification on Telegram when tunnel expires or a link errors
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
import webbrowser

import aiohttp
from aiohttp import web

from g2s.ai_engineer import AIEngineer
from g2s.bot import TelegramBot
from g2s.code_sync import CodeSyncManager
from g2s.db import Database, ProtectedLinkError, norm_url
from g2s.engine import Bypasser, BypassError, Config, parse_proxy, set_dynamic_rules
from g2s.ws_tunnel import WsTunnelManager

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
CFG_PATH = os.environ.get("G2S_CONFIG", os.path.join(HERE, "config.json"))
CACHE_PATH = os.path.join(HERE, "results.json")

db = Database(CFG_PATH, CACHE_PATH)
ws_tunnels = WsTunnelManager(db)
cfg = Config.load(CFG_PATH)


def _apply_db_settings_to_cfg():
    s = db.settings
    cfg.solver_url = (s.get("solver_url") or "https://cf.vltcx.eu.cc").rstrip("/")
    cfg.solver_api_key = s.get("solver_api_key")
    # Default browser mode is Direct (None); tunnel proxy is applied dynamically per-shortener
    # when a shortener's tunnel toggle is enabled in the Admin Panel.
    cfg.proxy = None
    cfg.accel_factor = float(s.get("accel_factor", 0.1))
    cfg.timeout = int(s.get("timeout", 300))
    cfg.stuck_seconds = int(s.get("stuck_seconds", 100))
    if s.get("no_accel_hosts"):
        cfg.no_accel_hosts = list(s["no_accel_hosts"])
    set_dynamic_rules(s.get("dynamic_rules") or {})


_apply_db_settings_to_cfg()

if "--show" in sys.argv:
    cfg.show_browser = True
    cfg.headless = False
if "--debug" in sys.argv:
    cfg.debug = True

HOST = os.environ.get("HOST") or os.environ.get("G2S_HOST") or "0.0.0.0"
PORT = int(os.environ.get("PORT") or db.settings.get("port") or 8080)
NO_OPEN = (
    os.environ.get("G2S_NO_OPEN", "").strip().lower() in ("1", "true", "yes")
    or ("--no-open" in sys.argv)
    or bool(os.environ.get("RAILWAY_ENVIRONMENT"))
    or (os.name != "nt" and not cfg.show_browser)
)

bypasser = Bypasser(cfg)
jobs: dict[str, dict] = {}
SESSION_SECRET = hashlib.sha256(f"g2s-secret-{os.getpid()}-{CFG_PATH}".encode()).hexdigest()


def make_auth_token(password: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), (password or "").encode(), hashlib.sha256).hexdigest()


def is_req_authenticated(req: web.Request) -> bool:
    raw_pw = str(db.settings.get("admin_password") or "admin123")
    expected = make_auth_token(raw_pw)
    auth_hdr = (req.headers.get("Authorization") or "").strip()
    if auth_hdr.startswith("Bearer "):
        tok = auth_hdr[7:].strip()
        if hmac.compare_digest(tok, expected) or hmac.compare_digest(tok, raw_pw):
            return True
    secret_hdr = (req.headers.get("X-Tunnel-Secret") or "").strip()
    if secret_hdr and (hmac.compare_digest(secret_hdr, raw_pw) or hmac.compare_digest(secret_hdr, expected)):
        return True
    cookie_tok = (req.cookies.get("g2s_admin_token") or "").strip()
    if cookie_tok and hmac.compare_digest(cookie_tok, expected):
        return True
    key_q = (
        req.query.get("key")
        or req.query.get("password")
        or req.query.get("secret")
        or req.query.get("token")
        or ""
    ).strip()
    if key_q and (hmac.compare_digest(key_q, raw_pw) or hmac.compare_digest(key_q, expected)):
        return True
    return False


async def test_proxy_status(px_override: str | None = "__current__") -> dict:
    px = (db.settings.get("proxy") or cfg.proxy) if px_override == "__current__" else px_override
    try:
        kw = {}
        if px:
            d = parse_proxy(px)
            kw["proxy"] = d["server"]
            if d.get("username"):
                raw_auth = f"{d['username']}:{d.get('password', '')}".encode("utf-8")
                kw["proxy_headers"] = {
                    "Proxy-Authorization": "Basic " + base64.b64encode(raw_auth).decode("ascii")
                }
        async with aiohttp.ClientSession() as s:
            async with s.get("https://ipinfo.io/json", timeout=aiohttp.ClientTimeout(total=18), **kw) as r:
                info = await r.json(content_type=None)
        dc = any(
            w in (info.get("org") or "").lower()
            for w in (
                "google", "amazon", "microsoft", "digitalocean", "ovh", "hetzner",
                "oracle", "linode", "railway", "cloudflare", "akamai", "choopa", "vultr",
            )
        )
        if px and db.settings.get("proxy_expired"):
            bot._alerted_expired_proxy = None
            await db.update_settings({"proxy_expired": False, "proxy_expired_notified_for": ""}, notify=False)
        return {
            "ok": True,
            "via_proxy": bool(px),
            "ip": info.get("ip"),
            "city": info.get("city"),
            "region": info.get("region"),
            "country": info.get("country"),
            "org": info.get("org"),
            "datacenter": dc,
        }
    except Exception as e:
        return {"ok": False, "via_proxy": bool(px), "error": f"{type(e).__name__}: {e}"}


async def set_system_proxy(new_proxy: str | None):
    clean = (new_proxy or "").strip() or None
    bot._alerted_expired_proxy = None
    await db.update_settings(
        {"proxy": clean, "proxy_expired": False, "proxy_expired_notified_for": ""},
        notify=False,
    )
    cfg.proxy = clean
    await bypasser.set_proxy(clean)


_inflight: dict[str, dict] = {}


async def resolve_link_core(
    url: str,
    force: bool = False,
    origin: str = "web",
    user_id: int | None = None,
    username: str | None = None,
    extra_log_cb=None,
) -> dict:
    key = norm_url(url)
    if origin != "ai-engineer-check":
        prot_src = db.check_protected_source_url(key)
        if prot_src:
            reason = prot_src.get("reason") or "Official Protected Bot Link"
            if extra_log_cb:
                extra_log_cb(f"🛡 Blocked: {reason} — This link cannot be bypassed as it is protected by us.")
            raise ProtectedLinkError(
                "This link cannot be bypassed as it is protected by us.",
                reason=reason,
                bot_name=prot_src.get("bot_name") or "",
            )

    hit = await db.get_cache(key, force=force)
    if hit:
        if origin != "ai-engineer-check" and hit.get("url"):
            prot_dest = db.check_protected_destination_url(hit["url"], source_url=key)
            if prot_dest:
                reason = prot_dest.get("reason") or "Official Protected Bot Link"
                if extra_log_cb:
                    extra_log_cb(f"🛡 Blocked: {reason} — This link cannot be bypassed as it is protected by us.")
                raise ProtectedLinkError(
                    "This link cannot be bypassed as it is protected by us.",
                    reason=reason,
                    bot_name=prot_dest.get("bot_name") or "",
                )
        if extra_log_cb:
            extra_log_cb("Served from cloud cache")
        return hit

    # Deduplicate simultaneous requests for the exact same URL (ignore stale >165s entries)
    if not force and key in _inflight:
        existing = _inflight[key]
        if not existing["fut"].done() and (time.monotonic() - existing.get("t0", time.monotonic())) < 165.0:
            if extra_log_cb:
                for prev_msg in existing["raw_logs"]:
                    try:
                        extra_log_cb(prev_msg)
                    except Exception:
                        pass
                existing["cbs"].append(extra_log_cb)
            return await asyncio.shield(existing["fut"])
        _inflight.pop(key, None)

    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    cbs = [extra_log_cb] if extra_log_cb else []
    raw_logs: list[str] = []
    if not force:
        _inflight[key] = {"fut": fut, "cbs": cbs, "raw_logs": raw_logs, "t0": time.monotonic()}

    log_lines: list[str] = []
    t0 = time.time()

    def log_fn(msg: str):
        nonlocal t0
        if not raw_logs:
            t0 = time.time()
        raw_logs.append(msg)
        line = f"[{time.time() - t0:5.1f}s] {msg}"
        log_lines.append(line)
        print(line, flush=True)
        for cb in list(cbs):
            if cb:
                try:
                    cb(msg)
                except Exception:
                    pass

    try:
        used_tunnel_initially = False

        async def _prepare_job():
            nonlocal t0, used_tunnel_initially
            t0 = time.time()
            use_tunnel = db.should_use_tunnel_for_url(key)
            used_tunnel_initially = use_tunnel
            candidates: list[dict] = []
            fallback_candidates: list[dict] = []
            if use_tunnel:
                candidates = await db.get_tunnel_candidates_for_url(key)
                if not candidates:
                    log_fn("⚠ Tunnel is enabled for this shortener, but no enabled tunnel device is online — using direct connection")
            else:
                log_fn("⚡ Shortener tunnel disabled — solving via direct connection")
                fallback_candidates = await db.get_tunnel_candidates_for_url(key, ignore_shortener_toggle=True)
            # Rotate proxy order on EVERY link for domains that need session isolation
            _kl = (key or "").lower()
            _rotate_hosts = (
                "arolinks.", "vplink.", "v2links.", "urlspay.", "droplink.",
                "gplinks.", "shrinkme.", "srnky.", "shrinkearn.", "shrinke.me",
                "get2short.", "babylinks.",
            )
            if any(h in _kl for h in _rotate_hosts):
                import random as _rnd
                if len(candidates) > 1:
                    _rnd.shuffle(candidates)
                    log_fn(f"🔄 Rotated {len(candidates)} tunnel proxies for this shortener job")
                if len(fallback_candidates) > 1:
                    _rnd.shuffle(fallback_candidates)
            return candidates, fallback_candidates

        async def _on_tunnel_used(device_id: str | None, success: bool):
            await db.record_tunnel_usage(device_id, success)
            if success and not used_tunnel_initially:
                try:
                    await db.set_shortener_tunnel(key, True)
                    log_fn("🛡 Auto-enabled tunnel routing for this shortener domain for future requests")
                except Exception:
                    pass

        res = await bypasser.resolve(
            key,
            log=log_fn,
            on_tunnel_used=_on_tunnel_used,
            prepare_fn=_prepare_job,
        )
        if origin != "ai-engineer-check" and res.get("url"):
            prot_dest = db.check_protected_destination_url(res["url"], source_url=key)
            if prot_dest:
                reason = prot_dest.get("reason") or "Official Protected Bot Link"
                log_fn(f"🛡 Blocked: {reason} — This link cannot be bypassed as it is protected by us.")
                raise ProtectedLinkError(
                    "This link cannot be bypassed as it is protected by us.",
                    reason=reason,
                    bot_name=prot_dest.get("bot_name") or "",
                )
        res["at"] = time.time()
        await db.set_cache(key, res)
        await db.increment_stat("total_bypasses", 1)
        out = {**res, "cached": False}
        if not fut.done():
            fut.set_result(out)
        return out
    except ProtectedLinkError as pe:
        if not fut.done():
            fut.set_exception(pe)
            try:
                fut.exception()
            except Exception:
                pass
        raise
    except Exception as e:
        err_str = str(e) if isinstance(e, BypassError) else f"{type(e).__name__}: {e}"
        log_fn(f"✖ {err_str}")
        if origin != "ai-engineer-check":
            entry = await db.add_error_log(
                source=key,
                error=err_str,
                log_lines=log_lines,
                origin=origin,
                user_id=user_id,
                username=username,
            )
            asyncio.create_task(bot.notify_error_log(entry))
        if not fut.done():
            fut.set_exception(e)
            try:
                fut.exception()
            except Exception:
                pass
        raise
    finally:
        if _inflight.get(key, {}).get("fut") is fut:
            _inflight.pop(key, None)


code_sync = CodeSyncManager(HERE, db, bypasser_Getter=lambda: bypasser)

bot = TelegramBot(
    db=db,
    resolve_fn=resolve_link_core,
    proxy_test_fn=test_proxy_status,
    set_proxy_fn=set_system_proxy,
)

ai_engineer = AIEngineer(
    db=db,
    code_sync=code_sync,
    resolve_fn=resolve_link_core,
    bypasser_getter=lambda: bypasser,
    notify_admin_fn=bot.notify_admins,
)
bot.ai_engineer = ai_engineer
bot.code_sync = code_sync


async def _on_proxy_expired(expired_px: str | None, err_msg: str):
    cfg.proxy = None
    await bot.notify_tunnel_expired(expired_px, err_msg)


bypasser.on_proxy_expired = _on_proxy_expired


async def _on_settings_changed(changed_keys: set, new_settings: dict):
    _apply_db_settings_to_cfg()
    if "proxy" in changed_keys and cfg.proxy != bypasser.cfg.proxy and not bypasser.busy:
        await bypasser.set_proxy(cfg.proxy)
    if "telegram_bot_token" in changed_keys:
        await bot.reload_if_needed()


db.on_settings_change(_on_settings_changed)


# ------------------------------------------------------------------ Job runner
async def run_job(job: dict):
    def on_log(msg: str):
        line = f"[{time.time() - job['t0']:5.1f}s] {msg}"
        job["log"].append(line)
        job["event"].set()

    job["status"] = "running"
    job["event"].set()
    try:
        res = await resolve_link_core(
            job["source"],
            force=job["force"],
            origin="admin-web",
            extra_log_cb=on_log,
        )
        job["result"] = res
    except ProtectedLinkError as e:
        job["protected"] = True
        job["error"] = f"🛡 Protected Official Link ({e.reason}): This link cannot be bypassed as it is protected by us."
    except BypassError as e:
        job["error"] = str(e)
    except Exception as e:
        job["error"] = f"{type(e).__name__}: {e}"
    job["status"] = "done"
    job["event"].set()


def new_job(url: str, force: bool = False) -> dict:
    jid = uuid.uuid4().hex[:10]
    job = {
        "id": jid,
        "source": norm_url(url),
        "force": force,
        "status": "queued",
        "log": [],
        "result": None,
        "error": None,
        "t0": time.time(),
        "event": asyncio.Event(),
    }
    jobs[jid] = job
    job["task"] = asyncio.ensure_future(run_job(job))
    return job


def public_job(job: dict) -> dict:
    out = {k: job[k] for k in ("id", "source", "status", "result", "error", "log")}
    if job.get("protected"):
        out["protected"] = True
    return out


def mask_proxy(p: str | None) -> str | None:
    import re as _re
    return _re.sub(r"(://[^:/@]+:)[^@]+@", r"\1•••@", p) if p else None


# ------------------------------------------------------------------ Middleware
@web.middleware
async def auth_middleware(req: web.Request, handler):
    path = req.path
    if path in ("/", "/api/health", "/api/auth/login", "/api/auth/logout", "/api/auth/me"):
        return await handler(req)
    if path.startswith("/api/"):
        if not is_req_authenticated(req):
            return web.json_response({"error": "Unauthorized — admin password required"}, status=401)
    return await handler(req)


# ---------------------------------------------------------------------- Routes
async def index(_: web.Request):
    with open(os.path.join(HERE, "web", "index.html"), encoding="utf-8") as f:
        return web.Response(text=f.read(), content_type="text/html")


async def auth_login(req: web.Request):
    data = await req.json()
    pw = str(data.get("password") or "").strip()
    expected_pw = str(db.settings.get("admin_password") or "admin123")
    if pw != expected_pw:
        return web.json_response({"ok": False, "error": "Invalid admin password"}, status=401)
    tok = make_auth_token(expected_pw)
    resp = web.json_response({
        "ok": True,
        "token": tok,
        "brand": db.settings.get("brand_name", "TheDrunkBots"),
    })
    resp.set_cookie("g2s_admin_token", tok, max_age=86400 * 30, httponly=True, samesite="Lax")
    return resp


async def auth_logout(_: web.Request):
    resp = web.json_response({"ok": True})
    resp.del_cookie("g2s_admin_token")
    return resp


async def auth_me(req: web.Request):
    return web.json_response({
        "authenticated": is_req_authenticated(req),
        "brand": db.settings.get("brand_name", "TheDrunkBots"),
    })


async def health(_: web.Request):
    try:
        h = await bypasser.solver.health()
        solver_st = "ok"
    except Exception as e:
        h = str(e)
        solver_st = "down"
    return web.json_response({
        "status": "ok" if solver_st == "ok" else "degraded",
        "solver": solver_st,
        "detail": h,
        "solver_url": cfg.solver_url,
        "proxy_set": bool(cfg.proxy),
        "proxy_expired": bool(db.settings.get("proxy_expired")),
        "mongo_connected": db.connected,
        "bot_running": bot.running,
        "bot_username": (bot.bot_info or {}).get("username"),
    })


async def dashboard(req: web.Request):
    # Record public server URL if accessed via non-localhost domain
    host_hdr = (req.headers.get("X-Forwarded-Host") or req.headers.get("Host") or "").strip()
    proto_hdr = (req.headers.get("X-Forwarded-Proto") or req.scheme or "http").strip()
    if host_hdr and not host_hdr.startswith(("127.0.0.1", "localhost", "0.0.0.0")):
        pub_u = f"{proto_hdr}://{host_hdr}"
        if db.settings.get("public_server_url") != pub_u:
            asyncio.create_task(db.update_settings({"public_server_url": pub_u}, notify=False))

    st = db.settings.get("stats") or {}
    devices = await db.list_tunnel_devices()
    shorteners = db.get_shortener_tunnel_list()
    online_devs = [d for d in devices if d.get("online")]
    active_dev = next((d for d in devices if d.get("is_active_selected")), None)
    enabled_shorteners = [s for s in shorteners if s.get("enabled")]

    return web.json_response({
        "brand": db.settings.get("brand_name", "TheDrunkBots"),
        "mongo_connected": db.connected,
        "mongo_error": db.last_error,
        "bot_running": bot.running,
        "bot_info": bot.bot_info,
        "proxy": (active_dev.get("proxy_url") if active_dev else cfg.proxy),
        "proxy_masked": mask_proxy(active_dev.get("proxy_url") if active_dev else cfg.proxy),
        "has_proxy": bool(active_dev or cfg.proxy),
        "proxy_expired": bool(db.settings.get("proxy_expired")) and not bool(online_devs),
        "tunnel_devices_total": len(devices),
        "tunnel_devices_online": len(online_devs),
        "active_tunnel_device": active_dev,
        "shorteners_total": len(shorteners),
        "shorteners_tunnel_enabled": len(enabled_shorteners),
        "solver_url": cfg.solver_url,
        "cache_enabled": bool(db.settings.get("cache_enabled", True)),
        "cache_hours": float(db.settings.get("cache_hours", 24)),
        "cache_count": len(db.local_cache),
        "users_count": len(db.local_users),
        "logs_count": len(db.local_logs),
        "fsub_enabled": bool(db.settings.get("force_sub_enabled", True)),
        "fsub_count": len(db.settings.get("force_sub_channels") or []),
        "protected_enabled": bool(db.settings.get("protected_links_enabled", True)),
        "protected_bots_count": len(db.settings.get("protected_bots") or []),
        "protected_links_synced": len(db.protected_known_urls),
        "premium_only_enabled": bool(db.settings.get("premium_only_enabled", True)),
        "free_trial_limit": int(db.settings.get("free_trial_limit", 3)),
        "premium_users_count": sum(
            1 for u in db.local_users.values()
            if u.get("is_premium") and float(u.get("premium_until") or 0) > time.time()
        ),
        "maintenance_mode": bool(db.settings.get("maintenance_mode", False)),
        "ai_auto_heal": bool(db.settings.get("ai_auto_heal", True)),
        "ai_patrol_enabled": bool(db.settings.get("ai_patrol_enabled", True)),
        "ai_busy": bool(ai_engineer.current_run and ai_engineer.current_run.get("status") == "running"),
        "stats": {
            "total_bypasses": int(st.get("total_bypasses", 0)),
            "cache_hits": int(st.get("cache_hits", 0)),
            "failed_bypasses": int(st.get("failed_bypasses", 0)),
            "ai_fixes": int(st.get("ai_fixes", 0)),
            "total_premium_sales": int(st.get("total_premium_sales", 0)),
            "total_revenue_inr": float(st.get("total_revenue_inr", 0.0)),
        },
    })


async def get_settings(_: web.Request):
    await db.refresh_settings_from_mongo()
    s = dict(db.settings)
    return web.json_response({
        **s,
        "proxy_masked": mask_proxy(s.get("proxy")),
        "has_proxy": bool(s.get("proxy")),
        "bot_running": bot.running,
        "bot_info": bot.bot_info,
        "mongo_connected": db.connected,
    })


async def post_settings(req: web.Request):
    data = await req.json()
    if "proxy" in data and data.get("proxy") != cfg.proxy:
        if bypasser.busy:
            return web.json_response({"error": "A bypass job is currently running — try again in a few seconds"}, status=409)
        new_px = (data.get("proxy") or "").strip() or None
        await set_system_proxy(new_px)
        data.pop("proxy", None)

    allowed = {
        "brand_name", "admin_password", "telegram_bot_token", "telegram_api_id",
        "telegram_api_hash", "owner_id", "admin_ids", "start_photo",
        "welcome_message", "updates_channel", "force_sub_enabled",
        "force_sub_channels", "protected_links_enabled", "protected_bots",
        "protected_mongo_clusters", "protected_rules", "protected_message",
        "premium_only_enabled", "free_trial_limit", "premium_plans",
        "paytm_mid", "upi_id", "upi_payee_name", "payment_api_url",
        "payment_log_channel_id", "owner_contact_url", "payment_max_minutes",
        "payment_verify_interval", "amount_tolerance",
        "maintenance_mode", "protect_content",
        "solver_url", "solver_api_key", "accel_factor", "timeout",
        "stuck_seconds", "cache_enabled", "cache_hours", "mongo_uri",
        "ai_auto_heal", "ai_patrol_enabled", "ai_patrol_interval_minutes",
        "ai_provider", "ai_api_key", "ai_model", "ai_base_url",
        "github_token", "github_repo", "github_branch", "dynamic_rules",
    }
    patch = {k: v for k, v in data.items() if k in allowed}
    if patch:
        await db.update_settings(patch, notify=True)
        if "force_sub_channels" in patch and bot.running:
            await bot.sync_all_fsub_channels()
    resp = await get_settings(req)
    if "admin_password" in patch:
        tok = make_auth_token(str(db.settings.get("admin_password") or "admin123"))
        resp.set_cookie("g2s_admin_token", tok, max_age=86400 * 30, httponly=True, samesite="Lax")
    return resp


async def proxy_test_route(_: web.Request):
    return web.json_response(await test_proxy_status())


async def create_job_route(req: web.Request):
    data = await req.json()
    urls = [u.strip() for u in str(data.get("url", "")).splitlines() if u.strip()]
    if not urls:
        return web.json_response({"error": "no url"}, status=400)
    return web.json_response({"jobs": [new_job(u, bool(data.get("force")))["id"] for u in urls]})


async def job_events_route(req: web.Request):
    job = jobs.get(req.match_info["jid"])
    if not job:
        raise web.HTTPNotFound()
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
    await resp.prepare(req)
    sent = 0
    try:
        while True:
            job["event"].clear()
            while sent < len(job["log"]):
                await resp.write(f"data: {json.dumps({'log': job['log'][sent]})}\n\n".encode())
                sent += 1
            if job["status"] == "done":
                await resp.write(f"data: {json.dumps({'done': public_job(job)})}\n\n".encode())
                break
            try:
                await asyncio.wait_for(job["event"].wait(), 15)
            except asyncio.TimeoutError:
                await resp.write(b": ping\n\n")
    except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
        pass
    return resp


async def resolve_api_route(req: web.Request):
    url = req.query.get("url")
    if not url:
        return web.json_response({"error": "pass ?url="}, status=400)
    job = new_job(url, req.query.get("force") in ("1", "true"))
    await job["task"]
    if job["error"]:
        is_prot = bool(job.get("protected"))
        return web.json_response(
            {"error": job["error"], "protected": is_prot, "log": job["log"]},
            status=403 if is_prot else 422,
        )
    return web.json_response(job["result"])


# --- Cloud Cache CRUD ---
async def list_cache_route(req: web.Request):
    q = req.query.get("q", "")
    items = await db.list_cache(search=q, limit=200)
    return web.json_response(items)


async def upsert_cache_route(req: web.Request):
    data = await req.json()
    src = (data.get("source") or "").strip()
    dest = (data.get("url") or "").strip()
    if not src or not dest:
        return web.json_response({"error": "Both source and destination url are required"}, status=400)
    entry = await db.set_cache(src, {
        "url": dest,
        "elapsed": float(data.get("elapsed") or 0.0),
        "method": data.get("method") or "admin-manual",
    })
    return web.json_response({"ok": True, "item": entry})


async def delete_cache_route(req: web.Request):
    src = req.query.get("source")
    if not src and req.can_read_body:
        try:
            body = await req.json()
            src = body.get("source")
        except Exception:
            pass
    if req.query.get("all") in ("1", "true") or not src:
        cnt = await db.clear_cache()
        return web.json_response({"ok": True, "cleared": cnt})
    ok = await db.delete_cache(src)
    return web.json_response({"ok": ok})


# --- Force-Sub CRUD ---
async def list_fsub_route(_: web.Request):
    return web.json_response({
        "enabled": bool(db.settings.get("force_sub_enabled", True)),
        "channels": db.settings.get("force_sub_channels") or [],
    })


async def save_fsub_route(req: web.Request):
    data = await req.json()
    if "enabled" in data:
        await db.update_settings({"force_sub_enabled": bool(data["enabled"])})
    if data.get("refresh_invites"):
        await bot.sync_all_fsub_channels(force_new_invite=True)
        return await list_fsub_route(req)
    if "chat_id" in data:
        cid = str(data.get("chat_id") or "").strip()
        if not cid:
            return web.json_response({"error": "chat_id required"}, status=400)
        title = (data.get("title") or "").strip()
        invite = (data.get("invite_link") or "").strip()
        resolved = await bot.resolve_and_prepare_fsub_channel(
            chat_id=cid,
            title=title,
            invite_link=invite,
            force_new_invite=bool(data.get("auto_invite", True) or not invite),
        )
        channels = list(db.settings.get("force_sub_channels") or [])
        updated = False
        for idx, c in enumerate(channels):
            if str(c.get("chat_id", "")).lower() == cid.lower():
                channels[idx] = resolved
                updated = True
                break
        if not updated:
            channels.append(resolved)
        await db.update_settings({"force_sub_channels": channels})
    return await list_fsub_route(req)


async def delete_fsub_route(req: web.Request):
    cid = (req.query.get("chat_id") or "").strip()
    channels = [
        c for c in (db.settings.get("force_sub_channels") or [])
        if str(c.get("chat_id", "")).lower() != cid.lower()
    ]
    await db.update_settings({"force_sub_channels": channels})
    return await list_fsub_route(req)


# --- Protected Bots & Links Shield CRUD ---
async def get_protected_route(_: web.Request):
    return web.json_response(db.get_protected_config())


async def post_protected_bot_route(req: web.Request):
    data = await req.json()
    if req.method == "PUT" or (data.get("action") == "toggle" and (data.get("id") or data.get("username"))):
        bid = str(data.get("id") or data.get("username") or "").strip()
        res = await db.toggle_protected_bot(bid, bool(data.get("enabled", True)))
        return web.json_response(res)
    res = await db.add_protected_bot(data)
    return web.json_response(res)


async def delete_protected_bot_route(req: web.Request):
    bid = (req.query.get("id") or req.query.get("username") or "").strip()
    if not bid and req.can_read_body:
        try:
            body = await req.json()
            bid = str(body.get("id") or body.get("username") or "").strip()
        except Exception:
            pass
    if not bid:
        return web.json_response({"error": "id or username required"}, status=400)
    res = await db.delete_protected_bot(bid)
    return web.json_response(res)


async def post_protected_cluster_route(req: web.Request):
    data = await req.json()
    res = await db.add_protected_cluster(data)
    return web.json_response(res)


async def delete_protected_cluster_route(req: web.Request):
    cid = (req.query.get("id") or "").strip()
    if not cid:
        return web.json_response({"error": "id required"}, status=400)
    res = await db.delete_protected_cluster(cid)
    return web.json_response(res)


async def post_protected_rules_route(req: web.Request):
    data = await req.json()
    res = await db.update_protected_rules(data)
    return web.json_response(res)


async def post_protected_sync_route(_: web.Request):
    sync_res = await db.sync_protected_masked_links()
    return web.json_response({**db.get_protected_config(), "sync_result": sync_res})


# --- Premium & Paytm Auto-Payment CRUD ---
async def get_premium_route(_: web.Request):
    return web.json_response(await db.get_premium_dashboard_config())


async def post_premium_settings_route(req: web.Request):
    data = await req.json()
    res = await db.update_payment_settings(data)
    return web.json_response(res)


async def post_premium_plan_route(req: web.Request):
    data = await req.json()
    res = await db.upsert_premium_plan(data)
    return web.json_response(res)


async def delete_premium_plan_route(req: web.Request):
    key = (req.query.get("key") or "").strip()
    if not key and req.can_read_body:
        try:
            body = await req.json()
            key = str(body.get("key") or "").strip()
        except Exception:
            pass
    if not key:
        return web.json_response({"error": "key required"}, status=400)
    res = await db.delete_premium_plan(key)
    return web.json_response(res)


async def post_premium_user_route(req: web.Request):
    from g2s.payment import send_payment_log_to_targets
    data = await req.json()
    try:
        uid = int(data.get("user_id") or 0)
    except (ValueError, TypeError):
        uid = 0
    if not uid:
        return web.json_response({"error": "Valid numeric user_id required"}, status=400)
    days = int(data.get("days") or data.get("time_value") or 30)
    plan_type = str(data.get("plan_type") or f"{days}d").strip()
    time_unit = str(data.get("time_unit") or "d").strip()
    matched = db.get_plan_by_key(plan_type)
    plan_label = (
        f"💎 {matched['name']}"
        if matched
        else (data.get("plan_label") or f"💎 {plan_type.replace('_', ' ').title()} ({days} Days)")
    )
    res = await db.add_premium_user(
        user_id=uid,
        time_value=days,
        plan_type=plan_type,
        plan_label=plan_label,
        source="web_admin",
        added_by=int(db.settings.get("owner_id") or 0),
        time_unit=time_unit,
    )
    if bot.running:
        expiry_str = res.get("expiry_str") or ""
        try:
            await bot.send_message(
                uid,
                f"<blockquote>🎉 <b>ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ᴀᴄᴛɪᴠᴀᴛᴇᴅ!</b></blockquote>\n\n"
                f"<blockquote>✅ Your account has been upgraded to <b>Premium</b> by Admin!\n"
                f"» <b>ᴘʟᴀɴ:</b> <b>{plan_label}</b>\n"
                f"» <b>ᴅᴜʀᴀᴛɪᴏɴ:</b> <b>{res.get('days_added')} Days</b>\n"
                f"» <b>ᴇxᴘɪʀᴇs ᴏɴ:</b> <code>{expiry_str}</code></blockquote>\n\n"
                f"<blockquote>ᴇɴᴊᴏʏ ᴜɴʟɪᴍɪᴛᴇᴅ ʟɪɴᴋ ʙʏᴘᴀssᴇs ᴡɪᴛʜ ᴢᴇʀᴏ ʟɪᴍɪᴛs! 🚀</blockquote>",
                reply_markup={"inline_keyboard": [[{"text": "👑 View My Plan", "callback_data": "usr:myplan"}]]},
            )
            log_text = (
                f"<blockquote>👑 <b>ᴘʀᴇᴍɪᴜᴍ ᴀᴅᴅᴇᴅ (ᴡᴇʙ ᴀᴅᴍɪɴ)</b></blockquote>\n\n"
                f"<blockquote>👤 ᴜsᴇʀ ɪᴅ: <code>{uid}</code></blockquote>\n"
                f"<blockquote>📦 ᴘʟᴀɴ: <b>{plan_label} ({res.get('days_added')} ᴅᴀʏs)</b></blockquote>\n"
                f"<blockquote>⏳ ᴇxᴘɪʀᴇs: <code>{expiry_str}</code></blockquote>"
            )
            asyncio.create_task(send_payment_log_to_targets(bot, db, log_text))
        except Exception:
            pass
    return web.json_response({**await db.get_premium_dashboard_config(), "activated": res})


async def delete_premium_user_route(req: web.Request):
    uid_str = (req.query.get("user_id") or "").strip()
    if not uid_str and req.can_read_body:
        try:
            body = await req.json()
            uid_str = str(body.get("user_id") or "").strip()
        except Exception:
            pass
    if not uid_str or not uid_str.lstrip("-").isdigit():
        return web.json_response({"error": "user_id required"}, status=400)
    uid = int(uid_str)
    await db.remove_premium_user(uid)
    if bot.running:
        try:
            await bot.send_message(
                uid,
                "<blockquote>⚠️ <b>ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ʀᴇᴠᴏᴋᴇᴅ</b></blockquote>\n"
                "<blockquote>Your Premium subscription has been ended by an administrator.</blockquote>",
            )
        except Exception:
            pass
    return web.json_response(await db.get_premium_dashboard_config())


async def post_reset_free_uses_route(req: web.Request):
    data = await req.json()
    uid = int(data.get("user_id") or 0)
    if not uid:
        return web.json_response({"error": "user_id required"}, status=400)
    u = db.local_users.get(uid) or {"user_id": uid}
    u["free_uses"] = 0
    u["free_exhausted_notified"] = False
    db.local_users[uid] = u
    db._save_local("users")
    if db.connected and db.db is not None:
        try:
            await db.db.users.update_one(
                {"user_id": uid},
                {"$set": {"free_uses": 0, "free_exhausted_notified": False}},
                upsert=True,
            )
        except Exception:
            pass
    return web.json_response({"ok": True, "user_id": uid, "free_uses": 0})


# --- Error Logs CRUD ---
async def list_logs_route(_: web.Request):
    return web.json_response(await db.list_error_logs(limit=100))


async def delete_logs_route(req: web.Request):
    lid = (req.query.get("id") or "").strip()
    if req.query.get("all") in ("1", "true") or not lid:
        cnt = await db.clear_error_logs()
        return web.json_response({"ok": True, "cleared": cnt})
    ok = await db.delete_error_log(lid)
    return web.json_response({"ok": ok})


# --- Users & Broadcast CRUD ---
async def list_users_route(req: web.Request):
    q = req.query.get("q", "")
    return web.json_response(await db.list_users(search=q, limit=250))


async def user_ban_route(req: web.Request):
    data = await req.json()
    uid = int(data.get("user_id") or 0)
    if not uid:
        return web.json_response({"error": "user_id required"}, status=400)
    await db.set_user_banned(uid, bool(data.get("banned")))
    return web.json_response({"ok": True})


async def delete_user_route(req: web.Request):
    uid = int(req.query.get("user_id") or 0)
    if not uid:
        return web.json_response({"error": "user_id required"}, status=400)
    ok = await db.delete_user(uid)
    return web.json_response({"ok": ok})


async def broadcast_route(req: web.Request):
    data = await req.json()
    text = (data.get("message") or "").strip()
    if not text:
        return web.json_response({"error": "message is empty"}, status=400)
    if not bot.running:
        return web.json_response({"error": "Telegram Bot is not running (set telegram_bot_token first)"}, status=400)
    uids = await db.get_all_user_ids(include_banned=False)
    sent_ok = 0
    failed = 0
    formatted = f"📢 • <b>𝗔𝗡𝗡𝗢𝗨𝗡𝗖𝗘𝗠𝗘𝗡𝗧</b>\n━━━━━━━━━━━━━━━━━━━━━━\n<blockquote>{text}</blockquote>"
    for uid in uids:
        r = await bot.send_message(uid, formatted)
        if r and r.get("ok"):
            sent_ok += 1
        else:
            failed += 1
        await asyncio.sleep(0.04)
    return web.json_response({"ok": True, "delivered": sent_ok, "failed": failed, "total": len(uids)})


# --- Multi-Device Tunnel Pool & Per-Shortener Routing CRUD ---
async def list_tunnels_route(_: web.Request):
    devices = await db.list_tunnel_devices()
    shorteners = db.get_shortener_tunnel_list()
    for d in devices:
        d["proxy_masked"] = mask_proxy(d.get("proxy_url"))
    online_count = sum(1 for d in devices if d.get("online"))
    enabled_shorteners = sum(1 for s in shorteners if s.get("enabled"))
    return web.json_response({
        "devices": devices,
        "shorteners": shorteners,
        "active_device_id": db.settings.get("active_tunnel_device_id"),
        "online_count": online_count,
        "total_devices": len(devices),
        "enabled_shorteners_count": enabled_shorteners,
        "total_shorteners": len(shorteners),
    })


async def register_tunnel_route(req: web.Request):
    data = await req.json()
    peer_ip = (
        req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or req.remote
        or ""
    )
    if not data.get("public_ip") and peer_ip:
        data["public_ip"] = peer_ip
    item = await db.register_tunnel_device(data)
    return web.json_response({"ok": True, "device": item})


async def heartbeat_tunnel_route(req: web.Request):
    data = await req.json()
    did = str(data.get("device_id") or "").strip()
    if not did:
        return web.json_response({"error": "device_id required"}, status=400)
    peer_ip = (
        req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or req.remote
        or ""
    )
    if not data.get("public_ip") and peer_ip:
        data["public_ip"] = peer_ip
    item = await db.heartbeat_tunnel_device(did, data)
    return web.json_response({"ok": True, "device": item})


async def toggle_tunnel_device_route(req: web.Request):
    data = await req.json()
    did = str(data.get("device_id") or "").strip()
    if not did:
        return web.json_response({"error": "device_id required"}, status=400)
    await db.set_tunnel_device_enabled(did, bool(data.get("enabled")))
    return await list_tunnels_route(req)


async def primary_tunnel_device_route(req: web.Request):
    data = await req.json()
    did = str(data.get("device_id") or "").strip()
    if not did:
        return web.json_response({"error": "device_id required"}, status=400)
    await db.set_primary_tunnel_device(did)
    return await list_tunnels_route(req)


async def test_tunnel_device_route(req: web.Request):
    data = await req.json() if req.can_read_body else {}
    did = str(data.get("device_id") or req.query.get("device_id") or "").strip()
    devices = await db.list_tunnel_devices()
    target = next((d for d in devices if d.get("device_id") == did), None)
    if not target or not target.get("proxy_url"):
        return web.json_response({"ok": False, "error": "Device has no active proxy URL"}, status=404)
    res = await test_proxy_status(target["proxy_url"])
    return web.json_response({**res, "device_id": did, "device_name": target.get("device_name")})


async def delete_tunnel_device_route(req: web.Request):
    did = str(req.query.get("device_id") or "").strip()
    if not did and req.can_read_body:
        try:
            body = await req.json()
            did = str(body.get("device_id") or "").strip()
        except Exception:
            pass
    if not did:
        return web.json_response({"error": "device_id required"}, status=400)
    sess = ws_tunnels.get_session(did)
    if sess:
        await sess.close()
    ok = await db.delete_tunnel_device(did)
    return await list_tunnels_route(req) if ok else web.json_response({"ok": False}, status=404)


async def toggle_shortener_tunnel_route(req: web.Request):
    data = await req.json()
    if data.get("all"):
        await db.set_all_shortener_tunnels(bool(data.get("enabled")))
        return await list_tunnels_route(req)
    dom = str(data.get("domain") or "").strip()
    if not dom:
        return web.json_response({"error": "domain required"}, status=400)
    await db.set_shortener_tunnel(
        dom,
        bool(data.get("enabled")),
        name=data.get("name"),
        desc=data.get("desc"),
    )
    return await list_tunnels_route(req)


async def delete_shortener_route(req: web.Request):
    dom = str(req.query.get("domain") or "").strip()
    if not dom:
        return web.json_response({"error": "domain required"}, status=400)
    await db.delete_custom_shortener(dom)
    return await list_tunnels_route(req)


async def download_pc_tunnel_route(req: web.Request):
    import io
    import zipfile
    host_hdr = (req.headers.get("X-Forwarded-Host") or req.headers.get("Host") or f"127.0.0.1:{PORT}").strip()
    proto_hdr = (req.headers.get("X-Forwarded-Proto") or req.scheme or "http").strip()
    server_url = db.settings.get("public_server_url") or f"{proto_hdr}://{host_hdr}"
    admin_pw = str(db.settings.get("admin_password") or "admin123")
    mongo_uri = str(db.settings.get("mongo_uri") or "")

    pc_dir = os.path.join(HERE, "tunnel_clients", "pc")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.isdir(pc_dir):
            for fname in os.listdir(pc_dir):
                fpath = os.path.join(pc_dir, fname)
                if os.path.isfile(fpath):
                    zf.write(fpath, arcname=f"TheDrunkBots-PC-Tunnel/{fname}")
        cfg_payload = {
            "server_url": server_url,
            "secret": admin_pw,
            "mongo_uri": mongo_uri,
            "device_name": "",
            "tunnel_mode": "auto",
            "auto_refresh_minutes": 50,
        }
        zf.writestr(
            "TheDrunkBots-PC-Tunnel/tunnel_config.json",
            json.dumps(cfg_payload, indent=2),
        )
    buf.seek(0)
    return web.Response(
        body=buf.read(),
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": 'attachment; filename="TheDrunkBots-PC-Tunnel.zip"',
        },
    )


async def download_android_apk_route(_: web.Request):
    apk_path = os.path.join(HERE, "tunnel_clients", "android", "TheDrunkBots-Tunnel.apk")
    if not os.path.exists(apk_path):
        return web.json_response({"error": "APK not found on server"}, status=404)
    with open(apk_path, "rb") as f:
        body = f.read()
    return web.Response(
        body=body,
        headers={
            "Content-Type": "application/vnd.android.package-archive",
            "Content-Disposition": 'attachment; filename="TheDrunkBots-Tunnel.apk"',
        },
    )


# --- Autonomous AI Engineer & Code Sync Routes ---
async def ai_status_route(_: web.Request):
    return web.json_response(await ai_engineer.get_dashboard_state())


async def ai_run_route(req: web.Request):
    data = await req.json()
    target_url = str(data.get("target_url") or data.get("url") or "").strip()
    prompt = str(data.get("prompt") or "").strip()
    trigger = str(data.get("trigger") or "manual").strip()
    error_id = str(data.get("error_id") or "").strip()
    err_entry = None
    if error_id:
        for item in db.local_logs:
            if item.get("id") == error_id:
                err_entry = item
                if not target_url:
                    target_url = item.get("source") or ""
                if not prompt:
                    prompt = f"Diagnose and fix error on {target_url}: {item.get('error')}"
                break
    run_info = await ai_engineer.start_run(
        trigger=trigger,
        target_url=target_url,
        prompt=prompt or "Scan all unresolved error logs, diagnose root causes, apply fixes, verify live, and push.",
        error_entry=err_entry,
    )
    return web.json_response(run_info)


async def ai_stream_route(req: web.Request):
    run_id = req.match_info.get("run_id", "")
    run = ai_engineer.current_run
    if not run or run.get("id") != run_id:
        for r in ai_engineer.runs_history:
            if r and r.get("id") == run_id:
                run = r
                break
    if not run:
        raise web.HTTPNotFound()

    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
    await resp.prepare(req)
    sent = 0
    try:
        while True:
            ev_obj = run.get("event_notify")
            if isinstance(ev_obj, asyncio.Event):
                ev_obj.clear()
            events = run.get("events") or []
            while sent < len(events):
                await resp.write(f"data: {json.dumps({'event': events[sent]})}\n\n".encode())
                sent += 1
            if run.get("status") in ("completed", "failed"):
                await resp.write(f"data: {json.dumps({'done': ai_engineer.public_run(run)})}\n\n".encode())
                break
            try:
                if isinstance(ev_obj, asyncio.Event):
                    await asyncio.wait_for(ev_obj.wait(), 12)
                else:
                    await asyncio.sleep(1.5)
            except asyncio.TimeoutError:
                await resp.write(b": ping\n\n")
    except (ConnectionResetError, asyncio.CancelledError, aiohttp.ClientConnectionError):
        pass
    return resp


async def ai_sync_route(req: web.Request):
    data = {}
    try:
        data = await req.json()
    except Exception:
        pass
    reason = str(data.get("reason") or "Admin triggered MongoDB + GitHub code sync")
    res = await code_sync.sync_all_to_mongo_and_github(reason=reason)
    return web.json_response(res)


async def ai_rollback_route(req: web.Request):
    data = await req.json()
    rev_id = str(data.get("revision_id") or "").strip()
    if not rev_id:
        return web.json_response({"ok": False, "error": "revision_id required"}, status=400)
    res = await code_sync.rollback_revision(rev_id)
    return web.json_response(res)


async def ai_rules_route(req: web.Request):
    data = await req.json()
    updated = await db.update_dynamic_rules(data)
    await code_sync.hot_reload_modules(["g2s/engine.py"])
    return web.json_response({"ok": True, "dynamic_rules": updated})


async def system_restart_route(req: web.Request):
    data = {}
    try:
        data = await req.json()
    except Exception:
        pass
    mode = str(data.get("mode") or "full").strip().lower()
    hydrated = await code_sync.hydrate_from_mongo_on_boot()
    if mode == "workers":
        for w in [bypasser] + list(getattr(bypasser, "_workers", []) or []):
            p_dir = getattr(getattr(w, "cfg", None), "profile_dir", None)
            try:
                if w.ctx:
                    await asyncio.wait_for(w.ctx.close(), timeout=4.0)
            except Exception:
                pass
            w.ctx = None
            if getattr(w, "_pw", None):
                try:
                    await asyncio.wait_for(w._pw.stop(), timeout=4.0)
                except Exception:
                    pass
                w._pw = None
            if p_dir and hasattr(bypasser, "_kill_profile_procs"):
                bypasser._kill_profile_procs(os.path.abspath(p_dir))
        await bypasser.start()
        return web.json_response({
            "ok": True,
            "mode": "workers",
            "hydrated": hydrated,
            "message": "Browser worker pool restarted cleanly & MongoDB code synced!",
        })

    async def _delayed_execv():
        await asyncio.sleep(0.7)
        await code_sync.trigger_graceful_restart(reason="Admin triggered restart from Web Dashboard")

    asyncio.create_task(_delayed_execv())
    return web.json_response({
        "ok": True,
        "mode": "full",
        "hydrated": hydrated,
        "message": "Restarting Bot & Server process now (applying latest MongoDB updates)…",
    })


# --------------------------------------------------------- Background Monitors
async def _background_sync_and_tunnel_monitor():
    tick = 0
    while True:
        await asyncio.sleep(45)
        tick += 1
        try:
            await code_sync.hydrate_from_mongo_on_boot()
            await db.refresh_settings_from_mongo()
            await db.sync_tunnels_from_mongo()
            if tick % 4 == 0:
                await db.sync_protected_masked_links()
            _apply_db_settings_to_cfg()
            await bot.reload_if_needed()
            active_px = (db.settings.get("proxy") or "").strip()
            if active_px and not db.settings.get("proxy_expired") and not bypasser.busy:
                info = await test_proxy_status(active_px)
                if not info.get("ok"):
                    await bot.notify_tunnel_expired(active_px, info.get("error") or "Tunnel unreachable")
        except asyncio.CancelledError:
            break
        except Exception:
            pass


async def on_startup(app: web.Application):
    await db.connect()
    hydrated = await code_sync.hydrate_from_mongo_on_boot()
    if hydrated:
        print(f"🛡 Boot Anti-Rollback Guard: Restored {len(hydrated)} AI-updated file(s) from MongoDB: {hydrated}", flush=True)
    _apply_db_settings_to_cfg()
    bypasser._ensure_display()
    print(f"Starting browser (headless={cfg.headless}, channel={cfg.browser_channel!r})…", flush=True)
    if cfg.proxy:
        print(f"Proxy configured: {mask_proxy(cfg.proxy)}", flush=True)
    else:
        print("Proxy: none configured at startup (can be set via Web Admin Panel or Telegram Bot).", flush=True)
    await bypasser.start()
    await bot.start()
    await ai_engineer.start()
    app["monitor_task"] = asyncio.create_task(_background_sync_and_tunnel_monitor())
    url = f"http://{HOST}:{PORT}/"
    print(f"\n  🍹 TheDrunkBots Admin Panel & API ready → {url}\n", flush=True)
    if not NO_OPEN:
        try:
            webbrowser.open(url)
        except Exception:
            pass


async def on_cleanup(app: web.Application):
    t = app.get("monitor_task")
    if t:
        t.cancel()
    await ai_engineer.stop()
    for sess in list(ws_tunnels.sessions.values()):
        await sess.close()
    await bot.stop()
    await bypasser.close()


app = web.Application(middlewares=[auth_middleware])
app.router.add_get("/", index)
app.router.add_post("/api/auth/login", auth_login)
app.router.add_post("/api/auth/logout", auth_logout)
app.router.add_get("/api/auth/me", auth_me)
app.router.add_get("/api/health", health)
app.router.add_get("/api/dashboard", dashboard)
app.router.add_get("/api/settings", get_settings)
app.router.add_post("/api/settings", post_settings)
app.router.add_get("/api/proxy-test", proxy_test_route)
app.router.add_get("/api/tunnels", list_tunnels_route)
app.router.add_post("/api/tunnels/register", register_tunnel_route)
app.router.add_post("/api/tunnels/heartbeat", heartbeat_tunnel_route)
app.router.add_post("/api/tunnels/toggle", toggle_tunnel_device_route)
app.router.add_post("/api/tunnels/primary", primary_tunnel_device_route)
app.router.add_post("/api/tunnels/test", test_tunnel_device_route)
app.router.add_delete("/api/tunnels", delete_tunnel_device_route)
app.router.add_get("/api/tunnels/ws", ws_tunnels.handle_ws)
app.router.add_get("/api/tunnels/download/pc", download_pc_tunnel_route)
app.router.add_get("/api/tunnels/download/android", download_android_apk_route)
app.router.add_post("/api/shorteners/toggle", toggle_shortener_tunnel_route)
app.router.add_delete("/api/shorteners", delete_shortener_route)
app.router.add_post("/api/jobs", create_job_route)
app.router.add_get("/api/jobs/{jid}/events", job_events_route)
app.router.add_get("/api/resolve", resolve_api_route)
app.router.add_get("/api/cache", list_cache_route)
app.router.add_post("/api/cache", upsert_cache_route)
app.router.add_delete("/api/cache", delete_cache_route)
app.router.add_get("/api/history", list_cache_route)
app.router.add_delete("/api/history", delete_cache_route)
app.router.add_get("/api/fsub", list_fsub_route)
app.router.add_post("/api/fsub", save_fsub_route)
app.router.add_delete("/api/fsub", delete_fsub_route)
app.router.add_get("/api/protected", get_protected_route)
app.router.add_post("/api/protected/bot", post_protected_bot_route)
app.router.add_put("/api/protected/bot", post_protected_bot_route)
app.router.add_delete("/api/protected/bot", delete_protected_bot_route)
app.router.add_post("/api/protected/cluster", post_protected_cluster_route)
app.router.add_delete("/api/protected/cluster", delete_protected_cluster_route)
app.router.add_post("/api/protected/rules", post_protected_rules_route)
app.router.add_post("/api/protected/sync", post_protected_sync_route)
app.router.add_get("/api/premium", get_premium_route)
app.router.add_post("/api/premium/settings", post_premium_settings_route)
app.router.add_post("/api/premium/plan", post_premium_plan_route)
app.router.add_delete("/api/premium/plan", delete_premium_plan_route)
app.router.add_post("/api/premium/user", post_premium_user_route)
app.router.add_delete("/api/premium/user", delete_premium_user_route)
app.router.add_post("/api/premium/reset-free", post_reset_free_uses_route)
app.router.add_get("/api/logs", list_logs_route)
app.router.add_delete("/api/logs", delete_logs_route)
app.router.add_get("/api/users", list_users_route)
app.router.add_post("/api/users/ban", user_ban_route)
app.router.add_delete("/api/users", delete_user_route)
app.router.add_post("/api/broadcast", broadcast_route)
app.router.add_get("/api/ai/status", ai_status_route)
app.router.add_post("/api/ai/run", ai_run_route)
app.router.add_get("/api/ai/stream/{run_id}", ai_stream_route)
app.router.add_post("/api/ai/sync", ai_sync_route)
app.router.add_post("/api/ai/rollback", ai_rollback_route)
app.router.add_post("/api/ai/rules", ai_rules_route)
app.router.add_post("/api/system/restart", system_restart_route)
app.on_startup.append(on_startup)
app.on_cleanup.append(on_cleanup)

if __name__ == "__main__":
    print(f"Listening on {HOST}:{PORT}", flush=True)
    web.run_app(app, host=HOST, port=PORT, print=None, reuse_address=True, reuse_port=(os.name != "nt"))
