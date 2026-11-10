"""
TheDrunkBots Telegram Bot Engine for G2S Direct-Link Generator.
Features:
  - Matches attached screenshot formatting (blockquotes, 14-segment live progress bar,
    estimated time remaining, elapsed time, COPY LINK + OPEN LINK inline buttons)
  - /start welcome message with photo https://i.ibb.co/1Nx1jMn/IMG-20261005-021725.png
  - Force-Subscribe check & interactive channel management
  - Full interactive Admin Panel inside Telegram (only visible to owner_id / admin_ids)
  - Instant MongoDB cache lookup & storage (0.01s response on cached links)
  - Zero technical logs shown to users; complete error logs stored in MongoDB/Web UI
    and forwarded to Owner/Admins on Telegram
  - Automatic Owner alert on Telegram when the Pinggy tunnel / proxy expires
"""
import asyncio
import contextlib
import html
import json
import random
import re
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .db import (
    DEFAULT_BRAND,
    DEFAULT_PAYMENT_CONFIG,
    DEFAULT_PREMIUM_PLANS,
    DEFAULT_PROTECTED_MESSAGE,
    DEFAULT_START_PHOTO,
    Database,
    ProtectedLinkError,
    SubscriptionRequiredError,
    format_ist_expiry,
    norm_url,
)
from .payment import (
    build_upi_qr_bytes,
    make_order_id,
    on_payment_success,
    send_payment_log_to_targets,
    start_auto_verifier,
    stop_auto_verifier,
    verify_paytm_order,
)

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
NON_SHORTENER_HOSTS = {
    "t.me", "telegram.me", "telegram.dog", "youtube.com", "www.youtube.com",
    "youtu.be", "instagram.com", "www.instagram.com", "facebook.com",
    "www.facebook.com", "twitter.com", "x.com", "whatsapp.com", "chat.whatsapp.com",
}


def extract_clean_urls(
    text: str,
    entities: list[dict] | None = None,
    reply_markup: dict | None = None,
) -> list[str]:
    from .engine import normalize_input_url
    raw: list[str] = []
    if entities:
        for ent in entities:
            if isinstance(ent, dict) and ent.get("url"):
                for u_ent in URL_RE.findall(str(ent.get("url"))):
                    raw.append(u_ent.rstrip(".,;:!?)>]}"))
    if isinstance(reply_markup, dict):
        for row in reply_markup.get("inline_keyboard") or []:
            if not isinstance(row, list):
                continue
            for btn in row:
                if isinstance(btn, dict) and btn.get("url"):
                    for u_btn in URL_RE.findall(str(btn.get("url"))):
                        raw.append(u_btn.rstrip(".,;:!?)>]}"))
    for u_txt in URL_RE.findall(text or ""):
        raw.append(u_txt.rstrip(".,;:!?)>]}"))
    seen = set()
    cleaned = []
    for u in raw:
        u_norm = normalize_input_url(u)
        if not u_norm or u_norm in seen:
            continue
        p_u = urlparse(u_norm)
        # Ignore bare root domains with no path/query (e.g. visible text of a [domain](full_url) text_link)
        if (p_u.path or "") in ("", "/") and not p_u.query and not p_u.fragment:
            continue
        seen.add(u_norm)
        cleaned.append(u_norm)
    # Remove any URL that is a strict prefix of a longer extracted URL (e.g. truncated text vs full text_link entity)
    deduped = [
        u for u in cleaned
        if not any(other != u and len(other) > len(u) and other.startswith(u.rstrip("…")) for other in cleaned)
    ]
    filtered = [
        u for u in deduped
        if (urlparse(u).hostname or "").lower() not in NON_SHORTENER_HOSTS
    ]
    return filtered


def esc(val: Any) -> str:
    return html.escape(str(val or ""))


def display_url(url: str, max_len: int = 280) -> str:
    """Format ultra-long URLs (e.g. 4.6KB koyeb tokens) so Telegram HTML messages never exceed 4,096 chars."""
    s = str(url or "").strip()
    if len(s) <= max_len:
        return s
    head = max(80, max_len - 45)
    return f"{s[:head]}…{s[-40:]}"


def estimate_duration(url: str) -> float:
    h = (urlparse(url).hostname or "").lower()
    if "pastelink." in h or "pastetoday." in h or "pastequest." in h or "hastebin." in h or "rentry." in h:
        return 2.0
    if "lockr." in h:
        return 32.0
    if "directlinker." in h or "linkpays." in h:
        return 8.0
    if "shrinkme." in h or "mrproblogger." in h or "ouo." in h:
        return 14.0
    if "arolinks." in h or "vplink." in h:
        return 118.0
    if "gplinks." in h:
        return 105.0
    if "exeygo." in h:
        return 28.0
    if "inshorturl." in h:
        return 90.0
    if "urlking." in h or "mytoolspro." in h:
        return 4.0
    if "sfl.gl" in h or "safelinku." in h or "khaddavi." in h:
        return 6.0
    if "short4cash." in h or "sayphotobooth." in h:
        return 8.0
    if "up.railway.app" in h:
        return 17.0
    if "linkvertise." in h or "link-hub." in h or "link-target." in h or "link-center." in h or "direct-link." in h:
        return 6.0
    if ("publicbotshub" in h or "koyeb.app" in h) and "/link/" in url:
        return 24.0
    if "mrn-officialx." in h or "avbypassbot." in h or "publicbotshub" in h:
        return 7.0
    if "linkprotect." in h:
        return 10.0
    if "speedy-links." in h or "best-links." in h or "loot-link." in h or "loot-links." in h or "lootdest." in h:
        return 15.0
    if "liteshort." in h or "nowshort." in h or "urllinkshort." in h or "earnlinks." in h or "prostore7." in h or "droplink." in h:
        return 8.0
    if "vipshort." in h or "linksflys." in h or "linksfire." in h or "urlspay." in h or "remso." in h:
        return 9.0
    if "babylinks." in h or "v2links." in h or "makelinks." in h or "nazki-protected." in h:
        return 13.0
    if "lksfy." in h:
        return 16.0
    if "get2short." in h:
        return 68.0
    if "shortxlinks." in h or "softurl." in h:
        return 39.0
    if "jobsraavi." in h or "alpha-links." in h:
        return 33.0
    if "shortwala." in h:
        return 20.0
    return 22.0


def build_progress_bar(pct: int, width: int = 14) -> str:
    pct = max(1, min(99, int(pct)))
    filled = max(1, min(width, round((pct / 100.0) * width)))
    return "▰" * filled + "▱" * (width - filled)


def format_fetching_message(pct: int, elapsed: float, eta: float) -> str:
    bar = build_progress_bar(pct, 14)
    eta_str = f"~{max(1, int(round(eta)))}s"
    return (
        f"<blockquote>⚡ <b>𝗙𝗘𝗧𝗖𝗛𝗜𝗡𝗚 𝗟𝗜𝗡𝗞...</b>\n"
        f"<code>{bar}</code>  <b>{pct}%</b>\n"
        f"⏳ <b>𝗘𝗧𝗔 :</b> <code>{eta_str}</code>  •  ⏱️ <b>𝗘𝗟𝗔𝗣𝗦𝗘𝗗 :</b> <code>{elapsed:.1f}s</code></blockquote>"
    )


def format_success_message(
    source_url: str,
    bypassed_url: str,
    elapsed: float,
    cached: bool = False,
    extra_links: list[str] | None = None,
) -> str:
    status_label = "CACHED ⚡" if cached else "SUCCESS"
    t_str = "0.01s" if cached and elapsed < 0.05 else f"{elapsed:.2f}s"
    extra_block = ""
    if extra_links:
        lines = [f"{i}. {esc(display_url(u, 220))}" for i, u in enumerate(extra_links[:12], 1)]
        extra_block = (
            f"📋 <b>𝗟𝗜𝗡𝗞𝗦 𝗜𝗡𝗦𝗜𝗗𝗘 𝗣𝗔𝗦𝗧𝗘 ({len(extra_links)}) :</b>\n"
            f"<blockquote>" + "\n".join(lines) + "</blockquote>\n"
        )
    return (
        f"🟢 • <b>𝗦𝗨𝗖𝗖𝗘𝗦𝗦</b>\n\n"
        f"🔗 <b>𝗢𝗥𝗜𝗚𝗜𝗡𝗔𝗟 𝗟𝗜𝗡𝗞 :</b>\n"
        f"<blockquote>{esc(display_url(source_url, 280))}</blockquote>\n"
        f"✅ <b>𝗕𝗬𝗣𝗔𝗦𝗦𝗘𝗗 𝗟𝗜𝗡𝗞 :</b>\n"
        f"<blockquote>{esc(display_url(bypassed_url, 800))}</blockquote>\n"
        f"{extra_block}"
        f"<blockquote>⏱️ <b>𝗧𝗜𝗠𝗘 𝗧𝗔𝗞𝗘𝗡 :</b> <code>{t_str}</code>  •  🟢 <b>𝗦𝗧𝗔𝗧𝗨𝗦 :</b> <code>{status_label}</code></blockquote>"
    )


def format_user_error_message(source_url: str) -> str:
    return (
        f"🔴 • <b>𝗙𝗔𝗜𝗟𝗘𝗗</b>\n\n"
        f"🔗 <b>𝗢𝗥𝗜𝗚𝗜𝗡𝗔𝗟 𝗟𝗜𝗡𝗞 :</b>\n"
        f"<blockquote>{esc(display_url(source_url, 280))}</blockquote>\n"
        f"<blockquote>⚠️ <b>𝗦𝗧𝗔𝗧𝗨𝗦 :</b> <code>Unable to bypass this link right now. Admin has been notified.</code></blockquote>"
    )


class TelegramBot:
    def __init__(self, db: Database, resolve_fn, proxy_test_fn, set_proxy_fn, ai_engineer=None, code_sync=None):
        self.db = db
        self.resolve_fn = resolve_fn
        self.proxy_test_fn = proxy_test_fn
        self.set_proxy_fn = set_proxy_fn
        self.ai_engineer = ai_engineer
        self.code_sync = code_sync

        self.token: str = ""
        self._invalid_token: str = ""
        self.bot_info: dict | None = None
        self.running: bool = False
        self._task: asyncio.Task | None = None
        self._expiry_task: asyncio.Task | None = None
        self._session: aiohttp.ClientSession | None = None
        self._offset: int = 0
        self._photo_file_id_cache: dict[str, str] = {}
        self._photo_msg_ids: set[tuple[Any, int]] = set()
        self._fsub_member_cache: dict[tuple[str, int], tuple[bool, float]] = {}
        self._fsub_pending_urls: dict[int, list[str]] = {}
        # Tracks interactive admin input state: {user_id: {"action": "...", ...}}
        self._admin_states: dict[int, dict[str, Any]] = {}
        # Interactive loop-setup state for premium users: {user_id: {"step": "links"|"times", ...}}
        self._user_states: dict[int, dict[str, Any]] = {}
        # Per-user loop mode config & runtime: config = links/times; runtime task + stop flag
        self._loop_configs: dict[int, dict[str, Any]] = {}
        self._loop_tasks: dict[int, asyncio.Task] = {}
        self._loop_stop_flags: dict[int, bool] = {}
        self._last_tunnel_alert_at: float = 0.0
        self._alerted_expired_proxy: str | None = None
        # Tracks active/queued bypass jobs for accurate queue-aware ETA: {job_uid: [start_mono, est_sec]}
        self._active_jobs: dict[str, list[float]] = {}
        # Per-chat FloodWait & pacing state so 40-50 concurrent links never get stuck on Processing
        self._chat_flood_until: dict[Any, float] = {}
        self._chat_last_send_at: dict[Any, float] = {}
        self._chat_locks: dict[Any, asyncio.Lock] = {}
        # Reassembly buffer for ultra-long (>4096 char) URLs split by Telegram into consecutive messages
        self._split_url_buffers: dict[tuple[Any, int], dict[str, Any]] = {}

    @property
    def api_base(self) -> str:
        return f"https://api.telegram.org/bot{self.token}"

    def _get_contact_admin_url(self) -> str:
        contact = str(
            self.db.settings.get("owner_contact_url")
            or DEFAULT_PAYMENT_CONFIG["owner_contact_url"]
        ).strip()
        if contact.startswith("@"):
            return f"https://t.me/{contact.lstrip('@')}"
        if not contact.startswith("http"):
            return f"https://t.me/{contact.lstrip('@') or 'ToxicXAdminRoBot'}"
        return contact

    async def start(self):
        token = (self.db.settings.get("telegram_bot_token") or "").strip()
        if not token:
            print("Telegram Bot: no telegram_bot_token configured yet (can be set in config.json or Admin Panel).", flush=True)
            return False
        if self.running and token == self.token and self._task and not self._task.done():
            return True
        await self.stop()
        self.token = token
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=45))
        me = await self.api("getMe")
        if not me or not me.get("ok"):
            err = (me or {}).get("description", "invalid token or network error")
            if "unauthorized" in str(err).lower():
                self._invalid_token = token
            print(f"⚠ Telegram Bot failed to start: {err}", flush=True)
            await self.stop()
            return False
        self._invalid_token = ""
        self.bot_info = me.get("result") or {}
        uname = self.bot_info.get("username", "unknown")
        print(f"✔ Telegram Bot started: @{uname} (ID: {self.bot_info.get('id')})", flush=True)
        await self._register_commands()
        self.running = True
        asyncio.create_task(self.sync_all_fsub_channels())
        self._task = asyncio.create_task(self._poll_loop())
        self._expiry_task = asyncio.create_task(self._premium_expiry_loop())
        asyncio.create_task(self._resume_pending_orders_on_boot())
        return True

    async def _resume_pending_orders_on_boot(self):
        """Resumes background auto-verifiers for any recent pending/processing orders after a restart."""
        await asyncio.sleep(2.0)
        now = time.time()
        for oid, o in list(self.db.local_orders.items()):
            st = o.get("status")
            exp_ts = float(o.get("expiry_ts") or 0)
            if st in ("pending", "processing") and exp_ts > (now - 300):
                if st == "processing":
                    await self.db.update_order_status(oid, "pending")
                start_auto_verifier(
                    self,
                    self.db,
                    order_id=oid,
                    chat_id=int(o.get("chat_id") or o.get("user_id") or 0),
                    qr_message_id=o.get("qr_message_id"),
                    expiry_ts=max(exp_ts, now + 60),
                )

    async def stop(self):
        self.running = False
        for t in (self._task, self._expiry_task):
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except Exception:
                    pass
        self._task = None
        self._expiry_task = None
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = None
        self.bot_info = None

    async def _premium_expiry_loop(self):
        """Background loop that checks for expired premium plans every 60s
        and notifies users automatically.
        """
        while self.running:
            try:
                await asyncio.sleep(60.0)
                if not self.running:
                    break
                expired_list = await self.db.check_and_expire_premium_users()
                contact_url = self._get_contact_admin_url()
                for exp in expired_list:
                    uid = int(exp.get("user_id") or 0)
                    if not uid:
                        continue
                    plan_lbl = exp.get("plan_label") or exp.get("plan_type") or "Premium"
                    exp_str = exp.get("expired_str") or "Now"
                    msg = (
                        f"<blockquote>⚠️ <b>ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ᴇxᴘɪʀᴇᴅ!</b></blockquote>\n\n"
                        f"<blockquote>ʏᴏᴜʀ ᴘʀᴇᴍɪᴜᴍ sᴜʙsᴄʀɪᴘᴛɪᴏɴ (<b>{esc(plan_lbl)}</b>) ᴇxᴘɪʀᴇᴅ ᴏɴ <code>{esc(exp_str)}</code>.</blockquote>\n"
                        f"<blockquote>ʀᴇɴᴇᴡ ʏᴏᴜʀ ᴘʟᴀɴ ʙᴇʟᴏᴡ ᴛᴏ ᴄᴏɴᴛɪɴᴜᴇ ᴇɴᴊᴏʏɪɴɢ ᴜɴʟɪᴍɪᴛᴇᴅ ʟɪɴᴋ ʙʏᴘᴀssᴇs!</blockquote>"
                    )
                    kb = {
                        "inline_keyboard": [
                            [{"text": "💎 Buy / Renew Premium", "callback_data": "usr:premium", "style": "success"}],
                            [
                                {"text": "👨‍💻 Contact Admin", "url": contact_url},
                                {"text": "🏠 Home", "callback_data": "usr:start"},
                            ],
                        ]
                    }
                    try:
                        await self.send_message(uid, msg, reply_markup=kb)
                    except Exception:
                        pass
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(30.0)

    async def reload_if_needed(self):
        new_token = (self.db.settings.get("telegram_bot_token") or "").strip()
        if new_token and new_token == self._invalid_token:
            return
        if new_token != self.token or (new_token and not self.running):
            if new_token:
                await self.start()
            else:
                await self.stop()

    async def api(
        self,
        method: str,
        payload: dict | None = None,
        timeout: float = 35.0,
        is_progress: bool = False,
    ) -> dict | None:
        if not self.token or not self._session:
            return None
        chat_id = (payload or {}).get("chat_id")
        is_chat_write = method in (
            "sendMessage",
            "editMessageText",
            "editMessageCaption",
            "sendPhoto",
        )
        max_attempts = 1 if is_progress else 8
        for attempt in range(max_attempts):
            if chat_id is not None and is_chat_write:
                now_m = time.monotonic()
                flood_until = self._chat_flood_until.get(chat_id, 0.0)
                if now_m < flood_until:
                    if is_progress:
                        return {"ok": False, "skipped_flood": True}
                    await asyncio.sleep(min(flood_until - now_m + 0.35, 60.0))
                lock = self._chat_locks.setdefault(chat_id, asyncio.Lock())
                async with lock:
                    now_m2 = time.monotonic()
                    flood_until2 = self._chat_flood_until.get(chat_id, 0.0)
                    if now_m2 < flood_until2:
                        if is_progress:
                            return {"ok": False, "skipped_flood": True}
                        await asyncio.sleep(min(flood_until2 - now_m2 + 0.35, 60.0))
                    last_at = self._chat_last_send_at.get(chat_id, 0.0)
                    min_gap = 1.8 if is_progress else 0.14
                    wait_gap = min_gap - (time.monotonic() - last_at)
                    if wait_gap > 0:
                        if is_progress and wait_gap > 0.8:
                            return {"ok": False, "skipped_pace": True}
                        await asyncio.sleep(wait_gap)
                    self._chat_last_send_at[chat_id] = time.monotonic()
            try:
                async with self._session.post(
                    f"{self.api_base}/{method}",
                    json=payload or {},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as r:
                    res = await r.json(content_type=None)
                if isinstance(res, dict) and res.get("error_code") == 429:
                    retry_after = float((res.get("parameters") or {}).get("retry_after") or 3.0)
                    if chat_id is not None:
                        self._chat_flood_until[chat_id] = max(
                            self._chat_flood_until.get(chat_id, 0.0),
                            time.monotonic() + retry_after + 0.75,
                        )
                    if is_progress:
                        return res
                    if attempt + 1 < max_attempts:
                        await asyncio.sleep(min(retry_after + 0.5, 60.0))
                        continue
                return res
            except Exception as e:
                if is_progress:
                    return {"ok": False, "description": str(e)}
                if attempt + 1 < max_attempts:
                    await asyncio.sleep(0.8 * (attempt + 1))
                    continue
                return {"ok": False, "description": str(e)}
        return {"ok": False, "description": "request_failed"}

    async def _register_commands(self):
        user_cmds = [
            {"command": "start", "description": "🍹 Start TheDrunkBots Bypasser"},
            {"command": "premium", "description": "💎 Buy Premium Subscription"},
            {"command": "myplan", "description": "👑 Check your Premium Plan & Free Trial status"},
            {"command": "help", "description": "📖 How to bypass links & supported sites"},
            {"command": "bypass", "description": "⚡ Bypass a shortlink"},
            {"command": "myinfo", "description": "👤 View your stats & profile"},
            {"command": "status", "description": "📊 Check bot & cloud cache status"},
            {"command": "loop", "description": "🔁 Open Loop Mode setup panel (Premium)"},
            {"command": "loop_setup", "description": "🔁 Setup Loop Mode (Premium) — continuous multi-link processing"},
            {"command": "loop_start", "description": "▶️ Start Loop Mode (Premium)"},
            {"command": "loop_stop", "description": "⏹ Stop running Loop Mode"},
            {"command": "loop_status", "description": "📊 Check Loop Mode status"},
        ]
        # Register globally so every user sees the full command list (including loop_*)
        res = await self.api("setMyCommands", {"commands": user_cmds})
        if res and res.get("ok"):
            print(f"✔ Bot commands registered ({len(user_cmds)} cmds, incl. loop/loop_setup/start/stop/status)", flush=True)
        else:
            print(f"⚠ setMyCommands failed: {(res or {}).get('description')}", flush=True)
            # Retry once after short delay (Telegram sometimes flakes on boot)
            await asyncio.sleep(2.0)
            res2 = await self.api("setMyCommands", {"commands": user_cmds})
            if res2 and res2.get("ok"):
                print("✔ Bot commands registered on retry", flush=True)
            else:
                print(f"⚠ setMyCommands retry failed: {(res2 or {}).get('description')}", flush=True)
        # Also clear any chat-specific overrides so the global list is what users see
        with contextlib.suppress(Exception):
            await self.api("deleteMyCommands", {"scope": {"type": "all_private_chats"}})
            await self.api("setMyCommands", {"commands": user_cmds, "scope": {"type": "all_private_chats"}})

    async def send_message(
        self,
        chat_id: int | str,
        text: str,
        reply_to: int | None = None,
        reply_markup: dict | None = None,
        disable_preview: bool = True,
        is_progress: bool = False,
    ) -> dict | None:
        safe_text = text if len(text) <= 4096 else esc(text[:4000]) + "…"
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": safe_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": disable_preview,
        }
        if self.db.settings.get("protect_content"):
            payload["protect_content"] = True
        if reply_to:
            payload["reply_to_message_id"] = reply_to
        if reply_markup:
            payload["reply_markup"] = reply_markup
        res = await self.api("sendMessage", payload, is_progress=is_progress)
        # Fallback if older Bot API server rejects copy_text button
        if not is_progress and (not res or not res.get("ok")) and reply_markup and "copy_text" in str(reply_markup):
            fallback_rows = []
            for row in reply_markup.get("inline_keyboard", []):
                new_row = [b for b in row if "copy_text" not in b]
                if new_row:
                    fallback_rows.append(new_row)
            payload["reply_markup"] = {"inline_keyboard": fallback_rows}
            res = await self.api("sendMessage", payload, is_progress=is_progress)
        return res

    async def edit_message(
        self,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict | None = None,
        disable_preview: bool = True,
        is_progress: bool = False,
    ) -> dict | None:
        safe_text = text if len(text) <= 4096 else esc(text[:4000]) + "…"
        is_photo = (chat_id, int(message_id)) in self._photo_msg_ids
        if is_photo:
            cap_payload: dict[str, Any] = {
                "chat_id": chat_id,
                "message_id": message_id,
                "caption": safe_text,
                "parse_mode": "HTML",
            }
            if reply_markup:
                cap_payload["reply_markup"] = reply_markup
            res = await self.api("editMessageCaption", cap_payload, is_progress=is_progress)
            if (not res or not res.get("ok")) and reply_markup and "copy_text" in str(reply_markup):
                fallback_rows = []
                for row in reply_markup.get("inline_keyboard", []):
                    new_row = [b for b in row if "copy_text" not in b]
                    if new_row:
                        fallback_rows.append(new_row)
                cap_payload["reply_markup"] = {"inline_keyboard": fallback_rows}
                res = await self.api("editMessageCaption", cap_payload, is_progress=is_progress)
            if res and res.get("ok"):
                return res
            desc_c = str((res or {}).get("description") or "").lower()
            if "message is not modified" in desc_c:
                return {"ok": True, "not_modified": True}
            if "no caption in the message" in desc_c:
                self._photo_msg_ids.discard((chat_id, int(message_id)))
            elif "caption is too long" in desc_c:
                await self.api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
                self._photo_msg_ids.discard((chat_id, int(message_id)))
                return await self.send_message(
                    chat_id,
                    safe_text,
                    reply_markup=reply_markup,
                    disable_preview=disable_preview,
                )

        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": safe_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": disable_preview,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        res = await self.api("editMessageText", payload, is_progress=is_progress)
        if (not res or not res.get("ok")) and reply_markup and "copy_text" in str(reply_markup):
            fallback_rows = []
            for row in reply_markup.get("inline_keyboard", []):
                new_row = [b for b in row if "copy_text" not in b]
                if new_row:
                    fallback_rows.append(new_row)
            payload["reply_markup"] = {"inline_keyboard": fallback_rows}
            res = await self.api("editMessageText", payload, is_progress=is_progress)
        if not res or not res.get("ok"):
            desc = str((res or {}).get("description") or "").lower()
            if "message is not modified" in desc:
                return {"ok": True, "not_modified": True}
            if "no text in the message" in desc:
                self._photo_msg_ids.add((chat_id, message_id))
                cap_payload = {
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "caption": text[:1024],
                    "parse_mode": "HTML",
                }
                if reply_markup:
                    cap_payload["reply_markup"] = reply_markup
                res_cap = await self.api("editMessageCaption", cap_payload, is_progress=is_progress)
                if res_cap and res_cap.get("ok"):
                    return res_cap
                if "message is not modified" in str((res_cap or {}).get("description") or "").lower():
                    return {"ok": True, "not_modified": True}
            if any(k in desc for k in ("message to edit not found", "message can't be edited")):
                return await self.send_message(
                    chat_id,
                    text,
                    reply_markup=reply_markup,
                    disable_preview=disable_preview,
                )
        return res

    async def send_photo(
        self,
        chat_id: int | str,
        photo_url: str,
        caption: str,
        reply_to: int | None = None,
        reply_markup: dict | None = None,
    ) -> dict | None:
        photo_ref = self._photo_file_id_cache.get(photo_url) or photo_url
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "photo": photo_ref,
            "caption": caption,
            "parse_mode": "HTML",
        }
        if reply_to:
            payload["reply_to_message_id"] = reply_to
        if reply_markup:
            payload["reply_markup"] = reply_markup
        res = await self.api("sendPhoto", payload)
        if res and res.get("ok"):
            msg_res = res.get("result") or {}
            mid = msg_res.get("message_id")
            if mid:
                self._photo_msg_ids.add((chat_id, int(mid)))
            photos = msg_res.get("photo") or []
            if photos and isinstance(photos, list):
                fid = photos[-1].get("file_id")
                if fid:
                    self._photo_file_id_cache[photo_url] = fid
            return res
        # Fallback to text message if image URL couldn't be fetched by Telegram
        return await self.send_message(chat_id, caption, reply_to=reply_to, reply_markup=reply_markup)

    async def delete_message(self, chat_id: int | str, message_id: int) -> dict | None:
        self._photo_msg_ids.discard((chat_id, int(message_id)))
        return await self.api("deleteMessage", {"chat_id": chat_id, "message_id": int(message_id)})

    async def send_photo_bytes(
        self,
        chat_id: int | str,
        photo_bytes: bytes,
        caption: str,
        reply_to: int | None = None,
        reply_markup: dict | None = None,
        filename: str = "qr.png",
    ) -> dict | None:
        """Uploads dynamically generated PNG bytes (e.g. UPI QR code) directly to Telegram."""
        if not self.token or not self._session:
            return None
        try:
            form = aiohttp.FormData()
            form.add_field("chat_id", str(chat_id))
            form.add_field("caption", caption)
            form.add_field("parse_mode", "HTML")
            if self.db.settings.get("protect_content"):
                form.add_field("protect_content", "true")
            if reply_to:
                form.add_field("reply_to_message_id", str(reply_to))
            if reply_markup:
                form.add_field("reply_markup", json.dumps(reply_markup))
            form.add_field("photo", photo_bytes, filename=filename, content_type="image/png")
            async with self._session.post(
                f"{self.api_base}/sendPhoto",
                data=form,
                timeout=aiohttp.ClientTimeout(total=35),
            ) as r:
                res = await r.json(content_type=None)
            if res and res.get("ok"):
                msg_res = res.get("result") or {}
                mid = msg_res.get("message_id")
                if mid:
                    self._photo_msg_ids.add((chat_id, int(mid)))
                return res
        except Exception:
            pass
        return await self.send_message(chat_id, caption, reply_to=reply_to, reply_markup=reply_markup)

    # ------------------------------------------------- Owner / Admin alerts
    async def notify_admins(self, text: str, reply_markup: dict | None = None):
        if not self.running:
            return
        targets = set()
        owner = int(self.db.settings.get("owner_id") or 0)
        if owner:
            targets.add(owner)
        for aid in self.db.settings.get("admin_ids") or []:
            try:
                if int(aid):
                    targets.add(int(aid))
            except Exception:
                pass
        for tid in targets:
            try:
                await self.send_message(tid, text, reply_markup=reply_markup)
            except Exception:
                pass

    async def notify_error_log(self, entry: dict):
        if not self.running:
            return
        src = entry.get("source") or ""
        err = entry.get("error") or "Unknown error"
        uid = entry.get("user_id")
        uname = entry.get("username")
        origin = entry.get("origin", "bot")
        logs = entry.get("log") or []
        short_logs = [f"{ln[:220]}…" if len(str(ln)) > 220 else str(ln) for ln in logs[-18:]]
        log_tail = "\n".join(short_logs) if short_logs else "No step logs recorded."
        if len(log_tail) > 2200:
            log_tail = "…\n" + log_tail[-2200:]
        user_line = f"<code>{uid}</code> (@{esc(uname)})" if uid else f"<code>{esc(origin)}</code>"
        msg = (
            f"🚨 • <b>𝗕𝗬𝗣𝗔𝗦𝗦 𝗘𝗥𝗥𝗢𝗥 𝗥𝗘𝗣𝗢𝗥𝗧</b>\n\n"
            f"👤 <b>𝗨𝗦𝗘𝗥 / 𝗢𝗥𝗜𝗚𝗜𝗡 :</b> {user_line}\n"
            f"🔗 <b>𝗟𝗜𝗡𝗞 :</b>\n<blockquote>{esc(display_url(src, 280))}</blockquote>\n"
            f"❌ <b>𝗘𝗥𝗥𝗢𝗥 :</b>\n<blockquote>{esc(display_url(err, 400))}</blockquote>\n"
            f"📜 <b>𝗖𝗢𝗠𝗣𝗟𝗘𝗧𝗘 𝗦𝗧𝗘𝗣 𝗟𝗢𝗚 :</b>\n"
            f"<pre>{esc(log_tail)}</pre>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "🛠 Open Admin Panel", "callback_data": "adm:home"},
                    {"text": "🌐 Set Tunnel Proxy", "callback_data": "adm:set_proxy"},
                ]
            ]
        }
        await self.notify_admins(msg, reply_markup=kb)

    async def notify_tunnel_expired(self, expired_proxy: str | None, reason: str):
        px_key = (expired_proxy or "").strip()
        if not px_key:
            return
        already_notified_for = (self.db.settings.get("proxy_expired_notified_for") or "").strip()
        if (
            self._alerted_expired_proxy == px_key
            or already_notified_for == px_key
            or bool(self.db.settings.get("proxy_expired"))
        ):
            return
        self._alerted_expired_proxy = px_key
        self._last_tunnel_alert_at = time.time()
        await self.db.update_settings(
            {"proxy_expired": True, "proxy_expired_notified_for": px_key},
            notify=False,
        )
        if not self.running:
            return
        masked = re.sub(r"(://[^:/@]+:)[^@]+@", r"\1•••@", px_key)
        msg = (
            f"⚠️ • <b>𝗧𝗨𝗡𝗡𝗘𝗟 / 𝗣𝗥𝗢𝗫𝗬 𝗘𝗫𝗣𝗜𝗥𝗘𝗗</b>\n\n"
            f"🌐 <b>𝗘𝗫𝗣𝗜𝗥𝗘𝗗 𝗧𝗨𝗡𝗡𝗘𝗟 :</b>\n<blockquote><code>{esc(masked)}</code></blockquote>\n"
            f"❗ <b>𝗥𝗘𝗔𝗦𝗢𝗡 :</b>\n<blockquote><code>{esc(reason[:300])}</code></blockquote>\n"
            f"<blockquote>🔄 <b>Please renew your Pinggy / residential tunnel and update it below or in the Web Admin Panel!</b></blockquote>"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "🌐 Update Tunnel Proxy Now", "callback_data": "adm:set_proxy"}],
                [{"text": "🛠 Open Admin Panel", "callback_data": "adm:home"}],
            ]
        }
        await self.notify_admins(msg, reply_markup=kb)

    # ------------------------------------------------- Force-Subscribe Check & Auto-Invite Sync
    async def resolve_and_prepare_fsub_channel(
        self,
        chat_id: str,
        title: str = "",
        invite_link: str = "",
        force_new_invite: bool = False,
    ) -> dict[str, Any]:
        cid = str(chat_id or "").strip()
        clean_title = (title or "").strip()
        clean_invite = (invite_link or "").strip()

        def _to_param(c_str: str):
            return int(c_str) if c_str.lstrip("-").isdigit() else c_str

        candidates = [cid]
        if cid in ("-1003768452343", "-1004462643599") or "drunkbots" in clean_title.lower() or "jU3thxiOiyhmNDFl" in clean_invite:
            for fb in ("-1004462643599", "@TheDrunkBots"):
                if fb not in candidates:
                    candidates.append(fb)
        if clean_invite and "t.me/" in clean_invite and "/+" not in clean_invite and "joinchat/" not in clean_invite:
            uname_cand = "@" + clean_invite.split("t.me/", 1)[1].split("?")[0].strip("/")
            if uname_cand != "@" and uname_cand not in candidates:
                candidates.append(uname_cand)

        chat_obj = None
        api_cid = "-1004462643599" if cid == "-1003768452343" else cid
        if not self.token:
            self.token = (self.db.settings.get("telegram_bot_token") or "").strip()
        if self.token and self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=45))
        if self.token:
            for cand in candidates:
                res = await self.api("getChat", {"chat_id": _to_param(cand)}, timeout=8.0)
                if res and res.get("ok") and res.get("result"):
                    chat_obj = res["result"]
                    api_cid = str(chat_obj.get("id") or cand)
                    break

        if cid == "-1003768452343" and (not clean_title or clean_title in ("-1003768452343", "TheDrunkBots")):
            clean_title = "TheDrunkBots Official"
        elif chat_obj and (not clean_title or clean_title == cid):
            clean_title = chat_obj.get("title") or clean_title or cid
        if not clean_title:
            clean_title = cid

        # Auto-generate a non-expiring permanent invite link when token is available
        need_new_invite = (
            force_new_invite
            or not clean_invite
            or "jU3thxiOiyhmNDFl" in clean_invite
        )
        if self.token and chat_obj and need_new_invite:
            inv_res = await self.api(
                "createChatInviteLink",
                {
                    "chat_id": _to_param(api_cid),
                    "name": f"TheDrunkBots ForceSub ({clean_title[:18]})",
                },
                timeout=8.0,
            )
            if inv_res and inv_res.get("ok") and (inv_res.get("result") or {}).get("invite_link"):
                clean_invite = inv_res["result"]["invite_link"]
            else:
                exp_res = await self.api("exportChatInviteLink", {"chat_id": _to_param(api_cid)}, timeout=8.0)
                if exp_res and exp_res.get("ok") and isinstance(exp_res.get("result"), str):
                    clean_invite = exp_res["result"]
                elif chat_obj.get("invite_link"):
                    clean_invite = chat_obj["invite_link"]
                elif chat_obj.get("username"):
                    clean_invite = f"https://t.me/{chat_obj['username']}"

        if not clean_invite:
            if cid.startswith("@"):
                clean_invite = f"https://t.me/{cid.lstrip('@')}"
            elif cid in ("-1003768452343", "-1004462643599"):
                clean_invite = "https://t.me/+e2xem-7b7-c3ZTM1"
            else:
                clean_invite = self.db.settings.get("updates_channel") or "https://t.me/TheDrunkBots"

        return {
            "chat_id": cid,
            "api_chat_id": api_cid,
            "title": clean_title,
            "invite_link": clean_invite,
        }

    async def sync_all_fsub_channels(self, force_new_invite: bool = False) -> list[dict]:
        raw_channels = list(self.db.settings.get("force_sub_channels") or [])
        if not raw_channels:
            return []
        updated_list = []
        changed = False
        for ch in raw_channels:
            if isinstance(ch, str):
                ch = {"chat_id": ch, "title": ch, "invite_link": ""}
            resolved = await self.resolve_and_prepare_fsub_channel(
                chat_id=str(ch.get("chat_id") or ""),
                title=str(ch.get("title") or ""),
                invite_link=str(ch.get("invite_link") or ""),
                force_new_invite=force_new_invite,
            )
            if resolved != ch:
                changed = True
            updated_list.append(resolved)
        if changed:
            await self.db.update_settings({"force_sub_channels": updated_list}, notify=False)
        return updated_list

    async def check_force_sub(self, user_id: int, force_refresh: bool = False) -> list[dict]:
        """Fast parallel Force-Subscribe check with TTL membership cache (zero lag)."""
        if self.db.is_strict_owner(user_id) or self.db.is_admin(user_id):
            return []
        if not self.db.settings.get("force_sub_enabled", True):
            return []
        channels = list(self.db.settings.get("force_sub_channels") or [])
        if not channels:
            return []

        now_m = time.monotonic()

        async def _check_one(ch_raw: Any) -> dict | None:
            ch = {"chat_id": ch_raw, "title": ch_raw, "invite_link": ""} if isinstance(ch_raw, str) else dict(ch_raw)
            cid = str(ch.get("chat_id") or "").strip()
            if not cid:
                return None
            api_cid = str(ch.get("api_chat_id") or cid).strip()
            if cid == "-1003768452343" and api_cid == "-1003768452343":
                api_cid = "-1004462643599"

            cache_key = (api_cid, int(user_id))
            if not force_refresh and cache_key in self._fsub_member_cache:
                is_joined, ts = self._fsub_member_cache[cache_key]
                if is_joined and (now_m - ts) < 300.0:
                    return None
                if (not is_joined) and (now_m - ts) < 3.0:
                    return {
                        "chat_id": cid,
                        "title": ch.get("title") or "TheDrunkBots Official",
                        "invite_link": ch.get("invite_link") or "https://t.me/+e2xem-7b7-c3ZTM1",
                    }

            param_cid: int | str = int(api_cid) if api_cid.lstrip("-").isdigit() else api_cid
            res = await self.api("getChatMember", {"chat_id": param_cid, "user_id": user_id}, timeout=6.0)
            if (not res or not res.get("ok")) and cid == "-1003768452343" and api_cid != "-1004462643599":
                desc0 = str((res or {}).get("description") or "").lower()
                if "chat not found" in desc0:
                    api_cid = "-1004462643599"
                    cache_key = (api_cid, int(user_id))
                    res = await self.api("getChatMember", {"chat_id": -1004462643599, "user_id": user_id}, timeout=6.0)

            if res and res.get("ok"):
                st = (res.get("result") or {}).get("status", "")
                is_mem = bool((res.get("result") or {}).get("is_member", False))
                if st in ("creator", "administrator", "member") or (st == "restricted" and is_mem):
                    self._fsub_member_cache[cache_key] = (True, now_m)
                    return None
                self._fsub_member_cache[cache_key] = (False, now_m)
            else:
                desc = str((res or {}).get("description") or "").lower()
                # Only bypass check if the bot genuinely lacks access to a custom unknown channel
                if ("chat not found" in desc or "bot is not a member" in desc) and cid not in ("-1003768452343", "-1004462643599"):
                    return None
                self._fsub_member_cache[cache_key] = (False, now_m)

            invite = (ch.get("invite_link") or "").strip()
            if not invite or "jU3thxiOiyhmNDFl" in invite:
                resolved = await self.resolve_and_prepare_fsub_channel(cid, ch.get("title") or "", invite, force_new_invite=True)
                invite = resolved.get("invite_link") or "https://t.me/+e2xem-7b7-c3ZTM1"
            title = ch.get("title") or ("TheDrunkBots Official" if cid == "-1003768452343" else cid)
            return {
                "chat_id": cid,
                "title": title,
                "invite_link": invite,
            }

        results = await asyncio.gather(*(_check_one(c) for c in channels), return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    def build_fsub_prompt(self, missing: list[dict], user: dict | None = None) -> tuple[str, dict]:
        fname = esc((user or {}).get("first_name") or "User")
        ch_lines = []
        rows = []
        pair = []
        for idx, ch in enumerate(missing, 1):
            title = ch.get("title") or f"Channel {idx}"
            inv = ch.get("invite_link") or "https://t.me/+e2xem-7b7-c3ZTM1"
            ch_lines.append(f"• 📢 <b>{esc(title)}</b>")
            btn: dict[str, Any] = {"text": f"📢 Join {title}", "url": inv}
            if len(missing) == 1:
                btn["style"] = "primary"
                rows.append([btn])
            else:
                pair.append(btn)
                if len(pair) == 2:
                    rows.append(pair)
                    pair = []
        if pair:
            rows.append(pair)
        rows.append([{"text": "✅ I Joined — Verify Now", "callback_data": "usr:verify_fsub", "style": "success"}])
        ch_block = "\n".join(ch_lines)
        text = (
            f"🔒 • <b>𝗙𝗢𝗥𝗖𝗘 𝗦𝗨𝗕𝗦𝗖𝗥𝗜𝗕𝗘 𝗥𝗘𝗤𝗨𝗜𝗥𝗘𝗗</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👋 Hey <b>{fname}</b>!\n\n"
            f"<blockquote>⚠️ <b>Access Restricted!</b>\n"
            f"To use this bot and bypass shortlinks at lightning speed, you must join our official channel(s) below first:</blockquote>\n\n"
            f"📌 <b>𝗥𝗘𝗤𝗨𝗜𝗥𝗘𝗗 𝗖𝗛𝗔𝗡𝗡𝗘𝗟(𝗦) :</b>\n"
            f"<blockquote>{ch_block}</blockquote>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"💡 <i>Tap the button below to join, then press <b>“✅ I Joined — Verify Now”</b> to continue instantly!</i>\n"
            f"🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
        )
        return text, {"inline_keyboard": rows}

    # ------------------------------------------------- Polling Loop
    async def _poll_loop(self):
        while self.running:
            try:
                res = await self.api(
                    "getUpdates",
                    {
                        "offset": self._offset,
                        "timeout": 25,
                        "allowed_updates": [
                            "message",
                            "callback_query",
                            "chat_member",
                            "my_chat_member",
                            "chat_join_request",
                        ],
                    },
                    timeout=35.0,
                )
                if not res or not res.get("ok"):
                    await asyncio.sleep(2.0)
                    continue
                for upd in res.get("result") or []:
                    uid = upd.get("update_id", 0)
                    if uid >= self._offset:
                        self._offset = uid + 1
                    asyncio.create_task(self._handle_update(upd))
            except asyncio.CancelledError:
                break
            except Exception as e:
                print("Bot poll error:", e, flush=True)
                await asyncio.sleep(2.0)

    async def _handle_update(self, upd: dict):
        try:
            if "chat_member" in upd:
                cm = upd["chat_member"] or {}
                cid = str((cm.get("chat") or {}).get("id") or "")
                uid = int(((cm.get("new_chat_member") or {}).get("user") or {}).get("id") or 0)
                st = (cm.get("new_chat_member") or {}).get("status", "")
                if cid and uid:
                    joined = st in ("creator", "administrator", "member")
                    self._fsub_member_cache[(cid, uid)] = (joined, time.monotonic())
                return
            if "chat_join_request" in upd:
                cjr = upd["chat_join_request"] or {}
                cid = str((cjr.get("chat") or {}).get("id") or "")
                uid = int((cjr.get("from") or {}).get("id") or 0)
                if cid and uid:
                    self._fsub_member_cache[(cid, uid)] = (True, time.monotonic())
                return
            if "callback_query" in upd:
                await self._on_callback(upd["callback_query"])
            elif "message" in upd:
                await self._on_message(upd["message"])
        except Exception as e:
            print("Update handler error:", e, flush=True)

    # ------------------------------------------------- Message Handler
    async def _on_message(self, msg: dict):
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        from_user = msg.get("from") or {}
        user_id = int(from_user.get("id") or 0)
        msg_id = msg.get("message_id")
        raw_text = msg.get("text") or msg.get("caption") or ""
        text = raw_text.strip()
        if not chat_id or not user_id:
            return

        # Reassemble ultra-long (>4096 char) URLs that Telegram splits across consecutive messages
        split_key = (chat_id, user_id)
        pending_buf = self._split_url_buffers.get(split_key)
        if (
            pending_buf is not None
            and text
            and "http://" not in text.lower()
            and "https://" not in text.lower()
            and re.match(r"^[A-Za-z0-9_+/=?&%-]{8,}$", text)
        ):
            pending_buf["parts"].append(text)
            pending_buf["event"].set()
            return

        ents = msg.get("entities") or msg.get("caption_entities") or []
        has_longer_entity_url = any(
            isinstance(e, dict) and len(str(e.get("url") or "")) > len(raw_text)
            for e in ents
        )
        if (
            len(raw_text) >= 3900
            and not has_longer_entity_url
            and re.search(r"https?://[^\s<>\"']{200,}$", text)
        ):
            ev = asyncio.Event()
            buf = {"parts": [text], "event": ev}
            self._split_url_buffers[split_key] = buf
            try:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(ev.wait(), timeout=1.25)
                if len(buf["parts"]) > 1:
                    ev.clear()
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(ev.wait(), timeout=0.35)
                text = "".join(buf["parts"])
            finally:
                if self._split_url_buffers.get(split_key) is buf:
                    self._split_url_buffers.pop(split_key, None)

        user_doc = await self.db.touch_user(from_user)
        is_adm = self.db.is_admin(user_id)

        if user_doc.get("banned") and not is_adm:
            await self.send_message(
                chat_id,
                "🚫 <b>𝗬𝗢𝗨 𝗔𝗥𝗘 𝗕𝗔𝗡𝗡𝗘𝗗</b>\n<blockquote>You have been restricted from using this bot.</blockquote>",
                reply_to=msg_id,
            )
            return

        if self.db.settings.get("maintenance_mode") and not is_adm:
            await self.send_message(
                chat_id,
                "🛠 <b>𝗠𝗔𝗜𝗡𝗧𝗘𝗡𝗔𝗡𝗖𝗘 𝗠𝗢𝗗𝗘</b>\n<blockquote>The bot is currently under scheduled maintenance. Please try again shortly!</blockquote>",
                reply_to=msg_id,
            )
            return

        # Handle interactive admin state prompts
        if is_adm and user_id in self._admin_states and not text.startswith("/"):
            await self._handle_admin_state_input(chat_id, user_id, msg_id, text)
            return

        # Handle interactive loop-setup state for premium users
        if user_id in self._user_states and not text.startswith("/"):
            await self._handle_loop_state_input(chat_id, user_id, from_user, msg_id, text)
            return

        # Commands
        if text.startswith("/"):
            parts = text.split(maxsplit=1)
            cmd = parts[0].split("@")[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd == "/cancel":
                if is_adm and user_id in self._admin_states:
                    self._admin_states.pop(user_id, None)
                    await self.send_message(chat_id, "✅ <b>Cancelled current action.</b>", reply_to=msg_id)
                    return
                if user_id in self._user_states:
                    self._user_states.pop(user_id, None)
                    await self.send_message(chat_id, "✅ <b>Loop setup cancelled.</b>", reply_to=msg_id)
                    return

            # Force-sub check for non-admin users on all user commands
            if not is_adm:
                missing = await self.check_force_sub(user_id)
                if missing:
                    if cmd in ("/bypass", "/b", "/dl") and arg:
                        self._fsub_pending_urls[user_id] = (URL_RE.findall(arg) or [arg.split()[0]])[:10]
                    f_txt, f_kb = self.build_fsub_prompt(missing, user=from_user)
                    await self.send_message(chat_id, f_txt, reply_to=msg_id, reply_markup=f_kb)
                    return

            if cmd == "/start":
                await self._cmd_start(chat_id, user_id, from_user, msg_id)
                return
            if cmd in ("/premium", "/buy", "/plans", "/upgrade"):
                await self._cmd_buy_premium(chat_id, user_id, from_user, msg_id)
                return
            if cmd in ("/myplan", "/plan", "/subscription"):
                await self._cmd_myplan(chat_id, user_id, from_user, msg_id)
                return
            if cmd == "/help":
                await self._cmd_help(chat_id, user_id, msg_id)
                return
            if cmd in ("/status", "/ping"):
                await self._cmd_status(chat_id, user_id, msg_id)
                return
            if cmd == "/myinfo":
                await self._cmd_myinfo(chat_id, user_doc, msg_id)
                return
            if cmd in ("/loop_setup", "/loopsetup", "/setup_loop", "/loop"):
                try:
                    await self._cmd_loop_setup(chat_id, user_id, from_user, msg_id)
                except Exception as e:
                    print(f"loop_setup error uid={user_id}: {e}", flush=True)
                    await self.send_message(
                        chat_id,
                        f"⚠ Loop setup error: <code>{html.escape(str(e)[:180])}</code>",
                        reply_to=msg_id,
                    )
                return
            if cmd in ("/loop_start", "/loopstart", "/start_loop"):
                try:
                    await self._cmd_loop_start(chat_id, user_id, from_user, msg_id)
                except Exception as e:
                    print(f"loop_start error uid={user_id}: {e}", flush=True)
                    await self.send_message(
                        chat_id,
                        f"⚠ Loop start error: <code>{html.escape(str(e)[:180])}</code>",
                        reply_to=msg_id,
                    )
                return
            if cmd in ("/loop_stop", "/loopstop", "/stop_loop"):
                try:
                    await self._cmd_loop_stop(chat_id, user_id, msg_id)
                except Exception as e:
                    print(f"loop_stop error uid={user_id}: {e}", flush=True)
                    await self.send_message(
                        chat_id,
                        f"⚠ Loop stop error: <code>{html.escape(str(e)[:180])}</code>",
                        reply_to=msg_id,
                    )
                return
            if cmd in ("/loop_status", "/loopstatus", "/status_loop"):
                try:
                    await self._cmd_loop_status(chat_id, user_id, msg_id)
                except Exception as e:
                    print(f"loop_status error uid={user_id}: {e}", flush=True)
                    await self.send_message(
                        chat_id,
                        f"⚠ Loop status error: <code>{html.escape(str(e)[:180])}</code>",
                        reply_to=msg_id,
                    )
                return
            if cmd in ("/bypass", "/b", "/dl"):
                if not arg:
                    await self.send_message(
                        chat_id,
                        "⚡ <b>Usage:</b> <code>/bypass https://lksfy.com/...</code>\n"
                        "<blockquote>Or simply send any shortlink directly in the chat!</blockquote>",
                        reply_to=msg_id,
                    )
                    return
                urls = extract_clean_urls(
                    arg,
                    entities=msg.get("entities") or msg.get("caption_entities"),
                    reply_markup=msg.get("reply_markup"),
                ) or list(dict.fromkeys(URL_RE.findall(arg) or [arg.split()[0]]))
                await asyncio.gather(*(
                    self._process_bypass(chat_id, user_id, from_user, msg_id, u)
                    for u in urls[:50]
                ))
                return

            # Admin-only slash commands
            if is_adm:
                if cmd in ("/admin", "/panel", "/settings"):
                    await self._send_admin_panel(chat_id, msg_id)
                    return
                if cmd in ("/addpremium", "/add_premium"):
                    await self._cmd_addpremium(chat_id, user_id, msg_id, arg)
                    return
                if cmd in ("/removepremium", "/remove_premium", "/delpremium"):
                    await self._cmd_removepremium(chat_id, user_id, msg_id, arg)
                    return
                if cmd in ("/premiumusers", "/premium_users", "/premusers"):
                    await self._cmd_premiumusers(chat_id, user_id, msg_id)
                    return
                if cmd == "/setproxy":
                    await self._cmd_setproxy(chat_id, msg_id, arg)
                    return
                if cmd == "/testproxy":
                    await self._cmd_testproxy(chat_id, msg_id)
                    return
                if cmd == "/addfsub":
                    await self._cmd_addfsub(chat_id, msg_id, arg)
                    return
                if cmd == "/delfsub":
                    await self._cmd_delfsub(chat_id, msg_id, arg)
                    return
                if cmd == "/fsub":
                    await self._cmd_listfsub(chat_id, msg_id)
                    return
                if cmd == "/clearcache":
                    cnt = await self.db.clear_cache()
                    await self.send_message(
                        chat_id,
                        f"🗑 <b>𝗖𝗔𝗖𝗛𝗘 𝗖𝗟𝗘𝗔𝗥𝗘𝗗</b>\n<blockquote>Removed <code>{cnt}</code> cached links from MongoDB & memory.</blockquote>",
                        reply_to=msg_id,
                    )
                    return
                if cmd == "/delcache":
                    if not arg:
                        await self.send_message(chat_id, "Usage: <code>/delcache https://...</code>", reply_to=msg_id)
                        return
                    ok = await self.db.delete_cache(arg)
                    await self.send_message(
                        chat_id,
                        f"{'✅ Deleted' if ok else '⚠️ Not found in'} cache: <code>{esc(arg)}</code>",
                        reply_to=msg_id,
                    )
                    return
                if cmd == "/logs":
                    await self._cmd_logs(chat_id, msg_id)
                    return
                if cmd == "/clearlogs":
                    cnt = await self.db.clear_error_logs()
                    await self.send_message(
                        chat_id,
                        f"🗑 <b>Cleared {cnt} error logs.</b>",
                        reply_to=msg_id,
                    )
                    return
                if cmd == "/stats":
                    await self._cmd_status(chat_id, user_id, msg_id)
                    return
                if cmd == "/ai":
                    if not arg:
                        await self._send_ai_menu(chat_id, msg_id=msg_id)
                    elif self.ai_engineer:
                        urls = [u.rstrip(".,;:!?)>]}") for u in URL_RE.findall(arg)]
                        run_info = await self.ai_engineer.start_run(
                            trigger="telegram_admin",
                            target_url=urls[0] if urls else "",
                            prompt=arg,
                        )
                        await self.send_message(
                            chat_id,
                            f"🤖 • <b>𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗘𝗗 (<code>{esc(run_info.get('id'))}</code>)</b>\n"
                            f"<blockquote>🧠 Analyzing logs, probing shortener origin &amp; running live checks for:\n"
                            f"<code>{esc(arg)}</code>\n\n"
                            f"Watch live step-by-step reasoning in the Web Admin Panel — a full completion report will be sent here automatically!</blockquote>",
                            reply_to=msg_id,
                        )
                    return
                if cmd == "/ban" and arg:
                    try:
                        await self.db.set_user_banned(int(arg), True)
                        await self.send_message(chat_id, f"🚫 Banned user <code>{esc(arg)}</code>", reply_to=msg_id)
                    except Exception:
                        await self.send_message(chat_id, "Usage: <code>/ban user_id</code>", reply_to=msg_id)
                    return
                if cmd == "/unban" and arg:
                    try:
                        await self.db.set_user_banned(int(arg), False)
                        await self.send_message(chat_id, f"✅ Unbanned user <code>{esc(arg)}</code>", reply_to=msg_id)
                    except Exception:
                        await self.send_message(chat_id, "Usage: <code>/unban user_id</code>", reply_to=msg_id)
                    return
                if cmd == "/addadmin" and arg:
                    try:
                        aid = int(arg)
                        admins = list(self.db.settings.get("admin_ids") or [])
                        if aid not in admins:
                            admins.append(aid)
                        await self.db.update_settings({"admin_ids": admins})
                        await self.send_message(chat_id, f"✅ Added admin <code>{aid}</code>", reply_to=msg_id)
                    except Exception:
                        await self.send_message(chat_id, "Usage: <code>/addadmin user_id</code>", reply_to=msg_id)
                    return
                if cmd == "/deladmin" and arg:
                    try:
                        aid = int(arg)
                        admins = [x for x in (self.db.settings.get("admin_ids") or []) if int(x) != aid]
                        await self.db.update_settings({"admin_ids": admins})
                        await self.send_message(chat_id, f"🗑 Removed admin <code>{aid}</code>", reply_to=msg_id)
                    except Exception:
                        await self.send_message(chat_id, "Usage: <code>/deladmin user_id</code>", reply_to=msg_id)
                    return
                if cmd == "/broadcast":
                    reply_msg = msg.get("reply_to_message")
                    b_text = arg or ((reply_msg or {}).get("text") or "")
                    if not b_text:
                        await self.send_message(
                            chat_id,
                            "📢 <b>Usage:</b> <code>/broadcast Your message here</code> (or reply to a message with <code>/broadcast</code>)",
                            reply_to=msg_id,
                        )
                        return
                    await self._run_broadcast(chat_id, msg_id, b_text)
                    return

        # Direct link sent in chat (including text_link entities and forwarded inline button URLs)
        urls = extract_clean_urls(
            text,
            entities=msg.get("entities") or msg.get("caption_entities"),
            reply_markup=msg.get("reply_markup"),
        )
        if urls:
            if not is_adm:
                missing = await self.check_force_sub(user_id)
                if missing:
                    self._fsub_pending_urls[user_id] = urls[:50]
                    f_txt, f_kb = self.build_fsub_prompt(missing, user=from_user)
                    await self.send_message(chat_id, f_txt, reply_to=msg_id, reply_markup=f_kb)
                    return
            await asyncio.gather(*(
                self._process_bypass(chat_id, user_id, from_user, msg_id, u)
                for u in urls[:50]
            ))

    def _build_protected_link_response(self) -> tuple[str, dict]:
        msg_txt = (self.db.settings.get("protected_message") or DEFAULT_PROTECTED_MESSAGE).replace("@DrunkBots", "@TheDrunkBots")
        upd_chan = (self.db.settings.get("updates_channel") or "https://t.me/TheDrunkBots").strip()
        if upd_chan.startswith("@"):
            upd_chan = f"https://t.me/{upd_chan.lstrip('@')}"
        elif not upd_chan.startswith("http"):
            upd_chan = "https://t.me/TheDrunkBots"
        kb = {
            "inline_keyboard": [
                [
                    {"text": "📢 Updates Channel", "url": upd_chan, "style": "primary"},
                    {"text": "🏠 Back to Home", "callback_data": "usr:start"},
                ],
            ]
        }
        return msg_txt, kb

    def _build_subscription_required_response(self, access_info: dict, user: dict | None = None) -> tuple[str, dict]:
        first_name = esc((user or {}).get("first_name") or "User")
        contact_url = self._get_contact_admin_url()
        plans = self.db.get_premium_plans(only_enabled=True)
        plan_lines = []
        for p in plans:
            amt = p.get("amount", 0)
            amt_str = int(amt) if amt == int(amt) else amt
            plan_lines.append(f"• 💎 <b>{esc(p.get('name'))} ({p.get('days')} Days)</b> — <code>₹{amt_str}</code>")
        plans_block = "\n".join(plan_lines) if plan_lines else "• 💎 <b>1 Month (30 Days)</b> — <code>₹100</code>"

        reason = access_info.get("reason") or "free_trial_exhausted"
        free_used = int(access_info.get("free_used") or 3)
        free_limit = int(access_info.get("free_limit") or 3)

        if reason == "premium_expired":
            exp_str = access_info.get("expired_str") or "Recently"
            plan_lbl = access_info.get("plan_label") or access_info.get("plan_type") or "Premium Plan"
            text = (
                f"🔒 • <b>𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗦𝗨𝗕𝗦𝗖𝗥𝗜𝗣𝗧𝗜𝗢𝗡 𝗘𝗫𝗣𝗜𝗥𝗘𝗗</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👋 Hey <b>{first_name}</b>!\n\n"
                f"<blockquote>⏰ <b>Your Premium Subscription Has Expired!</b>\n"
                f"• <b>Previous Plan :</b> <code>{esc(plan_lbl)}</code>\n"
                f"• <b>Expired On :</b> <code>{esc(exp_str)}</code>\n"
                f"• <b>Lifetime Free Uses :</b> <code>{free_used}/{free_limit} Used</code>\n\n"
                f"Renew your Premium membership below to continue bypassing shortlinks with <b>unlimited access &amp; zero limits</b>!</blockquote>\n\n"
                f"💎 <b>𝗔𝗩𝗔𝗜𝗟𝗔𝗕𝗟𝗘 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗣𝗟𝗔𝗡𝗦 :</b>\n"
                f"<blockquote>{plans_block}</blockquote>\n"
                f"<blockquote>⚡ <b>100% Automated Activation:</b> Tap <b>“💎 Buy Premium”</b> below, scan the UPI QR code, and your plan activates automatically within seconds!</blockquote>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
            )
        else:
            text = (
                f"🔒 • <b>𝗦𝗨𝗕𝗦𝗖𝗥𝗜𝗣𝗧𝗜𝗢𝗡 𝗥𝗘𝗤𝗨𝗜𝗥𝗘𝗗</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👋 Hey <b>{first_name}</b>!\n\n"
                f"<blockquote>🎁 <b>Free Trial Limit Reached ({free_used}/{free_limit} Used)!</b>\n"
                f"You have used all <b>{free_limit} lifetime free link bypasses</b> available on your account.\n\n"
                f"To continue bypassing shortlinks at lightning speed with <b>unlimited access &amp; zero restrictions</b>, please purchase a Premium Plan!</blockquote>\n\n"
                f"💎 <b>𝗔𝗩𝗔𝗜𝗟𝗔𝗕𝗟𝗘 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗣𝗟𝗔𝗡𝗦 :</b>\n"
                f"<blockquote>{plans_block}</blockquote>\n"
                f"<blockquote>⚡ <b>100% Automated Activation:</b> Tap <b>“💎 Buy Premium”</b> below, scan the dynamic UPI QR code, and your plan activates automatically!</blockquote>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
            )

        kb = {
            "inline_keyboard": [
                [{"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"}],
                [
                    {"text": "👑 My Plan", "callback_data": "usr:myplan"},
                    {"text": "👨‍💻 Contact Admin", "url": contact_url},
                ],
                [{"text": "🏠 Back to Home", "callback_data": "usr:start"}],
            ]
        }
        return text, kb

    # ------------------------------------------------- Bypass Flow (Screenshots UI)
    async def _process_bypass(self, chat_id: int, user_id: int, from_user: dict, reply_to: int, raw_url: str):
        url = norm_url(raw_url)
        await self.db.touch_user(from_user, increment_bypass=False)

        # 0. Check Protected Bots & Links Shield BEFORE consuming any free slot!
        prot_src = self.db.check_protected_source_url(url)
        if prot_src:
            p_txt, p_kb = self._build_protected_link_response()
            await self.send_message(chat_id, p_txt, reply_to=reply_to, reply_markup=p_kb)
            return

        # 0.5 Check Premium / 3-Lifetime-Free-Uses Access Quota!
        access = await self.db.try_consume_access_slot(user_id, is_admin=self.db.is_admin(user_id))
        if not access.get("allowed"):
            sub_Set = getattr(self, "_sub_notified_replies", None)
            if sub_Set is None:
                sub_Set = set()
                self._sub_notified_replies = sub_Set
            dedup_key = (chat_id, int(reply_to or 0))
            if reply_to and dedup_key in sub_Set:
                return
            if reply_to:
                sub_Set.add(dedup_key)
                if len(sub_Set) > 500:
                    sub_Set.clear()
            s_txt, s_kb = self._build_subscription_required_response(access, user=from_user)
            await self.send_message(chat_id, s_txt, reply_to=reply_to, reply_markup=s_kb)
            return

        consumed_free = bool(access.get("consumed_free_slot"))
        await self.db.touch_user(from_user, increment_bypass=True)

        # 1. Check MongoDB / Memory Cloud Cache first!
        hit = await self.db.get_cache(url, force=False)
        if hit and hit.get("url"):
            dest_url = hit["url"]
            extra_links = list(hit.get("extra_links") or [])
            if not extra_links and "pastelink.net/" in dest_url.lower():
                try:
                    from .engine import extract_pastelink_links
                    extra_links = await extract_pastelink_links(dest_url)
                except Exception:
                    pass
            prot_dest = self.db.check_protected_destination_url(dest_url, source_url=url)
            if not prot_dest and extra_links:
                for ex_u in extra_links:
                    prot_dest = self.db.check_protected_destination_url(ex_u, source_url=url)
                    if prot_dest:
                        break
            if prot_dest:
                if consumed_free:
                    await self.db.refund_free_slot(user_id)
                p_txt, p_kb = self._build_protected_link_response()
                await self.send_message(chat_id, p_txt, reply_to=reply_to, reply_markup=p_kb)
                return
            msg_text = format_success_message(raw_url, dest_url, 0.01, cached=True, extra_links=extra_links)
            rows = [
                [
                    {"text": "COPY LINK 📋", "copy_text": {"text": dest_url}},
                    {"text": "OPEN LINK ↗️", "url": dest_url, "style": "success"},
                ]
            ]
            if extra_links:
                pair_btns = []
                for idx_e, ex_u in enumerate(extra_links[:8], 1):
                    pair_btns.append({"text": f"OPEN #{idx_e} ↗️", "url": ex_u})
                    if len(pair_btns) == 2:
                        rows.append(pair_btns)
                        pair_btns = []
                if pair_btns:
                    rows.append(pair_btns)
            if consumed_free:
                msg_text += (
                    f"\n<blockquote>🎁 <b>𝗙𝗥𝗘𝗘 𝗧𝗥𝗜𝗔𝗟 :</b> "
                    f"<code>{access['free_used']}/{access['free_limit']} Used ({access['free_left']} Left)</code></blockquote>"
                )
                rows.append([{"text": "💎 Upgrade to Unlimited Premium", "callback_data": "usr:premium", "style": "primary"}])
            await self.send_message(chat_id, msg_text, reply_to=reply_to, reply_markup={"inline_keyboard": rows})
            return

        # 2. Launch solver immediately & send live progress message (matches image-2.png!)
        # Jobs run in parallel across isolated sessions/workers, so no single-file queue wait!
        t0 = time.monotonic()
        now_m = t0
        base_est = estimate_duration(url)
        for j_uid, (j_t0, j_est) in list(self._active_jobs.items()):
            # If the exact same URL is already in-flight, share its remaining time
            if j_uid.startswith(url + "|"):
                rem_same = max(4.0, j_est - (now_m - j_t0))
                base_est = rem_same
                break
        est_total = base_est
        job_track_id = f"{url}|{chat_id}:{reply_to}:{now_m}:{id(from_user)}:{time.time_ns()}"
        self._active_jobs[job_track_id] = [now_m, base_est]

        step_state: dict[str, Any] = {
            "pct_floor": 10,
            "done": False,
            "started_at": t0,
            "reached_final": False,
            "rem_at": None,  # (monotonic_ts, seconds_remaining)
        }
        log_lines: list[str] = []

        def on_log(line: str):
            now_l = time.monotonic()
            low = line.lower()
            if step_state["started_at"] is None:
                step_state["started_at"] = now_l
            step_state["pct_floor"] = max(step_state["pct_floor"], 14)
            elapsed_now = now_l - (step_state["started_at"] or t0)
            log_lines.append(f"[{elapsed_now:5.1f}s] {line}")

            m_wait = re.search(
                r"waiting\s+(\d+)s\b|server\s+timer\s+(\d+)s\s+left",
                low,
            )
            if m_wait:
                sec = float(m_wait.group(1) or m_wait.group(2) or 0)
                if sec > 0:
                    extra = 9.0 if "arolinks" in low else 12.0
                    step_state["rem_at"] = (now_l, sec + extra)
                    self._active_jobs[job_track_id] = [now_l, sec + extra]

            if "reached the shortener's final page" in low:
                step_state["reached_final"] = True
                step_state["pct_floor"] = max(step_state["pct_floor"], 86)
                step_state["rem_at"] = (now_l, 6.0)
                self._active_jobs[job_track_id] = [now_l, 6.0]
            elif "following final redirect" in low or "links/go api" in low:
                step_state["reached_final"] = True
                step_state["pct_floor"] = max(step_state["pct_floor"], 95)
                step_state["rem_at"] = (now_l, 2.0)
            elif "final link obtained" in low or "final link found" in low or "jumping to safelink" in low:
                step_state["pct_floor"] = max(step_state["pct_floor"], 72)
                step_state["rem_at"] = (now_l, 11.0)
            elif "turnstile solved" in low:
                step_state["pct_floor"] = max(step_state["pct_floor"], 64)
            elif "submitting safelink form" in low or "click" in low or "shortcut" in low:
                step_state["pct_floor"] = min(78, step_state["pct_floor"] + 10)

        # Start solving immediately at 0.00s in parallel with sending the progress message
        resolve_task = asyncio.create_task(
            self.resolve_fn(
                url,
                force=False,
                origin="telegram",
                user_id=user_id,
                username=from_user.get("username"),
                extra_log_cb=on_log,
            )
        )

        # Give fast direct solvers / cache hits 0.28s to finish before creating a "Processing" message.
        # In large batches (>8 simultaneous links in the same chat), skip creating separate "Fetching"
        # messages for links 9..50 so Telegram per-chat rate budget is 100% reserved for final results!
        await asyncio.sleep(0.28)
        prog_msg_id = None
        same_chat_now = sum(1 for k in self._active_jobs if f"|{chat_id}:" in k)
        if (
            not resolve_task.done()
            and same_chat_now <= 8
            and time.monotonic() >= self._chat_flood_until.get(chat_id, 0.0)
        ):
            init_text = format_fetching_message(8, 0.3, est_total)
            sent = await self.send_message(chat_id, init_text, reply_to=reply_to, is_progress=True)
            prog_msg_id = ((sent or {}).get("result") or {}).get("message_id")

        async def _deliver_final(final_text: str, reply_markup: dict | None = None):
            step_state["final_sent"] = True
            if prog_msg_id:
                res_ed = await self.edit_message(
                    chat_id,
                    prog_msg_id,
                    final_text,
                    reply_markup=reply_markup,
                    is_progress=False,
                )
                if res_ed and (res_ed.get("ok") or res_ed.get("not_modified")):
                    return
                # If editing the progress message failed (e.g. deleted or stale), send a fresh message and delete prog_msg_id only if sent
                sent_final = await self.send_message(
                    chat_id,
                    final_text,
                    reply_to=reply_to,
                    reply_markup=reply_markup,
                )
                if sent_final and sent_final.get("ok"):
                    with contextlib.suppress(Exception):
                        await self.api("deleteMessage", {"chat_id": chat_id, "message_id": prog_msg_id}, is_progress=True)
            else:
                await self.send_message(
                    chat_id,
                    final_text,
                    reply_to=reply_to,
                    reply_markup=reply_markup,
                )

        async def updater():
            import random as _rnd

            last_pct = 8
            while not step_state["done"] and prog_msg_id:
                same_chat_cnt = max(1, sum(1 for k in self._active_jobs if f"|{chat_id}:" in k))
                # Adaptive anti-FloodWait interval: >= 7.5s for 1 link, scales with concurrent links in chat
                sleep_interval = max(7.5, 3.8 * same_chat_cnt) + _rnd.uniform(0.25, 1.35)
                await asyncio.sleep(sleep_interval)
                if step_state["done"]:
                    break
                # When > 8 links are running simultaneously in the same chat or chat is in FloodWait,
                # skip cosmetic progress edits so 100% of Telegram rate budget goes to final results!
                if same_chat_cnt > 8 or time.monotonic() < self._chat_flood_until.get(chat_id, 0.0):
                    continue
                now_u = time.monotonic()
                el = now_u - t0
                started_at = step_state["started_at"] or t0
                active_el = now_u - started_at
                if step_state["rem_at"] is not None:
                    r_t0, r_sec = step_state["rem_at"]
                    rem = max(3.0 if step_state["reached_final"] else 8.0, r_sec - (now_u - r_t0))
                    total_proj = active_el + rem
                    time_pct = int(min(92, (active_el / max(8.0, total_proj)) * 90))
                else:
                    rem = max(3.0 if step_state["reached_final"] else 9.0, base_est - active_el)
                    time_pct = int(min(88, (active_el / max(8.0, base_est)) * 84))
                cap = 96 if step_state["reached_final"] else 84
                pct = max(last_pct + 1, time_pct, step_state["pct_floor"])
                pct = min(cap, pct)
                last_pct = pct
                try:
                    await self.edit_message(
                        chat_id,
                        prog_msg_id,
                        format_fetching_message(pct, el, rem),
                        is_progress=True,
                    )
                except Exception:
                    pass

        upd_task = asyncio.create_task(updater()) if prog_msg_id else None
        try:
            res = await resolve_task
            step_state["done"] = True
            if upd_task:
                upd_task.cancel()
                with contextlib.suppress(BaseException):
                    await upd_task
            self._active_jobs.pop(job_track_id, None)

            dest_url = res["url"]
            extra_links = list(res.get("extra_links") or [])
            if not extra_links and "pastelink.net/" in dest_url.lower():
                try:
                    from .engine import extract_pastelink_links
                    extra_links = await extract_pastelink_links(dest_url)
                except Exception:
                    pass
            prot_dest = self.db.check_protected_destination_url(dest_url, source_url=url)
            if not prot_dest and extra_links:
                for ex_u in extra_links:
                    prot_dest = self.db.check_protected_destination_url(ex_u, source_url=url)
                    if prot_dest:
                        break
            if prot_dest:
                if consumed_free:
                    await self.db.refund_free_slot(user_id)
                p_txt, p_kb = self._build_protected_link_response()
                await _deliver_final(p_txt, reply_markup=p_kb)
                return

            elapsed = float(res.get("elapsed") or round(time.monotonic() - t0, 2))
            is_cached = bool(res.get("cached"))
            final_text = format_success_message(raw_url, dest_url, elapsed, cached=is_cached, extra_links=extra_links)
            rows = [
                [
                    {"text": "COPY LINK 📋", "copy_text": {"text": dest_url}},
                    {"text": "OPEN LINK ↗️", "url": dest_url, "style": "success"},
                ]
            ]
            if extra_links:
                pair_btns = []
                for idx_e, ex_u in enumerate(extra_links[:8], 1):
                    pair_btns.append({"text": f"OPEN #{idx_e} ↗️", "url": ex_u})
                    if len(pair_btns) == 2:
                        rows.append(pair_btns)
                        pair_btns = []
                if pair_btns:
                    rows.append(pair_btns)
            if consumed_free:
                final_text += (
                    f"\n<blockquote>🎁 <b>𝗙𝗥𝗘𝗘 𝗧𝗥𝗜𝗔𝗟 :</b> "
                    f"<code>{access['free_used']}/{access['free_limit']} Used ({access['free_left']} Left)</code></blockquote>"
                )
                rows.append([{"text": "💎 Upgrade to Unlimited Premium", "callback_data": "usr:premium", "style": "primary"}])
            kb = {"inline_keyboard": rows}
            await _deliver_final(final_text, reply_markup=kb)
        except ProtectedLinkError:
            step_state["done"] = True
            if upd_task:
                upd_task.cancel()
                with contextlib.suppress(BaseException):
                    await upd_task
            self._active_jobs.pop(job_track_id, None)
            if consumed_free:
                await self.db.refund_free_slot(user_id)
            p_txt, p_kb = self._build_protected_link_response()
            await _deliver_final(p_txt, reply_markup=p_kb)
        except Exception:
            step_state["done"] = True
            if upd_task:
                upd_task.cancel()
                with contextlib.suppress(BaseException):
                    await upd_task
            self._active_jobs.pop(job_track_id, None)
            if consumed_free:
                await self.db.refund_free_slot(user_id)
            err_text = format_user_error_message(raw_url)
            await _deliver_final(err_text)
        finally:
            step_state["done"] = True
            if upd_task and not upd_task.done():
                upd_task.cancel()
            self._active_jobs.pop(job_track_id, None)
            if prog_msg_id and not step_state.get("final_sent"):
                with contextlib.suppress(Exception):
                    await _deliver_final(format_user_error_message(raw_url))

    # ------------------------------------------------- User Commands
    async def _cmd_start(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int | None = None,
        edit_id: int | None = None,
    ):
        brand = self.db.settings.get("brand_name") or DEFAULT_BRAND
        photo = (self.db.settings.get("start_photo") or DEFAULT_START_PHOTO).strip()
        tpl = self.db.settings.get("welcome_message") or ""
        first_name = esc(from_user.get("first_name") or "User")
        body = (
            tpl.replace("<code>{brand}</code>", "@TheDrunkBots")
            .replace("<code>TheDrunkBots</code>", "@TheDrunkBots")
            .replace("<code>DrunkBots</code>", "@TheDrunkBots")
            .replace("@DrunkBots", "@TheDrunkBots")
            .replace("{first_name}", first_name)
            .replace("{brand}", "@TheDrunkBots")
        )
        body = re.sub(
            r"(𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬\s*:\s*</b>\s*)(?:<code>)?@?(?:The)?DrunkBots(?:</code>)?",
            r"\1@TheDrunkBots",
            body,
        )
        caption = (
            f"🍹 • <b>𝗪𝗘𝗟𝗖𝗢𝗠𝗘 𝗧𝗢 {esc(brand.upper())}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{body}"
        )
        upd_chan = (self.db.settings.get("updates_channel") or "https://t.me/TheDrunkBots").strip()
        if upd_chan.startswith("@"):
            upd_chan = f"https://t.me/{upd_chan.lstrip('@')}"
        elif not upd_chan.startswith("http"):
            upd_chan = "https://t.me/TheDrunkBots"

        rows = [
            [
                {"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"},
                {"text": "👑 My Plan", "callback_data": "usr:myplan"},
            ],
            [
                {"text": "🔁 Loop Setup", "callback_data": "loop:setup", "style": "primary"},
                {"text": "▶️ Start Loop", "callback_data": "loop:start", "style": "success"},
            ],
            [
                {"text": "⏹ Stop Loop", "callback_data": "loop:stop"},
                {"text": "📊 Loop Status", "callback_data": "loop:status"},
            ],
            [
                {"text": "⚡ How To Use", "callback_data": "usr:help"},
                {"text": "📊 Bot Stats", "callback_data": "usr:status"},
            ],
            [
                {"text": "👤 My Profile", "callback_data": "usr:myinfo"},
                {"text": "📢 Updates Channel", "url": upd_chan},
            ],
        ]
        if self.db.is_admin(user_id):
            rows.append([{"text": "🛠 Admin Control Panel", "callback_data": "adm:home", "style": "primary"}])

        kb = {"inline_keyboard": rows}
        if edit_id:
            await self.edit_message(chat_id, edit_id, caption, reply_markup=kb)
        else:
            await self.send_photo(chat_id, photo, caption, reply_to=msg_id, reply_markup=kb)

    async def _cmd_help(self, chat_id: int, user_id: int, msg_id: int | None = None, edit_id: int | None = None):
        brand = self.db.settings.get("brand_name") or DEFAULT_BRAND
        txt = (
            f"📖 • <b>𝗛𝗢𝗪 𝗧𝗢 𝗨𝗦𝗘 ({esc(brand)})</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>1️⃣ <b>Send any shortlink</b> directly in this chat (or use <code>/bypass &lt;link&gt;</code>).\n"
            f"2️⃣ Watch the <b>live progress bar &amp; ETA</b> while our cloud browser bypasses ads, timers &amp; captchas.\n"
            f"3️⃣ Receive your <b>direct destination link</b> with one-tap <b>COPY LINK 📋</b> &amp; <b>OPEN LINK ↗️</b> buttons!\n"
            f"4️⃣ <b>Premium Loop Mode:</b> <code>/loop_setup</code> → set links + cycles → <code>/loop_start</code> "
            f"(continuous no-cache processing, max 3 concurrent, 3–5s random gap)</blockquote>\n\n"
            f"🔗 <b>𝗦𝗨𝗣𝗣𝗢𝗥𝗧𝗘𝗗 𝗦𝗛𝗢𝗥𝗧𝗘𝗡𝗘𝗥𝗦 :</b>\n"
            f"<blockquote>• <code>gplinks.co</code> • <code>exeygo.com</code> • <code>arolinks.com</code>\n"
            f"• <code>vplink.in</code> • <code>get2short.com</code> • <code>droplink.co</code>\n"
            f"• <code>babylinks.in</code> • <code>liteshort.com</code> • <code>lksfy.com</code>\n"
            f"• <code>shortwala.com</code> • <code>softurl.in</code> • <code>earnlinks.in</code>\n"
            f"• <code>urllinkshort.in</code> • <code>linksfire.co</code> • <code>alpha-links.in</code>\n"
            f"• <code>nowshort.com</code> • <code>linksflys.com</code> &amp; all WP Safelink blogs!</blockquote>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
        )
        rows = [
            [
                {"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"},
                {"text": "🏠 Back to Home", "callback_data": "usr:start"},
            ],
        ]
        if self.db.is_admin(user_id):
            rows.append([{"text": "🛠 Admin Control Panel", "callback_data": "adm:home", "style": "primary"}])
        kb = {"inline_keyboard": rows}
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _cmd_status(self, chat_id: int, user_id: int, msg_id: int | None = None, edit_id: int | None = None):
        brand = self.db.settings.get("brand_name") or DEFAULT_BRAND
        sh_list = self.db.get_shortener_tunnel_list()
        domains = [s.get("domain") for s in sh_list if s.get("domain")]
        site_lines = []
        for i in range(0, len(domains), 3):
            chunk = domains[i : i + 3]
            site_lines.append(" • ".join(f"<code>{esc(d)}</code>" for d in chunk))
        sites_block = "\n".join(site_lines)

        is_owner = self.db.is_strict_owner(user_id)
        txt = (
            f"📊 • <b>𝗕𝗢𝗧 𝗦𝗧𝗔𝗧𝗦 &amp; 𝗦𝗨𝗣𝗣𝗢𝗥𝗧𝗘𝗗 𝗦𝗜𝗧𝗘𝗦 ({esc(brand)})</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>⚡ <b>Bot Status :</b> <code>🟢 Online</code></blockquote>\n\n"
            f"🌐 <b>𝗪𝗢𝗥𝗞𝗜𝗡𝗚 𝗦𝗨𝗣𝗣𝗢𝗥𝗧𝗘𝗗 𝗦𝗜𝗧𝗘𝗦 ({len(domains)}+) :</b>\n"
            f"<blockquote>{sites_block}</blockquote>"
        )
        rows = [
            [
                {"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"},
                {"text": "🏠 Back to Home", "callback_data": "usr:start"},
            ],
        ]
        if is_owner:
            st = self.db.settings.get("stats") or {}
            cache_count = len(self.db.local_cache)
            users_count = len(self.db.local_users)
            px_on = bool(self.db.settings.get("proxy"))
            px_exp = bool(self.db.settings.get("proxy_expired"))
            px_status = "🟢 Active Tunnel" if (px_on and not px_exp) else ("🔴 Expired Tunnel" if px_exp else "🟡 Direct Connection")
            mongo_status = "🟢 Connected (Atlas)" if self.db.connected else "🟡 Local Fallback"
            cache_status = "🟢 Enabled" if self.db.settings.get("cache_enabled", True) else "🔴 Disabled"
            ai_on = "🟢 Auto-Heal Active" if self.db.settings.get("ai_auto_heal", True) else "⚪ Manual"
            txt += (
                f"\n👑 <b>𝗢𝗪𝗡𝗘𝗥 𝗦𝗬𝗦𝗧𝗘𝗠 &amp; 𝗖𝗟𝗢𝗨𝗗 𝗠𝗘𝗧𝗥𝗜𝗖𝗦 :</b>\n"
                f"<blockquote>🗄 <b>MongoDB :</b> <code>{mongo_status}</code>\n"
                f"🚀 <b>Cloud Cache :</b> <code>{cache_status} ({cache_count} links)</code>\n"
                f"⚡ <b>Cache Hits :</b> <code>{st.get('cache_hits', 0)}</code>\n"
                f"✅ <b>Total Bypassed :</b> <code>{st.get('total_bypasses', 0)}</code>\n"
                f"👥 <b>Total Users :</b> <code>{users_count}</code>\n"
                f"🌐 <b>Tunnel :</b> <code>{px_status}</code>\n"
                f"🤖 <b>AI Engineer :</b> <code>{ai_on} ({st.get('ai_fixes', 0)} fixes)</code></blockquote>"
            )
        if self.db.is_admin(user_id):
            rows.append([{"text": "🛠 Admin Control Panel", "callback_data": "adm:home", "style": "primary"}])
        txt += "\n━━━━━━━━━━━━━━━━━━━━━━\n🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
        kb = {"inline_keyboard": rows}
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _cmd_myinfo(self, chat_id: int, user_doc: dict, msg_id: int | None = None, edit_id: int | None = None):
        uid = int(user_doc.get("user_id") or 0)
        pstat = self.db.get_user_premium_status(uid)
        if self.db.is_admin(uid):
            role = "👑 Owner / Admin (Unlimited)"
            plan_line = "👑 Unlimited Admin Access"
        elif pstat.get("is_premium"):
            role = "💎 Premium Member"
            plan_line = f"{esc(pstat.get('plan_label') or 'Premium')} (Expires: {esc(pstat.get('expiry_str'))})"
        else:
            role = "👤 Free Trial User"
            plan_line = f"🎁 Free Trial ({pstat.get('free_used')}/{pstat.get('free_limit')} Used — {pstat.get('free_left')} Left)"

        contact_url = self._get_contact_admin_url()
        txt = (
            f"👤 • <b>𝗬𝗢𝗨𝗥 𝗣𝗥𝗢𝗙𝗜𝗟𝗘 &amp; 𝗣𝗟𝗔𝗡</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>🆔 <b>𝗨𝗦𝗘𝗥 𝗜𝗗 :</b> <code>{uid}</code>\n"
            f"🏷 <b>𝗡𝗔𝗠𝗘 :</b> <code>{esc(user_doc.get('first_name') or 'User')}</code>\n"
            f"🎖 <b>𝗥𝗢𝗟𝗘 :</b> <code>{role}</code>\n"
            f"💎 <b>𝗣𝗟𝗔𝗡 𝗦𝗧𝗔𝗧𝗨𝗦 :</b> <code>{plan_line}</code>\n"
            f"🔗 <b>𝗟𝗜𝗡𝗞𝗦 𝗕𝗬𝗣𝗔𝗦𝗦𝗘𝗗 :</b> <code>{user_doc.get('bypass_count', 0)}</code></blockquote>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
        )
        rows = [
            [
                {"text": "💎 Upgrade Premium", "callback_data": "usr:premium", "style": "success"},
                {"text": "👑 My Plan", "callback_data": "usr:myplan"},
            ],
            [
                {"text": "👨‍💻 Contact Admin", "url": contact_url},
                {"text": "🏠 Back to Home", "callback_data": "usr:start"},
            ],
        ]
        if self.db.is_admin(uid):
            rows.append([{"text": "🛠 Admin Control Panel", "callback_data": "adm:home", "style": "primary"}])
        kb = {"inline_keyboard": rows}
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    # ------------------------------------------------- Loop Mode (Premium)
    async def _cmd_loop_setup(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int | None = None,
    ):
        pstat = self.db.get_user_premium_status(user_id)
        if not pstat.get("is_premium") and not self.db.is_admin(user_id):
            await self.send_message(
                chat_id,
                "💎 <b>Loop Mode is Premium-only</b>\n"
                "<blockquote>This feature lets you continuously process 1 or multiple links in a loop "
                "(no cache, concurrent 1–5 of your choice, random 3–5s gap between cycles).\n\n"
                "Upgrade to Premium to unlock /loop_setup.</blockquote>",
                reply_to=msg_id,
                reply_markup={
                    "inline_keyboard": [
                        [{"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"}]
                    ]
                },
            )
            return

        self._user_states[user_id] = {"step": "links", "chat_id": chat_id}
        await self.send_message(
            chat_id,
            "🔁 <b>Loop Mode Setup</b>\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "<blockquote>Send <b>1 or more shortlinks</b> that you want the bot to process continuously.\n\n"
            "• One link per line <b>or</b> space/comma separated\n"
            "• Max 20 links recommended\n"
            "• These will be processed <b>without cache</b> (always live bypass)\n"
            "• You can set <b>how many links run at the same time</b> (1–5)\n"
            "• After each full cycle → random <b>3–5 second</b> gap, then repeat</blockquote>\n\n"
            "Send your links now (or /cancel to abort):",
            reply_to=msg_id,
        )

    async def _handle_loop_state_input(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int,
        text: str,
    ):
        state = self._user_states.get(user_id) or {}
        step = state.get("step")

        if step == "links":
            urls = extract_clean_urls(text) or list(dict.fromkeys(URL_RE.findall(text)))
            urls = [u for u in urls if u][:20]
            if not urls:
                await self.send_message(
                    chat_id,
                    "❌ No valid links found. Please send at least one shortlink (http/https).\n"
                    "Or send /cancel to abort.",
                    reply_to=msg_id,
                )
                return
            state["links"] = urls
            state["step"] = "times"
            self._user_states[user_id] = state
            links_preview = "\n".join(
                f"• <code>{html.escape(u[:80])}{'…' if len(u) > 80 else ''}</code>" for u in urls[:8]
            )
            if len(urls) > 8:
                links_preview += f"\n• … and {len(urls) - 8} more"
            await self.send_message(
                chat_id,
                f"✅ <b>{len(urls)} link(s) saved</b>\n"
                f"<blockquote>{links_preview}</blockquote>\n\n"
                "Now send the <b>number of cycles</b> (how many times to repeat the full list):\n"
                "• Example: <code>10</code> → process the list 10 times\n"
                "• Send <code>0</code> for unlimited (until you /loop_stop)\n\n"
                "Or /cancel to abort.",
                reply_to=msg_id,
            )
            return

        if step == "times":
            try:
                times = int(text.strip().split()[0])
                if times < 0:
                    raise ValueError
            except Exception:
                await self.send_message(
                    chat_id,
                    "❌ Please send a non-negative integer (e.g. <code>5</code> or <code>0</code> for unlimited).\n"
                    "Or /cancel to abort.",
                    reply_to=msg_id,
                )
                return
            state["times"] = times
            state["step"] = "concurrency"
            self._user_states[user_id] = state
            times_label = "Unlimited (until /loop_stop)" if times == 0 else str(times)
            await self.send_message(
                chat_id,
                f"✅ Cycles set: <code>{times_label}</code>\n\n"
                "⚡ <b>How many links should run at the same time?</b>\n"
                "<blockquote>Choose concurrency (parallel processing):\n"
                "• <code>1</code> → one-by-one (slowest, safest)\n"
                "• <code>2</code> → 2 together\n"
                "• <code>3</code> → 3 together (default)\n"
                "• <code>4</code> → 4 together\n"
                "• <code>5</code> → 5 together (fastest)</blockquote>\n\n"
                "Tap a button below <b>or</b> send a number <code>1</code>–<code>5</code>.\n"
                "Or /cancel to abort.",
                reply_to=msg_id,
                reply_markup={
                    "inline_keyboard": [
                        [
                            {"text": "1", "callback_data": "loop:conc:1"},
                            {"text": "2", "callback_data": "loop:conc:2"},
                            {"text": "3 ⭐", "callback_data": "loop:conc:3"},
                            {"text": "4", "callback_data": "loop:conc:4"},
                            {"text": "5", "callback_data": "loop:conc:5"},
                        ]
                    ]
                },
            )
            return

        if step == "concurrency":
            try:
                conc = int(text.strip().split()[0])
                if conc < 1 or conc > 5:
                    raise ValueError
            except Exception:
                await self.send_message(
                    chat_id,
                    "❌ Please send a number between <code>1</code> and <code>5</code> "
                    "(how many links to process at once).\n"
                    "Or /cancel to abort.",
                    reply_to=msg_id,
                    reply_markup={
                        "inline_keyboard": [
                            [
                                {"text": "1", "callback_data": "loop:conc:1"},
                                {"text": "2", "callback_data": "loop:conc:2"},
                                {"text": "3 ⭐", "callback_data": "loop:conc:3"},
                                {"text": "4", "callback_data": "loop:conc:4"},
                                {"text": "5", "callback_data": "loop:conc:5"},
                            ]
                        ]
                    },
                )
                return
            await self._finish_loop_setup(chat_id, user_id, state, conc, msg_id)
            return

        self._user_states.pop(user_id, None)

    async def _finish_loop_setup(
        self,
        chat_id: int,
        user_id: int,
        state: dict,
        concurrency: int,
        msg_id: int | None = None,
    ):
        links = list(state.get("links") or [])
        times = int(state.get("times") or 0)
        concurrency = max(1, min(int(concurrency or 3), 5))
        self._user_states.pop(user_id, None)
        self._loop_configs[user_id] = {
            "links": links,
            "times": times,
            "concurrency": concurrency,
            "chat_id": chat_id,
            "set_at": time.time(),
        }
        times_label = "Unlimited (until /loop_stop)" if times == 0 else str(times)
        await self.send_message(
            chat_id,
            f"✅ <b>Loop Mode configured!</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>🔗 <b>Links:</b> <code>{len(links)}</code>\n"
            f"🔁 <b>Cycles:</b> <code>{times_label}</code>\n"
            f"⚡ <b>Concurrency:</b> <code>{concurrency} simultaneous</code>\n"
            f"🚫 <b>Cache:</b> <code>Disabled (always live)</code>\n"
            f"⏱ <b>Gap between cycles:</b> <code>3–5s random</code></blockquote>\n\n"
            f"Send <b>/loop_start</b> to begin continuous processing.\n"
            f"Send <b>/loop_stop</b> anytime to halt.\n"
            f"Send <b>/loop_status</b> to check progress.",
            reply_to=msg_id,
            reply_markup={
                "inline_keyboard": [
                    [
                        {"text": "▶️ Start Loop", "callback_data": "loop:start", "style": "success"},
                        {"text": "🔄 Re-setup", "callback_data": "loop:setup"},
                    ]
                ]
            },
        )

    async def _cmd_loop_start(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int | None = None,
    ):
        pstat = self.db.get_user_premium_status(user_id)
        if not pstat.get("is_premium") and not self.db.is_admin(user_id):
            await self.send_message(
                chat_id,
                "💎 <b>Loop Mode is Premium-only.</b> Use /premium to upgrade.",
                reply_to=msg_id,
            )
            return

        cfg = self._loop_configs.get(user_id)
        if not cfg or not cfg.get("links"):
            await self.send_message(
                chat_id,
                "⚠ No loop configuration found.\n"
                "First run <b>/loop_setup</b> to set your links and cycle count.",
                reply_to=msg_id,
            )
            return

        existing = self._loop_tasks.get(user_id)
        if existing and not existing.done():
            await self.send_message(
                chat_id,
                "⚠ A loop is already running for you.\n"
                "Use <b>/loop_stop</b> first, then /loop_start again.",
                reply_to=msg_id,
            )
            return

        self._loop_stop_flags[user_id] = False
        task = asyncio.create_task(
            self._run_loop_mode(chat_id, user_id, from_user, cfg)
        )
        self._loop_tasks[user_id] = task
        times = cfg.get("times", 0)
        times_label = "∞" if times == 0 else str(times)
        conc = max(1, min(int(cfg.get("concurrency") or 3), 5))
        await self.send_message(
            chat_id,
            f"▶️ <b>Loop Mode STARTED</b>\n"
            f"<blockquote>🔗 {len(cfg['links'])} link(s) × {times_label} cycles\n"
            f"⚡ Max {conc} concurrent • No cache • 3–5s random gap</blockquote>\n"
            f"Results will appear here as each link finishes.\n"
            f"Send <b>/loop_stop</b> to halt anytime.",
            reply_to=msg_id,
        )

    async def _cmd_loop_stop(self, chat_id: int, user_id: int, msg_id: int | None = None):
        self._loop_stop_flags[user_id] = True
        task = self._loop_tasks.get(user_id)
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            self._loop_tasks.pop(user_id, None)
            await self.send_message(
                chat_id,
                "⏹ <b>Loop Mode stopped.</b>\n"
                "<blockquote>You can /loop_start again with the same config, or /loop_setup to change links.</blockquote>",
                reply_to=msg_id,
            )
        else:
            self._loop_tasks.pop(user_id, None)
            await self.send_message(
                chat_id,
                "ℹ No active loop was running.",
                reply_to=msg_id,
            )

    async def _cmd_loop_status(self, chat_id: int, user_id: int, msg_id: int | None = None):
        cfg = self._loop_configs.get(user_id)
        task = self._loop_tasks.get(user_id)
        running = bool(task and not task.done())
        if not cfg:
            await self.send_message(
                chat_id,
                "ℹ No loop configuration set. Use <b>/loop_setup</b> first.",
                reply_to=msg_id,
            )
            return
        times = cfg.get("times", 0)
        times_label = "Unlimited" if times == 0 else str(times)
        progress = cfg.get("current_cycle", 0)
        done = cfg.get("completed_count", 0)
        failed = cfg.get("failed_count", 0)
        status = "🟢 RUNNING" if running else "⚪ IDLE"
        await self.send_message(
            chat_id,
            f"📊 <b>Loop Mode Status</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>Status: <code>{status}</code>\n"
            f"Links: <code>{len(cfg.get('links') or [])}</code>\n"
            f"Cycles target: <code>{times_label}</code>\n"
            f"Current cycle: <code>{progress}</code>\n"
            f"✅ Completed: <code>{done}</code>\n"
            f"❌ Failed: <code>{failed}</code>\n"
            f"Concurrency: <code>{int(cfg.get('concurrency') or 3)}</code> • Cache: <code>OFF</code></blockquote>",
            reply_to=msg_id,
        )

    async def _run_loop_mode(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        cfg: dict,
    ):
        links = list(cfg.get("links") or [])
        times = int(cfg.get("times") or 0)
        concurrency = int(cfg.get("concurrency") or 3)
        if not links:
            return

        sem = asyncio.Semaphore(max(1, min(concurrency, 5)))
        cycle = 0
        cfg["completed_count"] = 0
        cfg["failed_count"] = 0
        cfg["current_cycle"] = 0

        try:
            while True:
                if self._loop_stop_flags.get(user_id):
                    break
                pstat = self.db.get_user_premium_status(user_id)
                if not pstat.get("is_premium") and not self.db.is_admin(user_id):
                    await self.send_message(
                        chat_id,
                        "⏹ <b>Loop stopped</b> — Premium expired. Renew with /premium.",
                    )
                    break

                cycle += 1
                cfg["current_cycle"] = cycle
                if times > 0 and cycle > times:
                    break

                await self.send_message(
                    chat_id,
                    f"🔄 <b>Cycle {cycle}{'/' + str(times) if times else ''} starting…</b> "
                    f"({len(links)} links, max {concurrency} concurrent)",
                )

                async def _one(url: str):
                    if self._loop_stop_flags.get(user_id):
                        return
                    async with sem:
                        if self._loop_stop_flags.get(user_id):
                            return
                        try:
                            await self._process_loop_single(
                                chat_id, user_id, from_user, url, cycle
                            )
                            cfg["completed_count"] = int(cfg.get("completed_count") or 0) + 1
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            cfg["failed_count"] = int(cfg.get("failed_count") or 0) + 1

                tasks = [asyncio.create_task(_one(u)) for u in links]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, asyncio.CancelledError):
                        raise r

                if self._loop_stop_flags.get(user_id):
                    break
                if times > 0 and cycle >= times:
                    break

                delay = random.uniform(3.0, 5.0)
                await self.send_message(
                    chat_id,
                    f"⏳ Cycle {cycle} done. Waiting <b>{delay:.1f}s</b> before next cycle…",
                )
                await asyncio.sleep(delay)

            if not self._loop_stop_flags.get(user_id):
                await self.send_message(
                    chat_id,
                    f"✅ <b>Loop Mode finished</b>\n"
                    f"<blockquote>Cycles completed: <code>{cycle}</code>\n"
                    f"✅ Successes: <code>{cfg.get('completed_count', 0)}</code>\n"
                    f"❌ Failures: <code>{cfg.get('failed_count', 0)}</code></blockquote>",
                )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            with contextlib.suppress(Exception):
                await self.send_message(
                    chat_id,
                    f"⚠ Loop Mode error: <code>{html.escape(str(e)[:200])}</code>",
                )
        finally:
            self._loop_tasks.pop(user_id, None)
            self._loop_stop_flags.pop(user_id, None)

    async def _process_loop_single(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        raw_url: str,
        cycle: int,
    ):
        """Lightweight bypass for loop mode: always force=True (no cache), compact result."""
        url = norm_url(raw_url)
        t0 = time.time()

        prot_src = self.db.check_protected_source_url(url)
        if prot_src:
            await self.send_message(
                chat_id,
                f"🛡 <b>Cycle {cycle}</b> — Protected link skipped\n"
                f"<blockquote><code>{html.escape(url[:120])}</code></blockquote>",
            )
            return

        try:
            res = await self.resolve_fn(
                url,
                force=True,
                origin="telegram-loop",
                user_id=user_id,
                username=from_user.get("username"),
            )
            elapsed = time.time() - t0
            dest_url = (res or {}).get("url") or ""
            extra_links = list((res or {}).get("extra_links") or [])

            if not dest_url:
                raise Exception("No destination returned")

            prot_dest = self.db.check_protected_destination_url(dest_url, source_url=url)
            if not prot_dest and extra_links:
                for ex_u in extra_links:
                    prot_dest = self.db.check_protected_destination_url(ex_u, source_url=url)
                    if prot_dest:
                        break
            if prot_dest:
                await self.send_message(
                    chat_id,
                    f"🛡 <b>Cycle {cycle}</b> — Protected destination blocked\n"
                    f"<blockquote><code>{html.escape(url[:100])}</code></blockquote>",
                )
                return

            rows = [
                [
                    {"text": "📋 COPY", "copy_text": {"text": dest_url}},
                    {"text": "OPEN ↗️", "url": dest_url, "style": "success"},
                ]
            ]
            if extra_links:
                pair = []
                for idx, ex in enumerate(extra_links[:6], 1):
                    pair.append({"text": f"#{idx} ↗️", "url": ex})
                    if len(pair) == 2:
                        rows.append(pair)
                        pair = []
                if pair:
                    rows.append(pair)

            txt = (
                f"✅ <b>Cycle {cycle}</b> • <code>{elapsed:.1f}s</code>\n"
                f"<blockquote>🔗 <code>{html.escape(url[:90])}{'…' if len(url) > 90 else ''}</code>\n"
                f"➡️ <code>{html.escape(dest_url[:200])}</code></blockquote>"
            )
            await self.send_message(
                chat_id,
                txt,
                reply_markup={"inline_keyboard": rows},
            )
            with contextlib.suppress(Exception):
                await self.db.touch_user(from_user, increment_bypass=True)
        except ProtectedLinkError:
            await self.send_message(
                chat_id,
                f"🛡 <b>Cycle {cycle}</b> — Protected link\n"
                f"<blockquote><code>{html.escape(url[:120])}</code></blockquote>",
            )
        except Exception as e:
            await self.send_message(
                chat_id,
                f"❌ <b>Cycle {cycle}</b> failed • <code>{html.escape(str(e)[:120])}</code>\n"
                f"<blockquote><code>{html.escape(url[:100])}</code></blockquote>",
            )

    async def _cmd_myplan(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int | None = None,
        edit_id: int | None = None,
    ):
        await self.db.touch_user(from_user)
        pstat = self.db.get_user_premium_status(user_id)
        contact_url = self._get_contact_admin_url()

        if self.db.is_admin(user_id):
            txt = (
                f"<blockquote>👑 <b>ʏᴏᴜʀ ᴘʀᴇᴍɪᴜᴍ sᴛᴀᴛᴜs</b></blockquote>\n\n"
                f"<blockquote>✅ <b>sᴛᴀᴛᴜs:</b> <code>ᴀᴅᴍɪɴ / ᴏᴡɴᴇʀ (ᴜɴʟɪᴍɪᴛᴇᴅ)</code>\n"
                f"» <b>ᴘʟᴀɴ:</b> <code>ʟɪꜰᴇᴛɪᴍᴇ ᴜɴʟɪᴍɪᴛᴇᴅ</code>\n"
                f"» <b>ʟɪɴᴋ ʙʏᴘᴀssᴇs:</b> <code>ᴜɴʟɪᴍɪᴛᴇᴅ ∞</code></blockquote>"
            )
        elif pstat.get("is_premium"):
            rem_sec = int(pstat.get("remaining_seconds") or 0)
            rem_days = rem_sec // 86400
            rem_hours = (rem_sec % 86400) // 3600
            txt = (
                f"<blockquote>👑 <b>ʏᴏᴜʀ ᴘʀᴇᴍɪᴜᴍ sᴜʙsᴄʀɪᴘᴛɪᴏɴ</b></blockquote>\n\n"
                f"<blockquote>✅ <b>sᴛᴀᴛᴜs:</b> <code>ᴀᴄᴛɪᴠᴇ ᴘʀᴇᴍɪᴜᴍ 💎</code>\n"
                f"» <b>ᴜsᴇʀ ɪᴅ:</b> <code>{user_id}</code>\n"
                f"» <b>ᴘʟᴀɴ:</b> <b>{esc(pstat.get('plan_label') or pstat.get('plan_type') or 'Premium')}</b>\n"
                f"» <b>ᴛɪᴍᴇ ʟᴇꜰᴛ:</b> <code>{rem_days}d {rem_hours}h remaining</code>\n"
                f"» <b>ᴇxᴘɪʀᴇs ᴏɴ:</b> <code>{esc(pstat.get('expiry_str'))}</code>\n"
                f"» <b>ʟɪɴᴋ ǫᴜᴏᴛᴀ:</b> <code>ᴜɴʟɪᴍɪᴛᴇᴅ ∞</code></blockquote>\n\n"
                f"<blockquote>💡 <i>You can extend your plan anytime by purchasing another plan below — days stack automatically!</i></blockquote>"
            )
        else:
            free_used = pstat.get("free_used", 0)
            free_limit = pstat.get("free_limit", 3)
            free_left = pstat.get("free_left", 0)
            exp_note = ""
            if pstat.get("premium_expired"):
                exp_note = (
                    f"<blockquote>⏰ <b>ᴘʀᴇᴠɪᴏᴜs ᴘʟᴀɴ:</b> <code>ᴇxᴘɪʀᴇᴅ ᴏɴ {esc(pstat.get('expired_str'))}</code></blockquote>\n"
                )
            status_badge = "🟢 Free Trial Active" if free_left > 0 else "🔴 Free Trial Exhausted — Subscription Required"
            txt = (
                f"<blockquote>👑 <b>ʏᴏᴜʀ ᴘʟᴀɴ &amp; ǫᴜᴏᴛᴀ sᴛᴀᴛᴜs</b></blockquote>\n\n"
                f"{exp_note}"
                f"<blockquote>» <b>ᴜsᴇʀ ɪᴅ:</b> <code>{user_id}</code>\n"
                f"» <b>sᴛᴀᴛᴜs:</b> <code>{status_badge}</code>\n"
                f"» <b>ʟɪꜰᴇᴛɪᴍᴇ ꜰʀᴇᴇ ᴜsᴇs:</b> <code>{free_used} / {free_limit} Used ({free_left} Remaining)</code></blockquote>\n\n"
                f"<blockquote>💎 <b>Upgrade to Premium</b> for unlimited link bypasses, zero cooldowns &amp; instant automated activation!</blockquote>"
            )

        kb = {
            "inline_keyboard": [
                [{"text": "💎 Buy / Extend Premium", "callback_data": "usr:premium", "style": "success"}],
                [
                    {"text": "👨‍💻 Contact Admin", "url": contact_url},
                    {"text": "🏠 Back to Home", "callback_data": "usr:start"},
                ],
            ]
        }
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _cmd_buy_premium(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        msg_id: int | None = None,
        edit_id: int | None = None,
    ):
        await self.db.touch_user(from_user)
        pstat = self.db.get_user_premium_status(user_id)
        plans = self.db.get_premium_plans(only_enabled=True)
        contact_url = self._get_contact_admin_url()

        if pstat.get("is_premium"):
            cur_line = f"🟢 <b>Current Plan:</b> <code>{esc(pstat.get('plan_label'))}</code> (Expires: <code>{esc(pstat.get('expiry_str'))}</code>)"
        else:
            cur_line = f"🎁 <b>Free Trial Quota:</b> <code>{pstat.get('free_used')}/{pstat.get('free_limit')} Used ({pstat.get('free_left')} Left)</code>"

        plan_lines = []
        plan_buttons = []
        for idx, p in enumerate(plans):
            key = p.get("key") or "plan_1m"
            name = p.get("name") or "1 Month"
            days = int(p.get("days") or 30)
            amt = p.get("amount", 100)
            amt_str = int(amt) if amt == int(amt) else amt
            badge = f" [{p.get('badge')}]" if p.get("badge") else ""
            plan_lines.append(
                f"• 💎 <b>{esc(name)} ({days} Days)</b> — <b>₹{amt_str}</b>{esc(badge)}"
            )
            btn: dict[str, Any] = {
                "text": f"💎 {name} ({days} Days) — ₹{amt_str}",
                "callback_data": f"plan_select_{key}",
            }
            if idx == len(plans) - 1:
                btn["style"] = "success"
            elif idx == 1:
                btn["style"] = "primary"
            plan_buttons.append([btn])

        plans_block = "\n".join(plan_lines) if plan_lines else "• 💎 <b>1 Month (30 Days)</b> — <b>₹100</b>"

        txt = (
            f"<blockquote>💎 <b>ᴛʜᴇᴅʀᴜɴᴋʙᴏᴛs ᴘʀᴇᴍɪᴜᴍ ᴍᴇᴍʙᴇʀsʜɪᴘ</b></blockquote>\n\n"
            f"<blockquote>{cur_line}</blockquote>\n"
            f"<blockquote>✨ <b>ᴘʀᴇᴍɪᴜᴍ ʙᴇɴᴇꜰɪᴛs:</b>\n"
            f"• ♾️ <b>Unlimited Link Bypasses</b> (Zero limits)\n"
            f"• ⚡ <b>Priority Multi-Worker Speed</b> &amp; Instant Cloud Cache\n"
            f"• 🤖 <b>100% Automated UPI QR Verification</b> (Instant activation)</blockquote>\n\n"
            f"<blockquote>📦 <b>sᴇʟᴇᴄᴛ ᴀ ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ʙᴇʟᴏᴡ:</b>\n"
            f"{plans_block}</blockquote>\n\n"
            f"<blockquote>👇 <i>Tap a plan below to generate your dynamic UPI QR code &amp; activate automatically!</i></blockquote>"
        )

        plan_buttons.append([
            {"text": "👑 My Plan", "callback_data": "usr:myplan"},
            {"text": "👨‍💻 Contact Admin", "url": contact_url},
        ])
        plan_buttons.append([{"text": "🏠 Back to Home", "callback_data": "usr:start"}])
        kb = {"inline_keyboard": plan_buttons}

        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _handle_plan_select(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        plan_key: str,
        edit_id: int | None = None,
        cb_id: str | None = None,
    ):
        contact_url = self._get_contact_admin_url()
        plan = self.db.get_plan_by_key(plan_key)
        if not plan:
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "⚠️ Selected plan was not found.", "show_alert": True},
                )
            return

        # Check if user already has an active pending order
        existing = await self.db.get_pending_order_for_user(user_id)
        if existing:
            ex_id = existing.get("_id") or existing.get("order_id")
            ex_amt = existing.get("payable_amount") or existing.get("amount") or 0
            ex_amt_str = int(ex_amt) if ex_amt == int(ex_amt) else ex_amt
            ex_lbl = existing.get("plan_label") or f"{existing.get('days', 30)} Days"
            rem = max(0, int((existing.get("expiry_ts") or 0) - time.time()))
            rem_m, rem_s = divmod(rem, 60)
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "⚠️ You already have an active pending order!"},
                )
            dup_txt = (
                f"<blockquote>⚠️ <b>ᴀᴄᴛɪᴠᴇ ᴏʀᴅᴇʀ ꜰᴏᴜɴᴅ</b></blockquote>\n\n"
                f"<blockquote>ʏᴏᴜ ᴀʟʀᴇᴀᴅʏ ʜᴀᴠᴇ ᴀ ᴘᴇɴᴅɪɴɢ ᴘᴀʏᴍᴇɴᴛ ᴏʀᴅᴇʀ:</blockquote>\n"
                f"<blockquote>» ᴏʀᴅᴇʀ ɪᴅ: <code>{esc(ex_id)}</code>\n"
                f"» ᴘʟᴀɴ: <b>{esc(ex_lbl)}</b>\n"
                f"» ᴀᴍᴏᴜɴᴛ: <b>₹{esc(ex_amt_str)}</b>\n"
                f"» ᴛɪᴍᴇ ʟᴇꜰᴛ: <code>{rem_m}m {rem_s}s</code></blockquote>\n\n"
                f"<blockquote>💡 <i>Complete your existing payment or cancel it below to select a different plan.</i></blockquote>"
            )
            dup_kb = {
                "inline_keyboard": [
                    [{"text": "✅ I Have Paid — Verify Now", "callback_data": f"pmt_done_{ex_id}", "style": "success"}],
                    [
                        {"text": "❌ Cancel Order", "callback_data": f"pmt_cancel_{ex_id}", "style": "danger"},
                        {"text": "👨‍💻 Contact Admin", "url": contact_url},
                    ],
                ]
            }
            if edit_id:
                await self.edit_message(chat_id, edit_id, dup_txt, reply_markup=dup_kb)
            else:
                await self.send_message(chat_id, dup_txt, reply_markup=dup_kb)
            return

        if cb_id:
            await self.api(
                "answerCallbackQuery",
                {"callback_query_id": cb_id, "text": "⚡ Generating your UPI QR Code..."},
            )

        days = int(plan.get("days") or 30)
        amount = float(plan.get("amount") or 100)
        amt_disp = int(amount) if amount == int(amount) else amount
        plan_name = str(plan.get("name") or f"{days} Days")
        plan_type = str(plan.get("plan_type") or plan.get("key") or "1_month")
        plan_label = f"💎 {plan_name} — ₹{amt_disp}"

        upi_id = str(self.db.settings.get("upi_id") or DEFAULT_PAYMENT_CONFIG["upi_id"]).strip()
        payee_name = str(self.db.settings.get("upi_payee_name") or DEFAULT_PAYMENT_CONFIG["upi_payee_name"]).strip()
        max_min = int(self.db.settings.get("payment_max_minutes") or DEFAULT_PAYMENT_CONFIG["payment_max_minutes"])

        order_id = make_order_id(user_id)
        qr_bytes = await asyncio.to_thread(
            build_upi_qr_bytes,
            upi_id=upi_id,
            payee_name=payee_name,
            amount=amount,
            order_id=order_id,
            note=f"{plan_name} Premium",
        )

        order = await self.db.create_order(
            order_id=order_id,
            user_id=user_id,
            days=days,
            amount=amount,
            plan_key=str(plan.get("key") or plan_key),
            plan_type=plan_type,
            plan_label=plan_label,
            chat_id=chat_id,
            qr_message_id=None,
        )

        caption = (
            f"<blockquote>💳 <b>ᴄᴏᴍᴘʟᴇᴛᴇ ʏᴏᴜʀ ᴘᴀʏᴍᴇɴᴛ</b></blockquote>\n\n"
            f"<blockquote>» ᴘʟᴀɴ: <b>{esc(plan_name)} ({days} ᴅᴀʏs)</b></blockquote>\n"
            f"<blockquote>» ᴀᴍᴏᴜɴᴛ: <b>₹{esc(amt_disp)}</b></blockquote>\n"
            f"<blockquote>» ᴜᴘɪ ɪᴅ: <code>{esc(upi_id)}</code></blockquote>\n"
            f"<blockquote>» ᴏʀᴅᴇʀ ɪᴅ: <code>{esc(order_id)}</code></blockquote>\n"
            f"<blockquote>» ᴛɪᴍᴇ ʟɪᴍɪᴛ: <code>{max_min} ᴍɪɴᴜᴛᴇs</code></blockquote>\n\n"
            f"<blockquote>📲 <b>ʜᴏᴡ ᴛᴏ ᴘᴀʏ:</b>\n"
            f"1. sᴄᴀɴ ᴛʜᴇ ǫʀ ᴄᴏᴅᴇ ᴀʙᴏᴠᴇ ᴡɪᴛʜ ᴀɴʏ ᴜᴘɪ ᴀᴘᴘ (ɢᴘᴀʏ, ᴘʜᴏɴᴇᴘᴇ, ᴘᴀʏᴛᴍ, ᴇᴛᴄ.)\n"
            f"2. ᴘᴀʏ ᴛʜᴇ ᴇxᴀᴄᴛ ᴀᴍᴏᴜɴᴛ <b>₹{esc(amt_disp)}</b>\n"
            f"3. ʏᴏᴜʀ ᴘʟᴀɴ ᴡɪʟʟ ᴀᴄᴛɪᴠᴀᴛᴇ <b>ᴀᴜᴛᴏᴍᴀᴛɪᴄᴀʟʟʏ</b> ᴡɪᴛʜɪɴ sᴇᴄᴏɴᴅs — ᴏʀ ᴛᴀᴘ <b>“✅ ɪ ʜᴀᴠᴇ ᴘᴀɪᴅ”</b> ʙᴇʟᴏᴡ!</blockquote>"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "✅ I Have Paid", "callback_data": f"pmt_done_{order_id}", "style": "success"}],
                [
                    {"text": "❌ Cancel Order", "callback_data": f"pmt_cancel_{order_id}", "style": "danger"},
                    {"text": "👨‍💻 Contact Admin", "url": contact_url},
                ],
            ]
        }

        if edit_id:
            try:
                await self.delete_message(chat_id, edit_id)
            except Exception:
                pass

        sent = await self.send_photo_bytes(chat_id, qr_bytes, caption, reply_markup=kb)
        qr_msg_id = ((sent or {}).get("result") or {}).get("message_id")
        if qr_msg_id:
            order["qr_message_id"] = int(qr_msg_id)
            if self.db.connected and self.db.db is not None:
                try:
                    await self.db.db.paytm_orders.update_one(
                        {"_id": order_id},
                        {"$set": {"qr_message_id": int(qr_msg_id)}},
                    )
                except Exception:
                    pass

        start_auto_verifier(
            self,
            self.db,
            order_id=order_id,
            chat_id=chat_id,
            qr_message_id=qr_msg_id,
            expiry_ts=float(order["expiry_ts"]),
        )

    async def _handle_pmt_done(
        self,
        chat_id: int,
        user_id: int,
        order_id: str,
        edit_id: int | None = None,
        cb_id: str | None = None,
    ):
        contact_url = self._get_contact_admin_url()
        order = await self.db.get_order(order_id)
        if not order:
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "❌ Order not found.", "show_alert": True},
                )
            return
        if int(order.get("user_id") or 0) != int(user_id) and not self.db.is_admin(user_id):
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "⛔ This order belongs to another user.", "show_alert": True},
                )
            return
        st = order.get("status")
        if st == "success":
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "✅ Payment already verified & plan activated!", "show_alert": True},
                )
            return
        if st in ("cancelled", "expired"):
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": f"⚠️ Order is already {st}.", "show_alert": True},
                )
            return

        result = await verify_paytm_order(self.db, order)
        if result:
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "🎉 Payment Verified! Activating your Premium Plan..."},
                )
            qr_mid = edit_id or order.get("qr_message_id")
            await on_payment_success(self, self.db, order, result, chat_id, qr_message_id=qr_mid)
            return

        if cb_id:
            await self.api(
                "answerCallbackQuery",
                {
                    "callback_query_id": cb_id,
                    "text": "⏳ Payment not detected yet. Auto-checking in background every 12s...",
                    "show_alert": True,
                },
            )

        amount = float(order.get("payable_amount") or order.get("amount") or 0)
        amt_disp = int(amount) if amount == int(amount) else amount
        upi_id = str(self.db.settings.get("upi_id") or DEFAULT_PAYMENT_CONFIG["upi_id"]).strip()
        plan_lbl = order.get("plan_label") or f"{order.get('days', 30)} Days"
        rem = max(0, int((order.get("expiry_ts") or 0) - time.time()))
        rem_m, rem_s = divmod(rem, 60)

        wait_caption = (
            f"<blockquote>⏳ <b>ᴘᴀʏᴍᴇɴᴛ ɴᴏᴛ ᴅᴇᴛᴇᴄᴛᴇᴅ ʏᴇᴛ</b></blockquote>\n\n"
            f"<blockquote>» ᴘʟᴀɴ: <b>{esc(plan_lbl)}</b></blockquote>\n"
            f"<blockquote>» ᴀᴍᴏᴜɴᴛ: <b>₹{esc(amt_disp)}</b></blockquote>\n"
            f"<blockquote>» ᴜᴘɪ ɪᴅ: <code>{esc(upi_id)}</code></blockquote>\n"
            f"<blockquote>» ᴏʀᴅᴇʀ ɪᴅ: <code>{esc(order_id)}</code></blockquote>\n"
            f"<blockquote>» ᴛɪᴍᴇ ʟᴇꜰᴛ: <code>{rem_m}m {rem_s}s</code></blockquote>\n\n"
            f"<blockquote>🔄 <b>ᴀᴜᴛᴏ-ᴠᴇʀɪꜰɪᴄᴀᴛɪᴏɴ ɪs ʀᴜɴɴɪɴɢ!</b>\n"
            f"As soon as your UPI transfer settles, this QR message will be deleted and your plan will activate automatically.</blockquote>"
        )
        kb = {
            "inline_keyboard": [
                [{"text": "🔄 Check Payment Again", "callback_data": f"pmt_done_{order_id}", "style": "success"}],
                [
                    {"text": "❌ Cancel Order", "callback_data": f"pmt_cancel_{order_id}", "style": "danger"},
                    {"text": "👨‍💻 Contact Admin", "url": contact_url},
                ],
            ]
        }
        if edit_id:
            await self.edit_message(chat_id, edit_id, wait_caption, reply_markup=kb)

    async def _handle_pmt_cancel(
        self,
        chat_id: int,
        user_id: int,
        from_user: dict,
        order_id: str,
        edit_id: int | None = None,
        cb_id: str | None = None,
    ):
        order = await self.db.get_order(order_id)
        if order and int(order.get("user_id") or 0) != int(user_id) and not self.db.is_admin(user_id):
            if cb_id:
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "⛔ You cannot cancel another user's order.", "show_alert": True},
                )
            return

        stop_auto_verifier(order_id)
        await self.db.cancel_order_if_pending(order_id, user_id=user_id)
        if cb_id:
            await self.api(
                "answerCallbackQuery",
                {"callback_query_id": cb_id, "text": "❌ Order cancelled."},
            )
        qr_mid = edit_id or (order or {}).get("qr_message_id")
        if qr_mid:
            try:
                await self.delete_message(chat_id, int(qr_mid))
            except Exception:
                pass
        await self._cmd_buy_premium(chat_id, user_id, from_user)

    # ------------------------------------------------- Admin Premium Commands
    async def _cmd_addpremium(self, chat_id: int, admin_id: int, msg_id: int | None, arg: str):
        """Supports:
        1) /addpremium <user_id> <plan_type> <days>  (e.g. /addpremium 123456789 1_month 30)
        2) /addpremium <user_id> <days>              (e.g. /addpremium 123456789 30)
        3) /addpremium <user_id> <value> <d/m/y>     (e.g. /addpremium 123456789 30 d)
        """
        tokens = (arg or "").strip().split()
        if len(tokens) < 2:
            usage = (
                "💎 • <b>𝗔𝗗𝗗 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗨𝗦𝗘𝗥 (𝗠𝗔𝗡𝗨𝗔𝗟)</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "<blockquote><b>Usage Format:</b>\n"
                "<code>/addpremium &lt;user_id&gt; &lt;plan_type&gt; &lt;days&gt;</code>\n\n"
                "<b>Examples:</b>\n"
                "• <code>/addpremium 123456789 1_month 30</code>\n"
                "• <code>/addpremium 123456789 3_months 90</code>\n"
                "• <code>/addpremium 123456789 6_months 180</code>\n"
                "• <code>/addpremium 123456789 VIP 60</code></blockquote>"
            )
            await self.send_message(chat_id, usage, reply_to=msg_id)
            return

        try:
            target_uid = int(tokens[0])
        except ValueError:
            await self.send_message(chat_id, "⚠️ Invalid <code>user_id</code> (must be numeric).", reply_to=msg_id)
            return

        plan_type = "custom"
        time_val = 30
        time_unit = "d"

        if len(tokens) == 2:
            t1 = tokens[1].strip()
            m_num = re.match(r"^(\d+)([dmy]?)$", t1.lower())
            if m_num:
                time_val = int(m_num.group(1))
                time_unit = m_num.group(2) or "d"
                plan_type = f"{time_val}{time_unit}"
            else:
                matched = self.db.get_plan_by_key(t1)
                if matched:
                    time_val = int(matched.get("days") or 30)
                    plan_type = str(matched.get("plan_type") or matched.get("key") or t1)
                else:
                    await self.send_message(
                        chat_id,
                        "⚠️ Please specify the number of days: <code>/addpremium &lt;user_id&gt; &lt;plan_type&gt; &lt;days&gt;</code>",
                        reply_to=msg_id,
                    )
                    return
        else:
            # 3 or more tokens: check if tokens[1] is numeric and tokens[2] is d/m/y
            if tokens[1].isdigit() and tokens[2].lower() in ("d", "day", "days", "m", "month", "months", "y", "year", "years"):
                time_val = int(tokens[1])
                time_unit = tokens[2].lower()[0]
                plan_type = f"{time_val}{time_unit}"
            else:
                # /addpremium <user_id> <plan_type> <days>
                last_tok = tokens[-1].lower().rstrip("d")
                if not last_tok.isdigit():
                    await self.send_message(
                        chat_id,
                        "⚠️ Invalid days value. Usage: <code>/addpremium &lt;user_id&gt; &lt;plan_type&gt; &lt;days&gt;</code>",
                        reply_to=msg_id,
                    )
                    return
                time_val = int(last_tok)
                time_unit = "d"
                plan_type = " ".join(tokens[1:-1]).strip() or f"{time_val}d"

        matched_plan = self.db.get_plan_by_key(plan_type)
        plan_label = (
            f"💎 {matched_plan['name']}"
            if matched_plan
            else f"💎 {plan_type.replace('_', ' ').title()} ({time_val} Days)"
        )

        res = await self.db.add_premium_user(
            user_id=target_uid,
            time_value=time_val,
            plan_type=plan_type,
            plan_label=plan_label,
            source="manual_admin",
            added_by=admin_id,
            time_unit=time_unit,
        )
        expiry_str = res.get("expiry_str") or format_ist_expiry(res.get("premium_until"))

        admin_txt = (
            f"<blockquote>✅ <b>ᴘʀᴇᴍɪᴜᴍ ᴀᴄᴛɪᴠᴀᴛᴇᴅ sᴜᴄᴄᴇssꜰᴜʟʟʏ</b></blockquote>\n\n"
            f"<blockquote>👤 <b>ᴜsᴇʀ ɪᴅ:</b> <code>{target_uid}</code>\n"
            f"📦 <b>ᴘʟᴀɴ ᴛʏᴘᴇ:</b> <code>{esc(plan_type)}</code> ({esc(plan_label)})\n"
            f"⏳ <b>ᴅᴜʀᴀᴛɪᴏɴ ᴀᴅᴅᴇᴅ:</b> <code>{res.get('days_added')} Days</code>\n"
            f"📅 <b>ᴇxᴘɪʀᴇs ᴏɴ:</b> <code>{esc(expiry_str)}</code></blockquote>"
        )
        await self.send_message(chat_id, admin_txt, reply_to=msg_id)

        # Notify the user on Telegram
        user_notify = (
            f"<blockquote>🎉 <b>ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ᴀᴄᴛɪᴠᴀᴛᴇᴅ!</b></blockquote>\n\n"
            f"<blockquote>✅ Your account has been upgraded to <b>Premium</b> by Admin!\n"
            f"» <b>ᴘʟᴀɴ:</b> <b>{esc(plan_label)}</b>\n"
            f"» <b>ᴅᴜʀᴀᴛɪᴏɴ:</b> <b>{res.get('days_added')} Days</b>\n"
            f"» <b>ᴇxᴘɪʀᴇs ᴏɴ:</b> <code>{esc(expiry_str)}</code></blockquote>\n\n"
            f"<blockquote>ᴇɴᴊᴏʏ ᴜɴʟɪᴍɪᴛᴇᴅ ʟɪɴᴋ ʙʏᴘᴀssᴇs ᴡɪᴛʜ ᴢᴇʀᴏ ʟɪᴍɪᴛs! 🚀</blockquote>"
        )
        try:
            await self.send_message(
                target_uid,
                user_notify,
                reply_markup={
                    "inline_keyboard": [
                        [
                            {"text": "👑 View My Plan", "callback_data": "usr:myplan", "style": "success"},
                            {"text": "🏠 Home", "callback_data": "usr:start"},
                        ]
                    ]
                },
            )
        except Exception:
            pass

        # Also log to Payment Log Channel (-1003270558605)
        log_text = (
            f"<blockquote>👑 <b>ᴘʀᴇᴍɪᴜᴍ ᴀᴅᴅᴇᴅ (ᴍᴀɴᴜᴀʟ ᴀᴅᴍɪɴ)</b></blockquote>\n\n"
            f"<blockquote>👤 ᴜsᴇʀ ɪᴅ: <code>{target_uid}</code></blockquote>\n"
            f"<blockquote>📦 ᴘʟᴀɴ: <b>{esc(plan_label)} ({res.get('days_added')} ᴅᴀʏs)</b></blockquote>\n"
            f"<blockquote>👮 ᴀᴅᴅᴇᴅ ʙʏ: <code>{admin_id}</code></blockquote>\n"
            f"<blockquote>⏳ ᴇxᴘɪʀᴇs: <code>{esc(expiry_str)}</code></blockquote>"
        )
        asyncio.create_task(send_payment_log_to_targets(self, self.db, log_text))

    async def _cmd_removepremium(self, chat_id: int, admin_id: int, msg_id: int | None, arg: str):
        if not arg or not arg.strip().lstrip("-").isdigit():
            await self.send_message(
                chat_id,
                "🗑 <b>Usage:</b> <code>/removepremium &lt;user_id&gt;</code>",
                reply_to=msg_id,
            )
            return
        target_uid = int(arg.strip())
        await self.db.remove_premium_user(target_uid)
        await self.send_message(
            chat_id,
            f"<blockquote>🗑 <b>ᴘʀᴇᴍɪᴜᴍ ʀᴇᴠᴏᴋᴇᴅ</b></blockquote>\n"
            f"<blockquote>Removed Premium access from user <code>{target_uid}</code>.</blockquote>",
            reply_to=msg_id,
        )
        try:
            await self.send_message(
                target_uid,
                "<blockquote>⚠️ <b>ᴘʀᴇᴍɪᴜᴍ ᴘʟᴀɴ ʀᴇᴠᴏᴋᴇᴅ</b></blockquote>\n"
                "<blockquote>Your Premium subscription has been ended by an administrator.</blockquote>",
                reply_markup={
                    "inline_keyboard": [
                        [
                            {"text": "💎 Buy Premium", "callback_data": "usr:premium", "style": "success"},
                            {"text": "👨‍💻 Contact Admin", "url": self._get_contact_admin_url()},
                        ]
                    ]
                },
            )
        except Exception:
            pass

    async def _cmd_premiumusers(
        self,
        chat_id: int,
        admin_id: int,
        msg_id: int | None = None,
        edit_id: int | None = None,
    ):
        prem_users = await self.db.list_active_premium_users()
        plans = self.db.get_premium_plans(only_enabled=False)
        free_lim = int(self.db.settings.get("free_trial_limit") or 3)
        upi_id = self.db.settings.get("upi_id") or DEFAULT_PAYMENT_CONFIG["upi_id"]
        mid = self.db.settings.get("paytm_mid") or DEFAULT_PAYMENT_CONFIG["paytm_mid"]
        log_ch = self.db.settings.get("payment_log_channel_id") or DEFAULT_PAYMENT_CONFIG["payment_log_channel_id"]

        p_lines = []
        for p in plans:
            st_icon = "🟢" if p.get("enabled", True) else "🔴"
            p_lines.append(
                f"{st_icon} <b>{esc(p.get('name'))}</b> (<code>{esc(p.get('key'))}</code>) — "
                f"<code>{p.get('days')}d</code> @ <b>₹{p.get('amount')}</b>"
            )
        plans_summary = "\n".join(p_lines)

        u_lines = []
        for idx, u in enumerate(prem_users[:15], 1):
            uid = u.get("user_id")
            uname = f"@{u.get('username')}" if u.get("username") else (u.get("first_name") or "User")
            rem_d = int(u.get("remaining_seconds", 0)) // 86400
            u_lines.append(
                f"{idx}. <code>{uid}</code> ({esc(uname)}) — <b>{esc(u.get('plan_type') or 'Premium')}</b>\n"
                f"   └ ⏳ <code>{rem_d}d left</code> • Exp: <code>{esc(u.get('expiry_str'))}</code>"
            )
        users_block = "\n".join(u_lines) if u_lines else "No active premium users right now."

        txt = (
            f"💎 • <b>𝗣𝗥𝗘𝗠𝗜𝗨𝗠 &amp; 𝗣𝗔𝗬𝗧𝗠 𝗔𝗨𝗧𝗢-𝗣𝗔𝗬 𝗠𝗔𝗡𝗔𝗚𝗘𝗥</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⚙️ <b>𝗚𝗔𝗧𝗘𝗪𝗔𝗬 &amp; 𝗤𝗨𝗢𝗧𝗔 𝗖𝗢𝗡𝗙𝗜𝗚 :</b>\n"
            f"<blockquote>• 🎁 <b>Free Trial Quota :</b> <code>{free_lim} lifetime uses / user</code>\n"
            f"• 🏦 <b>Paytm MID :</b> <code>{esc(mid)}</code>\n"
            f"• 💳 <b>UPI ID :</b> <code>{esc(upi_id)}</code>\n"
            f"• 📢 <b>Payment Log Channel :</b> <code>{esc(log_ch)}</code></blockquote>\n\n"
            f"📦 <b>𝗖𝗢𝗡𝗙𝗜𝗚𝗨𝗥𝗘𝗗 𝗣𝗟𝗔𝗡𝗦 :</b>\n"
            f"<blockquote>{plans_summary}</blockquote>\n\n"
            f"👑 <b>𝗔𝗖𝗧𝗜𝗩𝗘 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗨𝗦𝗘𝗥𝗦 ({len(prem_users)}) :</b>\n"
            f"<blockquote>{users_block}</blockquote>\n"
            f"<i>Use <code>/addpremium &lt;user_id&gt; &lt;plan_type&gt; &lt;days&gt;</code> or the Web Admin Panel to manage plans &amp; users!</i>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "➕ Add Premium User", "callback_data": "adm:add_prem_prompt", "style": "success"},
                    {"text": "🗑 Remove Premium User", "callback_data": "adm:del_prem_prompt", "style": "danger"},
                ],
                [
                    {"text": "🔄 Refresh List", "callback_data": "adm:prem_menu"},
                    {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                ],
            ]
        }
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    # ------------------------------------------------- Admin Commands & Panel
    def _build_admin_panel_view(self) -> tuple[str, dict]:
        s = self.db.settings
        px = s.get("proxy")
        masked_px = re.sub(r"(://[^:/@]+:)[^@]+@", r"\1•••@", px) if px else "None (Direct)"
        px_badge = "🟢 Active" if (px and not s.get("proxy_expired")) else ("🔴 Expired" if s.get("proxy_expired") else "⚪ Direct")
        fsub_on = "🟢 ON" if s.get("force_sub_enabled", True) else "🔴 OFF"
        fsub_cnt = len(s.get("force_sub_channels") or [])
        cache_on = "🟢 ON" if s.get("cache_enabled", True) else "🔴 OFF"
        maint_on = "🟡 ON" if s.get("maintenance_mode") else "🟢 OFF"
        ai_heal_on = "🟢 ON" if s.get("ai_auto_heal", True) else "🔴 OFF"
        ai_patrol_on = "🟢 ON" if s.get("ai_patrol_enabled", True) else "🔴 OFF"
        st = s.get("stats") or {}
        devs = self.db.list_tunnel_devices_sync()
        online_devs = sum(1 for d in devs if d.get("online"))
        sh_list = self.db.get_shortener_tunnel_list()
        sh_on_cnt = sum(1 for x in sh_list if x.get("enabled"))

        text = (
            f"🛠 • <b>𝗧𝗛𝗘𝗗𝗥𝗨𝗡𝗞𝗕𝗢𝗧𝗦 𝗔𝗗𝗠𝗜𝗡 𝗣𝗔𝗡𝗘𝗟</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 <b>𝗔𝗨𝗧𝗢𝗡𝗢𝗠𝗢𝗨𝗦 𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 :</b>\n"
            f"<blockquote>• 🧠 <b>Auto-Heal :</b> <code>{ai_heal_on}</code>  •  🛡 <b>Idle Patrol :</b> <code>{ai_patrol_on}</code>\n"
            f"• ☁️ <b>Boot Anti-Rollback :</b> <code>🟢 Active (MongoDB + GitHub)</code>\n"
            f"• 🔧 <b>AI Verified Fixes :</b> <code>{st.get('ai_fixes', 0)}</code></blockquote>\n"
            f"🌐 <b>𝗧𝗨𝗡𝗡𝗘𝗟 / 𝗣𝗥𝗢𝗫𝗬 ({px_badge}) :</b>\n"
            f"<blockquote><code>{esc(masked_px)}</code>\n"
            f"📱💻 <b>Devices Pool :</b> <code>{online_devs} online / {len(devs)} registered</code>\n"
            f"🔀 <b>Shorteners on Tunnel :</b> <code>{sh_on_cnt} / {len(sh_list)} enabled</code></blockquote>\n"
            f"📊 <b>𝗟𝗜𝗩𝗘 𝗠𝗘𝗧𝗥𝗜𝗖𝗦 &amp; 𝗦𝗬𝗡𝗖 :</b>\n"
            f"<blockquote>• 🗄 <b>MongoDB :</b> <code>{'Connected' if self.db.connected else 'Local Fallback'}</code>\n"
            f"• 🚀 <b>Cache :</b> <code>{cache_on} ({len(self.db.local_cache)} items, TTL {s.get('cache_hours', 24)}h)</code>\n"
            f"• 📢 <b>Force-Sub :</b> <code>{fsub_on} ({fsub_cnt} channels)</code>\n"
            f"• 👥 <b>Users :</b> <code>{len(self.db.local_users)}</code>  •  ✅ <b>Bypassed :</b> <code>{st.get('total_bypasses', 0)}</code>\n"
            f"• 🚨 <b>Error Logs :</b> <code>{len(self.db.local_logs)}</code>  •  🛠 <b>Maint :</b> <code>{maint_on}</code></blockquote>\n"
            f"<i>All changes sync instantaneously with MongoDB &amp; Web Admin UI.</i>"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "💎 Premium & Auto-Pay", "callback_data": "adm:prem_menu", "style": "success"},
                    {"text": f"🤖 AI Engineer ({ai_heal_on})", "callback_data": "adm:ai_menu", "style": "primary"},
                ],
                [
                    {"text": "☁️ Code Sync (Mongo/GH)", "callback_data": "adm:code_sync_menu"},
                    {"text": f"📱💻 Tunnel Devices ({online_devs}/{len(devs)})", "callback_data": "adm:tunnels_menu"},
                ],
                [
                    {"text": f"🔀 Shortener Tunnels ({sh_on_cnt}/{len(sh_list)})", "callback_data": "adm:shorteners_menu"},
                    {"text": "🌐 Set Tunnel Proxy", "callback_data": "adm:set_proxy"},
                ],
                [
                    {"text": "🔍 Test Exit IP", "callback_data": "adm:test_proxy"},
                    {"text": "🗑 Clear Proxy (Direct)", "callback_data": "adm:clear_proxy"},
                ],
                [
                    {"text": f"🚀 Cache: {cache_on}", "callback_data": "adm:toggle_cache"},
                    {"text": "🗄 Cache Manager", "callback_data": "adm:cache_menu"},
                ],
                [
                    {"text": f"📢 Force-Sub ({fsub_cnt})", "callback_data": "adm:fsub_menu"},
                    {"text": f"🚨 Error Logs ({len(self.db.local_logs)})", "callback_data": "adm:logs_menu"},
                ],
                [
                    {"text": f"👥 Users & Broadcast ({len(self.db.local_users)})", "callback_data": "adm:users_menu"},
                    {"text": "⚙️ Bot & Engine Settings", "callback_data": "adm:settings_menu"},
                ],
                [
                    {"text": "🔄 Refresh Panel", "callback_data": "adm:home"},
                    {"text": "⚡ Restart Bot", "callback_data": "adm:restart_bot", "style": "danger"},
                ],
                [
                    {"text": "🏠 User Home", "callback_data": "usr:start"},
                ],
            ]
        }
        return text, kb

    async def _send_admin_panel(self, chat_id: int, msg_id: int | None = None, edit_id: int | None = None):
        await self.db.sync_tunnels_from_mongo()
        text, kb = self._build_admin_panel_view()
        if edit_id:
            await self.edit_message(chat_id, edit_id, text, reply_markup=kb)
        else:
            await self.send_message(chat_id, text, reply_to=msg_id, reply_markup=kb)

    async def _send_ai_menu(self, chat_id: int, msg_id: int | None = None, edit_id: int | None = None):
        s = self.db.settings
        heal_on = "🟢 ON" if s.get("ai_auto_heal", True) else "🔴 OFF"
        patrol_on = "🟢 ON" if s.get("ai_patrol_enabled", True) else "🔴 OFF"
        interval_m = int(s.get("ai_patrol_interval_minutes", 15))
        active_run = self.ai_engineer.current_run if self.ai_engineer else None
        is_busy = bool(active_run and active_run.get("status") == "running")
        run_status = (
            f"🔄 RUNNING (<code>{esc(active_run.get('id'))}</code> — {esc(active_run.get('phase'))})"
            if is_busy
            else "🟢 IDLE &amp; MONITORING"
        )
        last_summary = ""
        if self.ai_engineer and self.ai_engineer.runs_history:
            last_r = self.ai_engineer.runs_history[0]
            last_summary = (
                f"\n📋 <b>𝗟𝗔𝗦𝗧 𝗔𝗜 𝗥𝗨𝗡 (<code>{esc(last_r.get('id'))}</code>) :</b>\n"
                f"<blockquote><code>{esc((last_r.get('summary') or '')[:350])}</code></blockquote>"
            )

        txt = (
            f"🤖 • <b>𝗔𝗨𝗧𝗢𝗡𝗢𝗠𝗢𝗨𝗦 𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 ('𝗕𝗥𝗢𝗧𝗛𝗘𝗥 𝗔𝗜')</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<blockquote>• ⚡ <b>Engine Status :</b> {run_status}\n"
            f"• 🧠 <b>Instant Auto-Heal on Errors :</b> <code>{heal_on}</code>\n"
            f"• 🛡 <b>Background Idle Patrol :</b> <code>{patrol_on} (every {interval_m}m)</code>\n"
            f"• ☁️ <b>Code Sync :</b> <code>MongoDB Atlas + GitHub Auto-Push</code>\n"
            f"• 🔒 <b>Anti-Rollback Guard :</b> <code>Active on Container Boot</code></blockquote>"
            f"{last_summary}"
        )
        kb = {
            "inline_keyboard": [
                [
                    {"text": "🚀 Scan & Fix Errors", "callback_data": "adm:ai_run_scan", "style": "success"},
                    {"text": "💬 Custom AI Task", "callback_data": "adm:ai_prompt", "style": "primary"},
                ],
                [
                    {"text": f"🧠 Auto-Heal: {heal_on}", "callback_data": "adm:ai_toggle_heal"},
                    {"text": f"🛡 Idle Patrol: {patrol_on}", "callback_data": "adm:ai_toggle_patrol"},
                ],
                [
                    {"text": "🔄 Refresh Status", "callback_data": "adm:ai_menu"},
                    {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                ],
            ]
        }
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _cmd_setproxy(self, chat_id: int, msg_id: int | None, arg: str):
        if not arg:
            await self.send_message(
                chat_id,
                "🌐 <b>Usage:</b> <code>/setproxy http://user:pass@host:port</code>\n"
                "Or <code>/setproxy off</code> to use direct connection.",
                reply_to=msg_id,
            )
            return
        new_px = None if arg.lower() in ("off", "none", "clear", "direct") else arg.strip()
        wait_msg = await self.send_message(chat_id, "⏳ <b>Applying tunnel proxy &amp; restarting browser context…</b>", reply_to=msg_id)
        wid = ((wait_msg or {}).get("result") or {}).get("message_id")
        try:
            await self.set_proxy_fn(new_px)
            info = await self.proxy_test_fn()
            if info.get("ok"):
                ip_txt = f"{info.get('ip')} ({info.get('city') or ''}, {info.get('country') or ''}) — {info.get('org') or ''}"
                status_line = f"✅ <b>𝗧𝗨𝗡𝗡𝗘𝗟 𝗨𝗣𝗗𝗔𝗧𝗘𝗗 &amp; 𝗩𝗘𝗥𝗜𝗙𝗜𝗘𝗗</b>\n<blockquote>🌐 <b>Exit IP:</b> <code>{esc(ip_txt)}</code></blockquote>"
            else:
                status_line = f"⚠️ <b>𝗧𝗨𝗡𝗡𝗘𝗟 𝗦𝗔𝗩𝗘𝗗 (𝗧𝗘𝗦𝗧 𝗙𝗔𝗜𝗟𝗘𝗗)</b>\n<blockquote><code>{esc(info.get('error'))}</code></blockquote>"
        except Exception as e:
            status_line = f"❌ <b>𝗙𝗔𝗜𝗟𝗘𝗗 𝗧𝗢 𝗦𝗘𝗧 𝗣𝗥𝗢𝗫𝗬 :</b> <code>{esc(e)}</code>"
        if wid:
            await self.edit_message(chat_id, wid, status_line)
        else:
            await self.send_message(chat_id, status_line, reply_to=msg_id)

    async def _cmd_testproxy(self, chat_id: int, msg_id: int | None, edit_id: int | None = None):
        wid = edit_id
        if not wid:
            wait_msg = await self.send_message(chat_id, "🔍 <b>Testing current exit IP…</b>", reply_to=msg_id)
            wid = ((wait_msg or {}).get("result") or {}).get("message_id")
        else:
            await self.edit_message(chat_id, wid, "🔍 <b>Testing current exit IP…</b>")
        info = await self.proxy_test_fn()
        if info.get("ok"):
            kind = "⚠️ Datacenter IP" if info.get("datacenter") else "✅ Residential / Home IP"
            txt = (
                f"🌐 • <b>𝗘𝗫𝗜𝗧 𝗜𝗣 𝗧𝗘𝗦𝗧 𝗥𝗘𝗦𝗨𝗟𝗧</b>\n\n"
                f"<blockquote>• <b>Via Proxy :</b> <code>{info.get('via_proxy')}</code>\n"
                f"• <b>Exit IP :</b> <code>{esc(info.get('ip'))}</code>\n"
                f"• <b>Location :</b> <code>{esc(info.get('city'))}, {esc(info.get('region'))}, {esc(info.get('country'))}</code>\n"
                f"• <b>ISP / Org :</b> <code>{esc(info.get('org'))}</code>\n"
                f"• <b>Type :</b> <code>{kind}</code></blockquote>"
            )
        else:
            txt = f"❌ <b>𝗣𝗥𝗢𝗫𝗬 𝗧𝗘𝗦𝗧 𝗙𝗔𝗜𝗟𝗘𝗗 :</b>\n<blockquote><code>{esc(info.get('error'))}</code></blockquote>"
        kb = {"inline_keyboard": [[{"text": "🔙 Back to Admin Panel", "callback_data": "adm:home"}]]} if edit_id else None
        if wid:
            await self.edit_message(chat_id, wid, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _cmd_addfsub(self, chat_id: int, msg_id: int | None, arg: str):
        if not arg:
            await self.send_message(
                chat_id,
                "📢 <b>Usage:</b> <code>/addfsub @ChannelUsername</code> or <code>/addfsub -1003768452343 TheDrunkBots Official</code>",
                reply_to=msg_id,
            )
            return
        parts = arg.split()
        cid = parts[0].strip()
        invite = parts[1].strip() if len(parts) > 1 and parts[1].startswith("http") else ""
        title = " ".join(parts[2:]) if len(parts) > 2 else (" ".join(parts[1:]) if len(parts) > 1 and not invite else "")
        resolved = await self.resolve_and_prepare_fsub_channel(cid, title, invite, force_new_invite=not bool(invite))
        channels = list(self.db.settings.get("force_sub_channels") or [])
        channels = [c for c in channels if str(c.get("chat_id")).lower() != cid.lower()]
        channels.append(resolved)
        await self.db.update_settings({"force_sub_channels": channels})
        await self.send_message(
            chat_id,
            f"✅ <b>Added Force-Sub Channel:</b>\n"
            f"<blockquote>• <b>Title :</b> <code>{esc(resolved['title'])}</code>\n"
            f"• <b>Chat ID :</b> <code>{esc(resolved['chat_id'])}</code>\n"
            f"• <b>Auto Invite Link :</b> {esc(resolved['invite_link'])}</blockquote>",
            reply_to=msg_id,
        )

    async def _cmd_delfsub(self, chat_id: int, msg_id: int | None, arg: str):
        if not arg:
            await self.send_message(chat_id, "Usage: <code>/delfsub @ChannelUsername</code>", reply_to=msg_id)
            return
        cid = arg.strip().lower()
        channels = list(self.db.settings.get("force_sub_channels") or [])
        new_ch = [c for c in channels if str(c.get("chat_id", "")).lower() != cid]
        await self.db.update_settings({"force_sub_channels": new_ch})
        await self.send_message(chat_id, f"🗑 <b>Removed Force-Sub Channel:</b> <code>{esc(arg)}</code>", reply_to=msg_id)

    async def _cmd_listfsub(self, chat_id: int, msg_id: int | None, edit_id: int | None = None):
        channels = self.db.settings.get("force_sub_channels") or []
        enabled = self.db.settings.get("force_sub_enabled", True)
        lines = []
        rows = [
            [
                {"text": f"Toggle Force-Sub ({'🟢 ON' if enabled else '🔴 OFF'})", "callback_data": "adm:toggle_fsub"},
                {"text": "➕ Add Channel", "callback_data": "adm:add_fsub_prompt", "style": "success"},
            ],
        ]
        for i, c in enumerate(channels):
            cid = c.get("chat_id", "")
            title = c.get("title") or cid
            inv = c.get("invite_link") or ""
            lines.append(f"{i+1}. <b>{esc(title)}</b> (<code>{esc(cid)}</code>)\n   🔗 {esc(inv)}")
            rows.append([{"text": f"🗑 Remove {title}", "callback_data": f"adm:del_fsub:{cid}", "style": "danger"}])
        rows.append([
            {"text": "🔄 Refresh Invites", "callback_data": "adm:fsub_refresh"},
            {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
        ])
        body = "\n".join(lines) if lines else "No Force-Sub channels configured yet."
        txt = (
            f"📢 • <b>𝗙𝗢𝗥𝗖𝗘-𝗦𝗨𝗕𝗦𝗖𝗥𝗜𝗕𝗘 𝗠𝗔𝗡𝗔𝗚𝗘𝗥</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Status :</b> <code>{'ENABLED' if enabled else 'DISABLED'}</code>\n\n"
            f"<blockquote>{body}</blockquote>\n"
            f"<i>Permanent non-expiring invite links are generated automatically by the bot.</i>"
        )
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup={"inline_keyboard": rows})
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup={"inline_keyboard": rows})

    async def _cmd_logs(self, chat_id: int, msg_id: int | None = None, edit_id: int | None = None):
        logs = await self.db.list_error_logs(limit=6)
        if not logs:
            txt = "🚨 • <b>𝗘𝗥𝗥𝗢𝗥 𝗟𝗢𝗚𝗦</b>\n\n<blockquote>✅ No error logs recorded! Everything is running smoothly.</blockquote>"
        else:
            parts = []
            for item in logs:
                ts = time.strftime("%H:%M:%S", time.localtime(item.get("at", 0)))
                badge = "✅ FIXED BY AI" if item.get("resolved") else "❌ UNRESOLVED"
                parts.append(
                    f"• <code>[{ts}]</code> [{badge}] <b>{esc(item.get('source'))}</b>\n"
                    f"  └ <code>{esc((item.get('error') or '')[:120])}</code>"
                )
            txt = (
                f"🚨 • <b>𝗥𝗘𝗖𝗘𝗡𝗧 𝗘𝗥𝗥𝗢𝗥 𝗟𝗢𝗚𝗦 ({len(self.db.local_logs)})</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n"
                f"<blockquote>" + "\n\n".join(parts) + "</blockquote>"
            )
        kb = {
            "inline_keyboard": [
                [{"text": "🤖 Auto-Fix All Errors with AI", "callback_data": "adm:ai_run_scan", "style": "success"}],
                [
                    {"text": "🗑 Clear All Logs", "callback_data": "adm:clear_logs", "style": "danger"},
                    {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                ],
            ]
        }
        if edit_id:
            await self.edit_message(chat_id, edit_id, txt, reply_markup=kb)
        else:
            await self.send_message(chat_id, txt, reply_to=msg_id, reply_markup=kb)

    async def _run_broadcast(self, chat_id: int, msg_id: int | None, text: str):
        uids = await self.db.get_all_user_ids(include_banned=False)
        status_msg = await self.send_message(
            chat_id,
            f"📢 <b>Broadcasting message to <code>{len(uids)}</code> users…</b>",
            reply_to=msg_id,
        )
        sid = ((status_msg or {}).get("result") or {}).get("message_id")
        sent_ok = 0
        failed = 0
        formatted = f"📢 • <b>𝗔𝗡𝗡𝗢𝗨𝗡𝗖𝗘𝗠𝗘𝗡𝗧</b>\n━━━━━━━━━━━━━━━━━━━━━━\n<blockquote>{text}</blockquote>"
        for uid in uids:
            r = await self.send_message(uid, formatted)
            if r and r.get("ok"):
                sent_ok += 1
            else:
                failed += 1
            await asyncio.sleep(0.05)
        done_txt = (
            f"✅ • <b>𝗕𝗥𝗢𝗔𝗗𝗖𝗔𝗦𝗧 𝗖𝗢𝗠𝗣𝗟𝗘𝗧𝗘</b>\n\n"
            f"<blockquote>• <b>Delivered :</b> <code>{sent_ok}</code>\n"
            f"• <b>Failed / Blocked :</b> <code>{failed}</code></blockquote>"
        )
        if sid:
            await self.edit_message(chat_id, sid, done_txt)
        else:
            await self.send_message(chat_id, done_txt, reply_to=msg_id)

    # ------------------------------------------------- Interactive Admin Input
    async def _handle_admin_state_input(self, chat_id: int, user_id: int, msg_id: int, text: str):
        state = self._admin_states.pop(user_id, None)
        if not state:
            return
        action = state.get("action")
        if action == "set_proxy":
            await self._cmd_setproxy(chat_id, msg_id, text)
        elif action == "add_fsub":
            await self._cmd_addfsub(chat_id, msg_id, text)
        elif action == "add_cache":
            parts = [p.strip() for p in text.split("|") if p.strip()]
            if len(parts) < 2:
                parts = text.split()
            if len(parts) >= 2:
                entry = await self.db.set_cache(parts[0], {"url": parts[1], "method": "admin"})
                await self.send_message(
                    chat_id,
                    f"✅ <b>Saved to Cloud Cache:</b>\n<blockquote><code>{esc(entry['source'])}</code>\n➡️ <code>{esc(entry['url'])}</code></blockquote>",
                    reply_to=msg_id,
                )
            else:
                await self.send_message(chat_id, "⚠️ Invalid format. Send: <code>shortlink | destination_url</code>", reply_to=msg_id)
        elif action == "del_cache":
            ok = await self.db.delete_cache(text.strip())
            await self.send_message(
                chat_id,
                f"{'✅ Deleted from cache:' if ok else '⚠️ Not found in cache:'} <code>{esc(text)}</code>",
                reply_to=msg_id,
            )
        elif action == "broadcast":
            await self._run_broadcast(chat_id, msg_id, text)
        elif action == "ban_user":
            try:
                uid = int(text.strip())
                await self.db.set_user_banned(uid, True)
                await self.send_message(chat_id, f"🚫 <b>Banned user:</b> <code>{uid}</code>", reply_to=msg_id)
            except Exception:
                await self.send_message(chat_id, "⚠️ Invalid User ID.", reply_to=msg_id)
        elif action == "unban_user":
            try:
                uid = int(text.strip())
                await self.db.set_user_banned(uid, False)
                await self.send_message(chat_id, f"✅ <b>Unbanned user:</b> <code>{uid}</code>", reply_to=msg_id)
            except Exception:
                await self.send_message(chat_id, "⚠️ Invalid User ID.", reply_to=msg_id)
        elif action == "set_welcome":
            await self.db.update_settings({"welcome_message": text})
            await self.send_message(chat_id, "✅ <b>Updated Welcome Message!</b>", reply_to=msg_id)
        elif action == "set_photo":
            await self.db.update_settings({"start_photo": text.strip()})
            await self.send_message(chat_id, f"✅ <b>Updated Start Photo URL:</b>\n<code>{esc(text.strip())}</code>", reply_to=msg_id)
        elif action == "set_cache_hours":
            try:
                h = float(text.strip())
                await self.db.update_settings({"cache_hours": h})
                await self.send_message(chat_id, f"✅ <b>Cache TTL updated to <code>{h}</code> hours.</b>", reply_to=msg_id)
            except Exception:
                await self.send_message(chat_id, "⚠️ Invalid number.", reply_to=msg_id)
        elif action == "add_prem":
            await self._cmd_addpremium(chat_id, user_id, msg_id, text.strip())
        elif action == "del_prem":
            await self._cmd_removepremium(chat_id, user_id, msg_id, text.strip())
        elif action == "ai_prompt":
            if self.ai_engineer:
                urls = URL_RE.findall(text)
                run_info = await self.ai_engineer.start_run(
                    trigger="telegram_admin",
                    target_url=urls[0] if urls else "",
                    prompt=text,
                )
                await self.send_message(
                    chat_id,
                    f"🤖 • <b>𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 𝗦𝗧𝗔𝗥𝗧𝗘𝗗 (<code>{esc(run_info.get('id'))}</code>)</b>\n"
                    f"<blockquote>🧠 Analyzing logs, probing shortener origin &amp; running live checks for:\n"
                    f"<code>{esc(text)}</code>\n\n"
                    f"Watch live step-by-step reasoning in the Web Admin Panel — a full completion report will be sent here automatically!</blockquote>",
                    reply_to=msg_id,
                    reply_markup={"inline_keyboard": [[{"text": "🤖 Open AI Menu", "callback_data": "adm:ai_menu"}]]},
                )
            else:
                await self.send_message(chat_id, "⚠️ AI Engineer not initialized.", reply_to=msg_id)

    # ------------------------------------------------- Callback Query Handler
    async def _on_callback(self, cb: dict):
        cb_id = cb.get("id")
        data = cb.get("data") or ""
        from_user = cb.get("from") or {}
        user_id = int(from_user.get("id") or 0)
        msg = cb.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        msg_id = msg.get("message_id")
        if not chat_id or not user_id:
            return
        if msg_id and msg.get("photo"):
            self._photo_msg_ids.add((chat_id, int(msg_id)))
        edit_target = int(msg_id) if msg_id else None

        if data == "usr:verify_fsub":
            missing = await self.check_force_sub(user_id, force_refresh=True)
            if missing:
                ch_names = ", ".join(str(c.get("title") or "Channel") for c in missing)
                await self.api(
                    "answerCallbackQuery",
                    {
                        "callback_query_id": cb_id,
                        "text": f"❌ You haven't joined {ch_names} yet! Tap the Join button first, then press Verify.",
                        "show_alert": True,
                    },
                )
                return
            await self.api(
                "answerCallbackQuery",
                {"callback_query_id": cb_id, "text": "✅ Membership verified! Welcome to TheDrunkBots.", "show_alert": False},
            )
            pending_urls = self._fsub_pending_urls.pop(user_id, None)
            await self._cmd_start(chat_id, user_id, from_user, None, edit_id=edit_target)
            if pending_urls:
                await asyncio.gather(*(
                    self._process_bypass(chat_id, user_id, from_user, msg_id, u)
                    for u in pending_urls[:50]
                ))
            return

        if not self.db.is_admin(user_id) and data.startswith("usr:"):
            missing = await self.check_force_sub(user_id)
            if missing:
                await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
                f_txt, f_kb = self.build_fsub_prompt(missing, user=from_user)
                if edit_target:
                    await self.edit_message(chat_id, edit_target, f_txt, reply_markup=f_kb)
                else:
                    await self.send_message(chat_id, f_txt, reply_markup=f_kb)
                return

        if data == "usr:premium":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            await self._cmd_buy_premium(chat_id, user_id, from_user, None, edit_id=edit_target)
            return

        if data == "usr:myplan":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            await self._cmd_myplan(chat_id, user_id, from_user, None, edit_id=edit_target)
            return

        if data.startswith("plan_select_"):
            plan_key = data.split("plan_select_", 1)[1].strip()
            await self._handle_plan_select(chat_id, user_id, from_user, plan_key, edit_id=edit_target, cb_id=cb_id)
            return

        if data.startswith("pmt_done_"):
            order_id = data.split("pmt_done_", 1)[1].strip()
            await self._handle_pmt_done(chat_id, user_id, order_id, edit_id=edit_target, cb_id=cb_id)
            return

        if data.startswith("pmt_cancel_"):
            order_id = data.split("pmt_cancel_", 1)[1].strip()
            await self._handle_pmt_cancel(chat_id, user_id, from_user, order_id, edit_id=edit_target, cb_id=cb_id)
            return

        if data == "usr:help":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            await self._cmd_help(chat_id, user_id, None, edit_id=edit_target)
            return

        if data == "usr:status":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            await self._cmd_status(chat_id, user_id, None, edit_id=edit_target)
            return

        if data == "usr:myinfo":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            udoc = await self.db.touch_user(from_user)
            await self._cmd_myinfo(chat_id, udoc, None, edit_id=edit_target)
            return

        if data == "usr:start":
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            await self._cmd_start(chat_id, user_id, from_user, None, edit_id=edit_target)
            return

        if data.startswith("loop:conc:"):
            try:
                await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            except Exception:
                pass
            try:
                conc = int(data.split(":")[-1])
                if conc < 1 or conc > 5:
                    raise ValueError("concurrency must be 1-5")
                state = self._user_states.get(user_id) or {}
                if state.get("step") != "concurrency":
                    await self.send_message(
                        chat_id,
                        "⚠ Concurrency step is not active. Run <b>/loop_setup</b> again.",
                        reply_to=msg_id,
                    )
                    return
                await self._finish_loop_setup(chat_id, user_id, state, conc, msg_id)
            except Exception as e:
                print(f"loop conc callback error uid={user_id}: {e}", flush=True)
                await self.send_message(
                    chat_id,
                    f"⚠ Loop error: <code>{html.escape(str(e)[:180])}</code>",
                    reply_to=msg_id,
                )
            return

        if data in ("loop:start", "loop:setup", "loop:stop", "loop:status"):
            try:
                await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            except Exception:
                pass
            try:
                if data == "loop:start":
                    await self._cmd_loop_start(chat_id, user_id, from_user, msg_id)
                elif data == "loop:setup":
                    await self._cmd_loop_setup(chat_id, user_id, from_user, msg_id)
                elif data == "loop:stop":
                    await self._cmd_loop_stop(chat_id, user_id, msg_id)
                else:
                    await self._cmd_loop_status(chat_id, user_id, msg_id)
            except Exception as e:
                print(f"loop callback {data} error uid={user_id}: {e}", flush=True)
                await self.send_message(
                    chat_id,
                    f"⚠ Loop error: <code>{html.escape(str(e)[:180])}</code>",
                    reply_to=msg_id,
                )
            return

        # Admin callbacks
        if data.startswith("adm:"):
            if not self.db.is_admin(user_id):
                await self.api(
                    "answerCallbackQuery",
                    {"callback_query_id": cb_id, "text": "⛔ Admin access only!", "show_alert": True},
                )
                return
            await self.api("answerCallbackQuery", {"callback_query_id": cb_id})
            edit_target = int(msg_id) if msg_id else None

            if data == "adm:home":
                self._admin_states.pop(user_id, None)
                await self._send_admin_panel(chat_id, edit_id=edit_target)
                return

            if data == "adm:prem_menu":
                self._admin_states.pop(user_id, None)
                await self._cmd_premiumusers(chat_id, user_id, edit_id=edit_target)
                return

            if data == "adm:add_prem_prompt":
                self._admin_states[user_id] = {"action": "add_prem"}
                txt = (
                    "💎 • <b>𝗔𝗗𝗗 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗨𝗦𝗘𝗥</b>\n\n"
                    "<blockquote>Send the User ID, Plan Type, and Days separated by spaces:\n"
                    "<code>123456789 1_month 30</code>\n"
                    "or\n"
                    "<code>123456789 3_months 90</code>\n\n"
                    "Send /cancel to abort.</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:prem_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:del_prem_prompt":
                self._admin_states[user_id] = {"action": "del_prem"}
                txt = (
                    "🗑 • <b>𝗥𝗘𝗠𝗢𝗩𝗘 𝗣𝗥𝗘𝗠𝗜𝗨𝗠 𝗨𝗦𝗘𝗥</b>\n\n"
                    "<blockquote>Send the numeric Telegram User ID whose Premium subscription you want to revoke:</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:prem_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:set_proxy":
                self._admin_states[user_id] = {"action": "set_proxy"}
                txt = (
                    "🌐 • <b>𝗦𝗘𝗧 𝗧𝗨𝗡𝗡𝗘𝗟 / 𝗣𝗥𝗢𝗫𝗬</b>\n\n"
                    "<blockquote>Send the new Pinggy / residential proxy URL now in the format:\n"
                    "<code>http://user:pass@host:port</code>\n\n"
                    "Or send <code>off</code> for direct connection.\n"
                    "Send /cancel to abort.</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Cancel", "callback_data": "adm:home"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:clear_proxy":
                await self.set_proxy_fn(None)
                await self._send_admin_panel(chat_id, edit_id=edit_target)
                return

            if data == "adm:test_proxy":
                await self._cmd_testproxy(chat_id, None, edit_id=edit_target)
                return

            if data == "adm:toggle_cache":
                cur = bool(self.db.settings.get("cache_enabled", True))
                await self.db.update_settings({"cache_enabled": not cur})
                await self._send_admin_panel(chat_id, edit_id=edit_target)
                return

            if data == "adm:fsub_menu":
                await self._cmd_listfsub(chat_id, None, edit_id=edit_target)
                return

            if data == "adm:fsub_refresh":
                await self.sync_all_fsub_channels(force_new_invite=True)
                await self._cmd_listfsub(chat_id, None, edit_id=edit_target)
                return

            if data == "adm:toggle_fsub":
                cur = bool(self.db.settings.get("force_sub_enabled", True))
                await self.db.update_settings({"force_sub_enabled": not cur})
                await self._cmd_listfsub(chat_id, None, edit_id=edit_target)
                return

            if data == "adm:add_fsub_prompt":
                self._admin_states[user_id] = {"action": "add_fsub"}
                txt = (
                    "📢 • <b>𝗔𝗗𝗗 𝗙𝗢𝗥𝗖𝗘-𝗦𝗨𝗕 𝗖𝗛𝗔𝗡𝗡𝗘𝗟</b>\n\n"
                    "<blockquote>Send the channel username or ID now:\n"
                    "Example 1: <code>@TheDrunkBots</code>\n"
                    "Example 2: <code>-1001234567890 https://t.me/+inviteLink My Channel</code>\n\n"
                    "Make sure the bot is an Admin in that channel!</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:fsub_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data.startswith("adm:del_fsub:"):
                cid = data.split("adm:del_fsub:", 1)[1]
                channels = [
                    c for c in (self.db.settings.get("force_sub_channels") or [])
                    if str(c.get("chat_id", "")).lower() != cid.lower()
                ]
                await self.db.update_settings({"force_sub_channels": channels})
                await self._cmd_listfsub(chat_id, None, edit_id=edit_target)
                return

            if data == "adm:cache_menu":
                items = await self.db.list_cache(limit=6)
                lines = [
                    f"• <code>{esc(i['source'])}</code>\n  ➡️ <code>{esc(i['url'][:65])}</code> (hits: {i.get('hits', 0)})"
                    for i in items
                ]
                body = "\n".join(lines) if lines else "Cache is currently empty."
                txt = (
                    f"🗄 • <b>𝗖𝗟𝗢𝗨𝗗 𝗖𝗔𝗖𝗛𝗘 𝗠𝗔𝗡𝗔𝗚𝗘𝗥 ({len(self.db.local_cache)} items)</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>{body}</blockquote>"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "➕ Add / Edit Cache", "callback_data": "adm:add_cache_prompt", "style": "success"},
                            {"text": "🗑 Delete Cache Link", "callback_data": "adm:del_cache_prompt"},
                        ],
                        [
                            {"text": "🔥 Clear Entire Cache", "callback_data": "adm:clear_cache_confirm", "style": "danger"},
                            {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                        ],
                    ]
                }
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:add_cache_prompt":
                self._admin_states[user_id] = {"action": "add_cache"}
                txt = (
                    "➕ • <b>𝗔𝗗𝗗 / 𝗠𝗢𝗗𝗜𝗙𝗬 𝗖𝗔𝗖𝗛𝗘 𝗘𝗡𝗧𝗥𝗬</b>\n\n"
                    "<blockquote>Send the shortlink and destination URL separated by <code>|</code>:\n"
                    "<code>https://lksfy.com/abc | https://t.me/dest</code></blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:cache_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:del_cache_prompt":
                self._admin_states[user_id] = {"action": "del_cache"}
                txt = "🗑 • <b>𝗗𝗘𝗟𝗘𝗧𝗘 𝗖𝗔𝗖𝗛𝗘 𝗘𝗡𝗧𝗥𝗬</b>\n\n<blockquote>Send the shortlink URL you want to delete from cache:</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:cache_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:clear_cache_confirm":
                await self.db.clear_cache()
                await self._send_admin_panel(chat_id, edit_id=edit_target)
                return

            if data == "adm:logs_menu":
                await self._cmd_logs(chat_id, edit_id=edit_target)
                return

            if data == "adm:clear_logs":
                await self.db.clear_error_logs()
                await self._cmd_logs(chat_id, edit_id=edit_target)
                return

            if data == "adm:users_menu":
                users = await self.db.list_users(limit=8)
                lines = []
                for u in users:
                    st_lbl = "🚫 BANNED" if u.get("banned") else f"✅ {u.get('bypass_count', 0)} links"
                    lines.append(
                        f"• <code>{u['user_id']}</code> — {esc(u.get('first_name'))} "
                        f"(@{esc(u.get('username') or 'none')}) [{st_lbl}]"
                    )
                body = "\n".join(lines) if lines else "No users recorded yet."
                txt = (
                    f"👥 • <b>𝗨𝗦𝗘𝗥𝗦 &amp; 𝗕𝗥𝗢𝗔𝗗𝗖𝗔𝗦𝗧 ({len(self.db.local_users)} total)</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>{body}</blockquote>"
                )
                kb = {
                    "inline_keyboard": [
                        [{"text": "📢 Broadcast Message to All Users", "callback_data": "adm:broadcast_prompt", "style": "primary"}],
                        [
                            {"text": "🚫 Ban User ID", "callback_data": "adm:ban_prompt", "style": "danger"},
                            {"text": "✅ Unban User ID", "callback_data": "adm:unban_prompt", "style": "success"},
                        ],
                        [{"text": "🔙 Back to Admin Panel", "callback_data": "adm:home"}],
                    ]
                }
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:broadcast_prompt":
                self._admin_states[user_id] = {"action": "broadcast"}
                txt = "📢 • <b>𝗕𝗥𝗢𝗔𝗗𝗖𝗔𝗦𝗧 𝗠𝗘𝗦𝗦𝗔𝗚𝗘</b>\n\n<blockquote>Send the message text (HTML supported) you want to broadcast to all users:</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:users_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:ban_prompt":
                self._admin_states[user_id] = {"action": "ban_user"}
                txt = "🚫 • <b>𝗕𝗔𝗡 𝗨𝗦𝗘𝗥</b>\n\n<blockquote>Send the numeric Telegram User ID to ban:</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:users_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:unban_prompt":
                self._admin_states[user_id] = {"action": "unban_user"}
                txt = "✅ • <b>𝗨𝗡𝗕𝗔𝗡 𝗨𝗦𝗘𝗥</b>\n\n<blockquote>Send the numeric Telegram User ID to unban:</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:users_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:settings_menu":
                s = self.db.settings
                maint = "🟡 ON" if s.get("maintenance_mode") else "🟢 OFF"
                prot = "🔒 ON" if s.get("protect_content") else "🔓 OFF"
                txt = (
                    f"⚙️ • <b>𝗕𝗢𝗧 &amp; 𝗘𝗡𝗚𝗜𝗡𝗘 𝗦𝗘𝗧𝗧𝗜𝗡𝗚𝗦</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>• <b>Brand :</b> <code>{esc(s.get('brand_name'))}</code>\n"
                    f"• <b>Maintenance Mode :</b> <code>{maint}</code>\n"
                    f"• <b>Protect Content :</b> <code>{prot}</code>\n"
                    f"• <b>Cache TTL :</b> <code>{s.get('cache_hours', 24)} hours</code>\n"
                    f"• <b>Engine Timeout :</b> <code>{s.get('timeout', 300)}s</code>\n"
                    f"• <b>Start Photo :</b> <code>{esc((s.get('start_photo') or '')[:45])}</code>\n"
                    f"• <b>Admins :</b> <code>{esc(s.get('admin_ids'))}</code></blockquote>"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": f"🛠 Maintenance: {maint}", "callback_data": "adm:toggle_maint"},
                            {"text": f"🔒 Protect: {prot}", "callback_data": "adm:toggle_prot"},
                        ],
                        [
                            {"text": "🖼 Edit Start Photo", "callback_data": "adm:set_photo_prompt"},
                            {"text": "💬 Edit Welcome Text", "callback_data": "adm:set_welcome_prompt"},
                        ],
                        [
                            {"text": "⏱ Edit Cache Hours", "callback_data": "adm:set_cache_hours_prompt"},
                            {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                        ],
                    ]
                }
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:toggle_maint":
                cur = bool(self.db.settings.get("maintenance_mode", False))
                await self.db.update_settings({"maintenance_mode": not cur})
                cb["data"] = "adm:settings_menu"
                await self._on_callback(cb)
                return

            if data == "adm:toggle_prot":
                cur = bool(self.db.settings.get("protect_content", False))
                await self.db.update_settings({"protect_content": not cur})
                cb["data"] = "adm:settings_menu"
                await self._on_callback(cb)
                return

            if data == "adm:set_photo_prompt":
                self._admin_states[user_id] = {"action": "set_photo"}
                txt = "🖼 • <b>𝗦𝗘𝗧 𝗦𝗧𝗔𝗥𝗧 𝗣𝗛𝗢𝗧𝗢 𝗨𝗥𝗟</b>\n\n<blockquote>Send the direct image URL for /start:</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:settings_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:set_welcome_prompt":
                self._admin_states[user_id] = {"action": "set_welcome"}
                txt = (
                    "💬 • <b>𝗦𝗘𝗧 𝗪𝗘𝗟𝗖𝗢𝗠𝗘 𝗠𝗘𝗦𝗦𝗔𝗚𝗘</b>\n\n"
                    "<blockquote>Send the new welcome message (HTML allowed; use <code>{first_name}</code> and <code>{brand}</code> placeholders):</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:settings_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:set_cache_hours_prompt":
                self._admin_states[user_id] = {"action": "set_cache_hours"}
                txt = "⏱ • <b>𝗦𝗘𝗧 𝗖𝗔𝗖𝗛𝗘 𝗧𝗧𝗟 (𝗛𝗢𝗨𝗥𝗦)</b>\n\n<blockquote>Send the number of hours to keep resolved links in cache (e.g. <code>24</code>):</blockquote>"
                kb = {"inline_keyboard": [[{"text": "🔙 Back", "callback_data": "adm:settings_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:tunnels_menu" or data.startswith("adm:dev_"):
                await self.db.sync_tunnels_from_mongo()
                if data.startswith("adm:dev_toggle:"):
                    did_prefix = data.split(":", 2)[2]
                    did = next((k for k in self.db.local_tunnels if k.startswith(did_prefix)), did_prefix)
                    cur_d = self.db.local_tunnels.get(did) or {}
                    await self.db.set_tunnel_device_enabled(did, not bool(cur_d.get("enabled", True)))
                elif data.startswith("adm:dev_primary:"):
                    did_prefix = data.split(":", 2)[2]
                    did = next((k for k in self.db.local_tunnels if k.startswith(did_prefix)), did_prefix)
                    await self.db.set_primary_tunnel_device(did)

                devs = await self.db.list_tunnel_devices()
                online_cnt = sum(1 for d in devs if d.get("online"))
                lines = []
                rows = []
                for d in devs[:8]:
                    icon = "📱" if d.get("device_type") == "android" else "💻"
                    did = d["device_id"]
                    name = d.get("device_name") or did
                    role = d.get("role") or "OFFLINE"
                    ip = d.get("public_ip") or "—"
                    en = bool(d.get("enabled", True))
                    lines.append(
                        f"{icon} <b>{esc(name)}</b> (<code>{esc(ip)}</code>)\n"
                        f"   └ Status: <code>{esc(role)}</code> | Reqs: <code>{d.get('total_requests', 0)}</code>"
                    )
                    rows.append([
                        {
                            "text": f"{'🟢 ON' if en else '🔴 OFF'}: {name[:16]}",
                            "callback_data": f"adm:dev_toggle:{did[:36]}",
                        },
                        {
                            "text": "⭐ Primary" if d.get("is_active_selected") else "⚡ Set Primary",
                            "callback_data": f"adm:dev_primary:{did[:36]}",
                        },
                    ])
                body = "\n".join(lines) if lines else "No tunnel devices connected yet. Install the Android APK or PC Software!"
                txt = (
                    f"📱💻 • <b>𝗖𝗢𝗡𝗡𝗘𝗖𝗧𝗘𝗗 𝗧𝗨𝗡𝗡𝗘𝗟 𝗗𝗘𝗩𝗜𝗖𝗘𝗦 ({online_cnt}/{len(devs)} Online)</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>{body}</blockquote>\n"
                    f"<i>Select a Primary device; other enabled devices remain Standby/Fallback with zero conflict.</i>"
                )
                rows.append([
                    {"text": "🔄 Refresh Devices", "callback_data": "adm:tunnels_menu"},
                    {"text": "🔙 Back to Admin Panel", "callback_data": "adm:home"},
                ])
                kb = {"inline_keyboard": rows}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:shorteners_menu" or data.startswith("adm:sh_"):
                if data.startswith("adm:sh_toggle:"):
                    dom = data.split(":", 2)[2]
                    cur_on = self.db.should_use_tunnel_for_url(dom)
                    await self.db.set_shortener_tunnel(dom, not cur_on)
                elif data == "adm:sh_all:on":
                    await self.db.set_all_shortener_tunnels(True)
                elif data == "adm:sh_all:off":
                    await self.db.set_all_shortener_tunnels(False)

                sh_list = self.db.get_shortener_tunnel_list()
                on_cnt = sum(1 for s in sh_list if s.get("enabled"))
                rows = [
                    [
                        {"text": "✅ Enable All", "callback_data": "adm:sh_all:on"},
                        {"text": "🚫 Disable All (Default)", "callback_data": "adm:sh_all:off"},
                    ]
                ]
                pair = []
                for s in sh_list[:20]:
                    dom = s["domain"]
                    en = s["enabled"]
                    pair.append({
                        "text": f"{'🟢' if en else '⚪'} {dom}",
                        "callback_data": f"adm:sh_toggle:{dom}",
                    })
                    if len(pair) == 2:
                        rows.append(pair)
                        pair = []
                if pair:
                    rows.append(pair)
                rows.append([{"text": "🔙 Back to Admin Panel", "callback_data": "adm:home"}])
                txt = (
                    f"🔀 • <b>𝗦𝗛𝗢𝗥𝗧𝗘𝗡𝗘𝗥 𝗧𝗨𝗡𝗡𝗘𝗟 𝗥𝗢𝗨𝗧𝗜𝗡𝗚 ({on_cnt}/{len(sh_list)} ON)</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>• <b>🟢 Green</b> = Solves via Active Tunnel Device\n"
                    f"• <b>⚪ Grey (Default)</b> = Solves via Direct Connection\n\n"
                    f"Tap any shortener below to toggle its tunnel routing live immediately!</blockquote>"
                )
                kb = {"inline_keyboard": rows}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:ai_menu":
                await self._send_ai_menu(chat_id, edit_id=edit_target)
                return

            if data == "adm:ai_toggle_heal":
                cur = bool(self.db.settings.get("ai_auto_heal", True))
                await self.db.update_settings({"ai_auto_heal": not cur})
                await self._send_ai_menu(chat_id, edit_id=edit_target)
                return

            if data == "adm:ai_toggle_patrol":
                cur = bool(self.db.settings.get("ai_patrol_enabled", True))
                await self.db.update_settings({"ai_patrol_enabled": not cur})
                await self._send_ai_menu(chat_id, edit_id=edit_target)
                return

            if data == "adm:ai_run_scan":
                if self.ai_engineer:
                    run_info = await self.ai_engineer.start_run(
                        trigger="telegram_admin",
                        prompt="Scan all unresolved error logs, diagnose root causes, apply fixes, verify live, and push.",
                    )
                    txt = (
                        f"🤖 • <b>𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 𝗦𝗖𝗔𝗡 𝗦𝗧𝗔𝗥𝗧𝗘𝗗 (<code>{esc(run_info.get('id'))}</code>)</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"<blockquote>🧠 The Autonomous AI Engineer is now scanning unresolved error logs, probing origin IPs, "
                        f"applying fixes &amp; running live bypass checks.\n\n"
                        f"You can watch live step-by-step reasoning in the Web Admin Panel or tap <b>🔄 Refresh AI Status</b> below!</blockquote>"
                    )
                else:
                    txt = "⚠️ AI Engineer not initialized."
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "🔄 Refresh AI Status", "callback_data": "adm:ai_menu", "style": "primary"},
                            {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                        ],
                    ]
                }
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:ai_prompt":
                self._admin_states[user_id] = {"action": "ai_prompt"}
                txt = (
                    "🤖 • <b>𝗚𝗜𝗩𝗘 𝗔𝗜 𝗘𝗡𝗚𝗜𝗡𝗘𝗘𝗥 𝗔 𝗧𝗔𝗦𝗞</b>\n\n"
                    "<blockquote>Send any broken shortener link or engineering instruction now (e.g.:\n"
                    "<code>Fix https://get2short.com/Pg6a and verify live</code>\n"
                    "or simply send a URL).\n\n"
                    "Send /cancel to abort.</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back to AI Menu", "callback_data": "adm:ai_menu"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data in ("adm:code_sync_menu", "adm:code_sync_now"):
                sync_note = ""
                if data == "adm:code_sync_now" and self.code_sync:
                    res_s = await self.code_sync.sync_all_to_mongo_and_github(reason="Admin triggered Telegram sync")
                    m_cnt = len(res_s.get("mongo_synced") or [])
                    g_cnt = len(res_s.get("github_pushed") or [])
                    sync_note = f"\n✅ <b>Synced {m_cnt} files to MongoDB &amp; {g_cnt} files to GitHub!</b>\n"
                st_info = await self.code_sync.get_status() if self.code_sync else {}
                f_lines = []
                for f in (st_info.get("files") or [])[:8]:
                    badge = "🤖 AI-Updated" if f.get("ai_modified") else "📦 Baseline"
                    f_lines.append(f"• <code>{esc(f.get('path'))}</code> — rev #{f.get('revision', 1)} [{badge}]")
                body = "\n".join(f_lines) if f_lines else "Code files tracked in MongoDB."
                gh_lbl = "🟢 Token Configured" if st_info.get("github_configured") else "⚪ MongoDB Cloud Active (Add GH Token in Web UI)"
                txt = (
                    f"☁️ • <b>𝗖𝗢𝗗𝗘 𝗦𝗬𝗡𝗖 &amp; 𝗔𝗡𝗧𝗜-𝗥𝗢𝗟𝗟𝗕𝗔𝗖𝗞 𝗚𝗨𝗔𝗥𝗗</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"<blockquote>• 🗄 <b>MongoDB Code Vault :</b> <code>{'Connected' if self.db.connected else 'Local'}</code>\n"
                    f"• 🐙 <b>GitHub Repo :</b> <code>{esc(st_info.get('github_repo', 'Urvashi212144/gss-free'))} ({gh_lbl})</code>\n"
                    f"• 🛡 <b>Boot Anti-Rollback :</b> <code>ACTIVE (Restores AI code on VPS/Railway restart)</code></blockquote>"
                    f"{sync_note}\n"
                    f"📂 <b>𝗧𝗥𝗔𝗖𝗞𝗘𝗗 𝗖𝗢𝗗𝗘𝗕𝗔𝗦𝗘 𝗙𝗜𝗟𝗘𝗦 :</b>\n"
                    f"<blockquote>{body}</blockquote>"
                )
                kb = {
                    "inline_keyboard": [
                        [
                            {"text": "☁️ Sync Code Now", "callback_data": "adm:code_sync_now", "style": "success"},
                            {"text": "🔙 Admin Panel", "callback_data": "adm:home"},
                        ],
                    ]
                }
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                return

            if data == "adm:restart_bot":
                txt = (
                    "⚡ • <b>𝗥𝗘𝗦𝗧𝗔𝗥𝗧𝗜𝗡𝗚 𝗕𝗢𝗧 &amp; 𝗪𝗢𝗥𝗞𝗘𝗥 𝗣𝗢𝗢𝗟</b>\n"
                    "━━━━━━━━━━━━━━━━━━━━━━\n"
                    "<blockquote>🔄 Pulling latest verified code &amp; rules from MongoDB Atlas, closing browser workers cleanly, and restarting process now…\n\n"
                    "✅ The bot will be back online in ~2–3 seconds!</blockquote>"
                )
                kb = {"inline_keyboard": [[{"text": "🔙 Back to Admin Panel", "callback_data": "adm:home"}]]}
                if edit_target:
                    await self.edit_message(chat_id, edit_target, txt, reply_markup=kb)
                else:
                    await self.send_message(chat_id, txt, reply_markup=kb)
                if self.code_sync:
                    await self.code_sync.hydrate_from_mongo_on_boot()
                    asyncio.create_task(self.code_sync.trigger_graceful_restart(reason="Admin triggered restart from Telegram Panel"))
                return

