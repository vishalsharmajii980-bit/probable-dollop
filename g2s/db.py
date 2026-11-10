"""
MongoDB + local JSON persistence & real-time synchronization layer for TheDrunkBots G2S.
Handles:
  - Live settings & credentials (proxy/tunnel, bot token, api_id, api_hash, owner/admin IDs,
    web admin password, force-subscribe channels, welcome message, start photo, etc.)
  - Cloud link cache (full CRUD: get, add/upsert, edit, delete, clear, search)
  - Complete error logs (stored for Web Admin Panel + forwarded to Admin on Telegram)
  - Telegram users registry (stats, ban/unban, broadcast targets)
"""
import asyncio
import json
import os
import time
import uuid
from typing import Any

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    HAS_MOTOR = True
except ImportError:  # pragma: no cover
    AsyncIOMotorClient = None
    HAS_MOTOR = False

DEFAULT_MONGO_URI = (
    "mongodb+srv://shauryasharma9940_db_user:hi1OxTU3GdXFtRLf"
    "@g2sv2.fnvvosz.mongodb.net/?appName=G2SV2"
)
DEFAULT_START_PHOTO = "https://i.ibb.co/1Nx1jMn/IMG-20261005-021725.png"
DEFAULT_BRAND = "TheDrunkBots"
DEFAULT_WELCOME = (
    "👋 <b>Hey {first_name}!</b>\n"
    "<blockquote>⚡ <b>Send me any supported shortlink and I will bypass ads, "
    "timers & captchas automatically to give you the direct destination link!</b></blockquote>\n\n"
    "✨ <b>𝗙𝗘𝗔𝗧𝗨𝗥𝗘𝗦 :</b>\n"
    "<blockquote>• 🚀 <b>Instant Cloud Cache</b> (0.01s for repeated links)\n"
    "• 📊 <b>Live Progress Bar & ETA</b> while bypassing\n"
    "• 🛡 <b>Auto Turnstile & Multi-Step Solver</b>\n"
    "• 🔗 <b>25+ Shorteners Supported</b></blockquote>\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
)

DEFAULT_FORCE_SUB_CHANNELS = [
    {
        "chat_id": "-1003768452343",
        "api_chat_id": "-1004462643599",
        "title": "TheDrunkBots Official",
        "invite_link": "https://t.me/+e2xem-7b7-c3ZTM1",
    }
]

DEFAULT_PROTECTED_MESSAGE = (
    "🛡 • <b>𝗣𝗥𝗢𝗧𝗘𝗖𝗧𝗘𝗗 𝗟𝗜𝗡𝗞 𝗗𝗘𝗧𝗘𝗖𝗧𝗘𝗗</b>\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "🚫 <b>This link cannot be bypassed!</b>\n\n"
    "<blockquote>🔒 <b>Official Protected Link</b>\n"
    "This short link belongs to one of our own official bots and is protected by us under <b>TheDrunkBots Security Shield</b>.</blockquote>\n\n"
    "💡 <i>Please open the link in your browser and complete the verification steps directly to support our bots and unlock your content.</i>\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "🏷 <b>𝗣𝗢𝗪𝗘𝗥𝗘𝗗 𝗕𝗬 :</b> @TheDrunkBots"
)

DEFAULT_PROTECTED_BOTS = [
    {
        "id": "web-series-bot-new",
        "name": "WEB-SERIES-BOT-NEW",
        "username": "TheOnlyFapsRoBot",
        "repo": "https://github.com/amazedreamer/WEB-SERIES-BOT-NEW",
        "db_name": "OnlyFapsFileShareBot",
        "enabled": True,
    },
    {
        "id": "the-viral-meme-new",
        "name": "THE-VIRAL-MEME-NEW",
        "username": "D2NEWSxRoBot",
        "repo": "https://github.com/amazedreamer/THE-VIRAL-MEME-NEW",
        "db_name": "TheToxicMeme",
        "enabled": True,
    },
    {
        "id": "xd-free-dish",
        "name": "XD-Free-Dish",
        "username": "DDNewsXDBot",
        "repo": "https://github.com/amazedreamer/XD-Free-Dish",
        "db_name": "NewUpdate",
        "enabled": True,
    },
    {
        "id": "dd-free-dish-2-0",
        "name": "DD-Free-Dish-2.0",
        "username": "OGNewsRoBot",
        "repo": "https://github.com/amazedreamer/DD-Free-Dish-2.0",
        "db_name": "DailyPrimeNews",
        "enabled": True,
    },
    {
        "id": "dx-free-dish-new",
        "name": "DX-FREE-DISH-NEW",
        "username": "NewsAndFormatBot",
        "repo": "https://github.com/amazedreamer/DX-FREE-DISH-NEW",
        "db_name": "RealmeUneven",
        "enabled": True,
    },
    {
        "id": "the-eb-new",
        "name": "THE-EB-NEW",
        "username": "ThePinkNewsRoBot",
        "repo": "https://github.com/amazedreamer/THE-EB-NEW",
        "db_name": "FileStoreCopy",
        "enabled": True,
    },
    {
        "id": "cuteheaven-bot-new",
        "name": "CUTEHEAVEN-BOT-NEW",
        "username": "officialcuteHeavenBOT",
        "repo": "https://github.com/amazedreamer/CUTEHEAVEN-BOT-NEW",
        "db_name": "CUTEHEAVEN",
        "enabled": True,
    },
    {
        "id": "king-news-bot",
        "name": "KINGFISHERNEWS Bot",
        "username": "KINGNEWSROBOT",
        "repo": "https://github.com/amazedreamer/XD-Free-Dish",
        "db_name": "KINGFISHERNEWS",
        "enabled": True,
    },
    {
        "id": "dd-delivery-girl-bot",
        "name": "PromoCHBot",
        "username": "DDdeliveryGirlRoBot",
        "repo": "https://github.com/amazedreamer/DX-FREE-DISH-NEW",
        "db_name": "PromoCHBot",
        "enabled": True,
    },
    {
        "id": "pompom-files-bot",
        "name": "POMPOM20 Bot",
        "username": "Pompommfilesssbot",
        "repo": "https://github.com/amazedreamer/THE-EB-NEW",
        "db_name": "POMPOM20",
        "enabled": True,
    },
    {
        "id": "exclusive2-bot",
        "name": "Exclusive2robot",
        "username": "Exclusive2robot",
        "repo": "https://github.com/amazedreamer/THE-EB-NEW",
        "db_name": "Exclusive2robot",
        "enabled": True,
    },
]

DEFAULT_PROTECTED_MONGO_CLUSTERS = [
    {
        "id": "cluster-cuteheaven",
        "name": "CuteHeaven Cluster (ra1oy8c)",
        "uri": "mongodb+srv://harshraja200865_db_user:ZBgFiRZCZH2H1cvX@cluster0.ra1oy8c.mongodb.net/?appName=Cluster0",
        "databases": ["CUTEHEAVEN"],
        "enabled": True,
    },
    {
        "id": "cluster-urvashiix",
        "name": "Urvashiix Cluster (evuqrai)",
        "uri": "mongodb+srv://urvashiix:dThGnaimQESSvwFT@urvashiix.evuqrai.mongodb.net/?appName=urvashiix",
        "databases": ["RealmeUneven", "TheToxicMeme", "DailyPrimeNews", "PromoCHBot"],
        "enabled": True,
    },
    {
        "id": "cluster-iomykdc",
        "name": "XD / KingNews Cluster (iomykdc)",
        "uri": "mongodb+srv://Test:aloksingh@cluster0.iomykdc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
        "databases": ["NewUpdate", "KINGFISHERNEWS", "FiesSNew"],
        "enabled": True,
    },
    {
        "id": "cluster-5ge2hgy",
        "name": "EB / WebSeries Cluster (5ge2hgy)",
        "uri": "mongodb+srv://sameerpandey1:k9TPWFNg2jK4PDET@cluster0.5ge2hgy.mongodb.net/?appName=Cluster0",
        "databases": ["FileStoreCopy", "OnlyFapsFileShareBot", "POMPOM20", "Exclusive2robot"],
        "enabled": True,
    },
]

DEFAULT_PROTECTED_RULES = {
    "block_double_underscore_alias": False,
    "block_yu3elk_payload": False,
    "block_masked_redirect_routes": False,
    "custom_patterns": [],
}


class ProtectedLinkError(Exception):
    def __init__(self, message: str, reason: str = "", bot_name: str = ""):
        super().__init__(message)
        self.reason = reason or message
        self.bot_name = bot_name


class SubscriptionRequiredError(Exception):
    def __init__(self, message: str, mode: str = "exhausted", status_info: dict | None = None):
        super().__init__(message)
        self.mode = mode
        self.status_info = status_info or {}


DEFAULT_PREMIUM_PLANS = [
    {
        "key": "plan_1m",
        "plan_type": "1_month",
        "name": "1 Month",
        "label": "1 Month",
        "days": 30,
        "amount": 100,
        "price_str": "₹ 100",
        "badge": "Popular",
        "enabled": True,
    },
    {
        "key": "plan_3m",
        "plan_type": "3_months",
        "name": "3 Months",
        "label": "3 Months",
        "days": 90,
        "amount": 250,
        "price_str": "₹ 250",
        "badge": "Best Value",
        "enabled": True,
    },
    {
        "key": "plan_6m",
        "plan_type": "6_months",
        "name": "6 Months",
        "label": "6 Months",
        "days": 180,
        "amount": 450,
        "price_str": "₹ 450",
        "badge": "Mega Saver",
        "enabled": True,
    },
]

DEFAULT_PAYMENT_CONFIG = {
    "premium_only_enabled": True,
    "free_trial_limit": 3,
    "upi_id": "paytmqr6mexnc@ptys",
    "upi_payee_name": "APPLE GIFT GALLERY",
    "paytm_mid": "PKNtOC25387320837859",
    "payment_api_url": "https://thedrunkbots-pay-check-api.onrender.com/",
    "payment_verify_interval": 12,
    "payment_max_minutes": 15,
    "amount_tolerance": 2.0,
    "payment_log_channel_id": -1003270558605,
    "payment_log_relay_token": "8658044760:AAFj5uFfUU4EbyYtwPU7hYHWlEb7fvvfcGE",
    "owner_contact_url": "https://t.me/ToxicXAdminRoBot",
    "owner_tag": "ToxicXAdminRoBot",
}


def format_ist_expiry(ts_or_iso: Any) -> str:
    from datetime import datetime, timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    if not ts_or_iso:
        return "N/A"
    try:
        if isinstance(ts_or_iso, (int, float)):
            dt = datetime.fromtimestamp(float(ts_or_iso), tz=ist)
            return dt.strftime("%d %b %Y, %I:%M %p IST")
        s = str(ts_or_iso).strip()
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ist)
        else:
            dt = dt.astimezone(ist)
        return dt.strftime("%d %b %Y, %I:%M %p IST")
    except Exception:
        return str(ts_or_iso)[:22]


DEFAULT_SHORTENERS = [
    {"domain": "vplink.in", "name": "VPLink", "desc": "103s Timer + AntiBypass Guard"},
    {"domain": "arolinks.com", "name": "AroLinks", "desc": "103s Timer + Safelink Blog"},
    {"domain": "get2short.com", "name": "Get2Short", "desc": "CF Check + Multi-Step Blog"},
    {"domain": "gplinks.co", "name": "GPLinks", "desc": "3-Step Blog + 90s Ads-Track Gate"},
    {"domain": "exeygo.com", "name": "ExeyGo", "desc": "2-Step Turnstile + VHit Gate"},
    {"domain": "droplink.co", "name": "DropLink", "desc": "2-Hop Safelink + /links/go"},
    {"domain": "babylinks.in", "name": "BabyLinks", "desc": "JobSheel Safelink + /links/go"},
    {"domain": "liteshort.com", "name": "LiteShort", "desc": "Multi-Step Blog + AntiBypass"},
    {"domain": "nowshort.com", "name": "NowShort", "desc": "Safelink + Turnstile"},
    {"domain": "linksflys.com", "name": "LinksFlys", "desc": "Safelink Redirect + /links/go"},
    {"domain": "alpha-links.in", "name": "AlphaLinks", "desc": "25s Server Timer + AI3 Gate"},
    {"domain": "mrn-officialx.vercel.app", "name": "MRN OfficialX", "desc": "MRN Gate + Turnstile Verify API"},
    {"domain": "speedy-links.com", "name": "SpeedyLinks", "desc": "LootLabs Task 41 WS + Turnstile"},
    {"domain": "best-links.org", "name": "BestLinks", "desc": "LootLabs Task 41 WS + Turnstile"},
    {"domain": "loot-link.com", "name": "LootLink", "desc": "LootLabs Task 41 WS + Turnstile"},
    {"domain": "remso.xyz", "name": "Remso", "desc": "Safelink + /links/go"},
    {"domain": "shortxlinks.com", "name": "ShortXLinks", "desc": "Multi-Step Safelink + /links/go"},
    {"domain": "odiadance.com", "name": "OdiaDance", "desc": "Sub Gate + /links/go"},
    {"domain": "vipshort.in", "name": "VipShort", "desc": "VIP1=4 Unwrap + m.vipshort.in"},
    {"domain": "softurl.in", "name": "SoftURL", "desc": "NewWpSafelink + 33s Timer"},
    {"domain": "urllinkshort.in", "name": "UrlLinkShort", "desc": "SunTechU Token + Web Gate"},
    {"domain": "lksfy.com", "name": "Lksfy", "desc": "2-Step Form + AES-CBC Decrypt"},
    {"domain": "urlspay.com", "name": "UrlsPay", "desc": "Gateway Unwrap + /links/go"},
    {"domain": "v2links.me", "name": "V2Links", "desc": "IPOS Browser Token + /links/go"},
    {"domain": "urlking.in", "name": "URLKing", "desc": "Gate Auth + AES-CBC Direct API"},
    {"domain": "linksfire.co", "name": "LinksFire", "desc": "Blog Gate + /links/go"},
    {"domain": "short2url.in", "name": "Short2URL", "desc": "Short2URL Gate + /links/go"},
    {"domain": "inshorturl.in", "name": "InShortURL", "desc": "Multi-Step Safelink + /links/go"},
    {"domain": "shortwala.com", "name": "ShortWala", "desc": "Safelink + /links/go"},
    {"domain": "earnlinks.in", "name": "EarnLinks", "desc": "Safelink + /links/go"},
    {"domain": "nazki-protected.vercel.app", "name": "NazkiProtected", "desc": "SHA-256 PoW Gate + Shortener"},
    {"domain": "linkprotect.bindaasheart.workers.dev", "name": "LinkProtect", "desc": "Turnstile + /api/claim + /finish2"},
    {"domain": "sfl.gl", "name": "SafeLinkU", "desc": "2-Step Khaddavi Session + /api/go"},
    {"domain": "linkvertise.com", "name": "Linkvertise", "desc": "GraphQL + CHEQ Anti-Bot Solver"},
    {"domain": "short4cash.com", "name": "Short4Cash", "desc": "SayPhotoBooth Safelink + /links/go"},
    {"domain": "web-production-a702d.up.railway.app", "name": "LailaCheckpoint", "desc": "Railway /api/init + /api/complete + /unlock"},
    {"domain": "url.shortners.workers.dev", "name": "LinkForge", "desc": "Turnstile + FreeShare + Remso AdLinkFly"},
    {"domain": "vplinks.in", "name": "VPLinks Beta", "desc": "Django Turnstile Gate + VPLink Chain"},
    {"domain": "publicbotshub-verify.koyeb.app", "name": "PublicBotsHub", "desc": "Koyeb 2-Step CToken & Verify Gate"},
    {"domain": "avbypassbot.koyeb.app", "name": "AVBypass Gate", "desc": "Koyeb Turnstile Verification Gate"},
    {"domain": "pastelink.net", "name": "PasteLink", "desc": "Direct Paste Container Extractor"},
    {"domain": "pastetoday.com", "name": "PasteToday", "desc": "Direct Paste Container Extractor"},
    {"domain": "move2link.co", "name": "Move2Link", "desc": "Siendu m2l-api Direct Solver"},
    {"domain": "genlink.site", "name": "GenLink", "desc": "Jazbaat Multi-Step Safelink"},
    {"domain": "linkpays.in", "name": "LinkPays", "desc": "SavePe Referer + /links/go API"},
    {"domain": "shrinkme.click", "name": "ShrinkMe", "desc": "ShrinkMe / MrProBlogger Direct Solver"},
    {"domain": "ouo.io", "name": "OUO", "desc": "OUO Direct Solver"},
    {"domain": "work.ink", "name": "Work.ink", "desc": "Zen API Direct Solver"},
    {"domain": "rekonise.com", "name": "Rekonise", "desc": "Zen API Direct Solver"},
    {"domain": "sub2unlock.com", "name": "Sub2Unlock", "desc": "Zen API Direct Solver"},
    {"domain": "bstlar.com", "name": "Boostellar", "desc": "Zen API Direct Solver"},
    {"domain": "lockr.so", "name": "Lockr.so", "desc": "Lockr Locker /view -> /task -> /unlock API"},
    {"domain": "lockr.to", "name": "Lockr.to", "desc": "Lockr Locker /view -> /task -> /unlock API"},
    {"domain": "lockr.net", "name": "Lockr.net", "desc": "Lockr Locker /view -> /task -> /unlock API"},
    {"domain": "directlinker.com", "name": "DirectLinker", "desc": "Rentry + Linkvertise Multi-Hop Unwrapper"},
    {"domain": "hastebin.com", "name": "Hastebin", "desc": "NextData Paste Container Extractor"},
    {"domain": "rentry.co", "name": "Rentry", "desc": "Markdown Paste Container Extractor"},
]


def _is_poisoned_destination(src: str, dest: str, elapsed: float = 0.0, method: str = "") -> bool:
    from urllib.parse import urlparse
    s = (src or "").strip().lower()
    d = (dest or "").strip().lower()
    if not d or not d.startswith(("http://", "https://")):
        return True
    if ("arolinks.com/" in s or "vplink.in/" in s) and float(elapsed or 0) < 103.0 and method != "manual":
        return True
    if "publicbotshub" in s and "/link/" in s and (float(elapsed or 0) < 80.0 or method == "koyeb ctoken gate"):
        return True
    bad_gates = (
        "avbypassbot.koyeb.app",
        "publicbotshub-verify.koyeb.app",
        "herokuapp.com/link/",
        "mega-verify-",
        "mrn-officialx.vercel.app",
        "ezy-gules.vercel.app",
        "mrn-universe-store-tv.blogspot.com",
        "antibypass-bot.prostore7.workers.dev",
        "directlinker.com/",
        "lockr.net/",
        "lockr.to/",
        "lockr.so/",
        "linkprotect.bindaasheart.workers.dev",
        "freeshare.thankyoucloudflare.workers.dev",
        "url.shortners.workers.dev",
        "wbschemenews.com",
        "remso.xyz",
        "iskerts.com",
        "vplinks.in",
        "kishanganjhalchal.com",
        "sayphotobooth.com",
        "khaddavi.net",
        "app.khaddavi.net",
        "diary.siendu.com",
        "siendu.com",
        "jazbaat.in",
        "rank1st.in",
        "themezon.net",
        "mrproblogger.com",
        "pornworks.com",
        "/finish2?s=",
        "/finish?t=",
        "prostore7.pages.dev",
        "mytoolspro.pages.dev",
        "nazki-protected.vercel.app",
        "nazki.duckdns.org",
        "nerventualken.com",
        "nismscoldnesfspu.org",
        "onsultingco.com",
        "mrn_movies_request_group",
        "+mdupwsnwvp0zn2u1",
        "+-imjj7_ezp01nzk1",
        "mrn_officialx",
    )
    if any(g in d for g in bad_gates):
        return True
    try:
        ps = urlparse(s)
        pd = urlparse(d)
        hs = (ps.hostname or "").lower()
        hd = (pd.hostname or "").lower()
        paas_sfx = ("workers.dev", "vercel.app", "pages.dev", "koyeb.app", "onrender.com", "duckdns.org", "herokuapp.com")
        bs = hs if any(hs.endswith("." + x) for x in paas_sfx) else (".".join(hs.split(".")[-2:]) if len(hs.split(".")) >= 2 else hs)
        bd = hd if any(hd.endswith("." + x) for x in paas_sfx) else (".".join(hd.split(".")[-2:]) if len(hd.split(".")) >= 2 else hd)
        direct_ok = (
            "pastelink.net", "pastebin.com", "pastetoday.com", "pastequest.com", "rentry.co", "rentry.org",
            "hastebin.com", "paster.so", "pastefy.app", "paste-drop.com", "pastelua.com",
            "t.me", "telegram.me", "telegram.dog", "mega.nz", "drive.google.com", "docs.google.com",
            "mediafire.com", "gofile.io", "devuploads.com", "dupload.net", "pixeldrain.com",
            "1fichier.com", "dropbox.com", "cloudfam.io", "hubcloud.ist", "hubcloud.dad",
            "hubcloud.lol", "gdflix.dev", "torupload.com", "file-upload.org", "file-upload.com",
            "frdl.my", "freedl.ink", "vikingfile.com", "workupload.com",
        )
        if hd.startswith(("ww1.", "ww2.", "ww12.", "ww25.", "ww38.", "ww547.")) or "d.torupload.com" in hd or "frdl.io" in hd:
            return True
        if bs and bd and bs == bd and bs not in direct_ok:
            return True
        bad_paths = (
            "/payout-rates", "/rates", "/pricing", "/login", "/signup",
            "/register", "/terms", "/privacy", "/dmca", "/contact", "/about",
        )
        if any(pd.path.lower().startswith(bp) for bp in bad_paths):
            return True
    except Exception:
        pass
    return False


def _extract_shortener_domain(url: str) -> str:
    from urllib.parse import urlparse
    try:
        u = (url or "").strip()
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        h = (urlparse(u).hostname or "").lower()
    except Exception:
        h = ""
    if not h:
        return ""
    if "mytoolspro.pages.dev" in h:
        return "urlking.in"
    if "jobsraavi.in" in h or "softurl.com" in h:
        return "softurl.in"
    if "inshorturl.com" in h:
        return "inshorturl.in"
    if "khaddavi.net" in h:
        return "sfl.gl"
    if "kishanganjhalchal.com" in h:
        return "liteshort.com"
    if any(h == lv or h.endswith("." + lv) for lv in (
        "linkvertise.com", "link-hub.net", "link-target.net", "link-center.net",
        "direct-link.net", "up-to-down.net", "file-link.net", "linkvertise.net", "linkvertise.download"
    )):
        return "linkvertise.com"
    for sfx in ("vercel.app", "koyeb.app", "pages.dev", "workers.dev", "onrender.com", "duckdns.org"):
        if h.endswith("." + sfx):
            return h
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def norm_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        from g2s.engine import normalize_input_url
        url = normalize_input_url(url)
    except Exception:
        pass
    return url.rstrip("/")


def _clean_int_list(val: Any) -> list[int]:
    if not val:
        return []
    if isinstance(val, (int, float)):
        return [int(val)]
    if isinstance(val, str):
        parts = [p.strip() for p in val.replace(";", ",").split(",") if p.strip()]
    elif isinstance(val, (list, tuple, set)):
        parts = list(val)
    else:
        return []
    out = []
    for p in parts:
        try:
            i = int(str(p).strip())
            if i and i not in out:
                out.append(i)
        except Exception:
            pass
    return out


class Database:
    def __init__(self, cfg_path: str, cache_path: str):
        self.cfg_path = cfg_path
        self.cache_path = cache_path
        self.client: Any = None
        self.db: Any = None
        self.connected: bool = False
        self.last_error: str | None = None
        self._lock = asyncio.Lock()

        # Local in-memory mirrors (always available even if Mongo is momentarily unreachable)
        self.settings: dict[str, Any] = self._load_initial_settings()
        self.local_cache: dict[str, dict] = self._load_local_cache()
        self.local_logs: list[dict] = []
        self.system_logs: list[dict] = []
        self.local_users: dict[int, dict] = {}
        self.local_orders: dict[str, dict] = {}
        self.local_tunnels: dict[str, dict] = {}
        self.protected_known_urls: dict[str, dict] = {}
        self.protected_masked_hashes: dict[str, dict] = {}
        self.protected_last_sync: float = 0.0
        self._protected_sync_lock = asyncio.Lock()
        self._user_locks: dict[int, asyncio.Lock] = {}
        self._on_settings_change_cbs = []
        self._on_error_log_cbs = []

    def on_settings_change(self, cb):
        self._on_settings_change_cbs.append(cb)

    def on_error_log(self, cb):
        self._on_error_log_cbs.append(cb)

    def add_system_log(self, message: str, level: str = "INFO", component: str = "system"):
        entry = {
            "at": time.time(),
            "level": level,
            "component": component,
            "message": str(message),
        }
        self.system_logs.append(entry)
        if len(self.system_logs) > 400:
            self.system_logs = self.system_logs[-400:]

    def list_system_logs(self, limit: int = 120) -> list[dict]:
        return list(self.system_logs[-limit:])

    def _load_initial_settings(self) -> dict[str, Any]:
        raw = {}
        if os.path.exists(self.cfg_path):
            try:
                with open(self.cfg_path, encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception:
                raw = {}

        owner_raw = os.environ.get("G2S_OWNER_ID") or os.environ.get("OWNER_ID") or raw.get("owner_id") or 0
        try:
            owner_id = int(str(owner_raw).strip()) if str(owner_raw).strip() else 0
        except Exception:
            owner_id = 0

        admin_ids = _clean_int_list(
            os.environ.get("G2S_ADMIN_IDS") or os.environ.get("ADMIN_IDS") or raw.get("admin_ids") or []
        )
        if owner_id and owner_id not in admin_ids:
            admin_ids.insert(0, owner_id)

        api_id_raw = (
            os.environ.get("G2S_API_ID")
            or os.environ.get("TELEGRAM_API_ID")
            or os.environ.get("API_ID")
            or raw.get("telegram_api_id")
            or 0
        )
        try:
            api_id = int(str(api_id_raw).strip()) if str(api_id_raw).strip() else 0
        except Exception:
            api_id = 0

        return {
            "mongo_uri": (
                os.environ.get("G2S_MONGO_URI")
                or os.environ.get("MONGO_URI")
                or raw.get("mongo_uri")
                or DEFAULT_MONGO_URI
            ),
            "brand_name": raw.get("brand_name") or DEFAULT_BRAND,
            "admin_password": (
                os.environ.get("G2S_ADMIN_PASSWORD")
                or os.environ.get("ADMIN_PASSWORD")
                or raw.get("admin_password")
                or "admin123"
            ),
            "telegram_bot_token": (
                os.environ.get("G2S_BOT_TOKEN")
                or os.environ.get("TELEGRAM_BOT_TOKEN")
                or os.environ.get("BOT_TOKEN")
                or raw.get("telegram_bot_token")
                or ""
            ).strip(),
            "telegram_api_id": api_id,
            "telegram_api_hash": (
                os.environ.get("G2S_API_HASH")
                or os.environ.get("TELEGRAM_API_HASH")
                or os.environ.get("API_HASH")
                or raw.get("telegram_api_hash")
                or ""
            ).strip(),
            "owner_id": owner_id,
            "admin_ids": admin_ids,
            "start_photo": (
                os.environ.get("G2S_START_PHOTO")
                or raw.get("start_photo")
                or DEFAULT_START_PHOTO
            ).strip(),
            "welcome_message": raw.get("welcome_message") or DEFAULT_WELCOME,
            "updates_channel": raw.get("updates_channel") or "https://t.me/TheDrunkBots",
            "force_sub_enabled": bool(raw.get("force_sub_enabled", True)),
            "force_sub_channels": list(raw.get("force_sub_channels") or DEFAULT_FORCE_SUB_CHANNELS),
            "protected_links_enabled": bool(raw.get("protected_links_enabled", True)),
            "protected_bots": list(raw.get("protected_bots") if "protected_bots" in raw else DEFAULT_PROTECTED_BOTS),
            "removed_protected_bots": list(raw.get("removed_protected_bots") or []),
            "protected_mongo_clusters": list(raw.get("protected_mongo_clusters") or DEFAULT_PROTECTED_MONGO_CLUSTERS),
            "protected_rules": dict(DEFAULT_PROTECTED_RULES | (raw.get("protected_rules") or {})),
            "protected_message": raw.get("protected_message") or DEFAULT_PROTECTED_MESSAGE,
            "premium_only_enabled": bool(raw.get("premium_only_enabled", DEFAULT_PAYMENT_CONFIG["premium_only_enabled"])),
            "free_trial_limit": int(raw.get("free_trial_limit", DEFAULT_PAYMENT_CONFIG["free_trial_limit"])),
            "premium_plans": list(raw.get("premium_plans") or DEFAULT_PREMIUM_PLANS),
            "upi_id": str(raw.get("upi_id") or DEFAULT_PAYMENT_CONFIG["upi_id"]).strip(),
            "upi_payee_name": str(raw.get("upi_payee_name") or DEFAULT_PAYMENT_CONFIG["upi_payee_name"]).strip(),
            "paytm_mid": str(raw.get("paytm_mid") or DEFAULT_PAYMENT_CONFIG["paytm_mid"]).strip(),
            "payment_api_url": str(raw.get("payment_api_url") or DEFAULT_PAYMENT_CONFIG["payment_api_url"]).strip(),
            "payment_verify_interval": int(raw.get("payment_verify_interval", DEFAULT_PAYMENT_CONFIG["payment_verify_interval"])),
            "payment_max_minutes": int(raw.get("payment_max_minutes", DEFAULT_PAYMENT_CONFIG["payment_max_minutes"])),
            "amount_tolerance": float(raw.get("amount_tolerance", DEFAULT_PAYMENT_CONFIG["amount_tolerance"])),
            "payment_log_channel_id": int(raw.get("payment_log_channel_id", DEFAULT_PAYMENT_CONFIG["payment_log_channel_id"])),
            "payment_log_relay_token": str(raw.get("payment_log_relay_token") or DEFAULT_PAYMENT_CONFIG["payment_log_relay_token"]).strip(),
            "owner_contact_url": str(raw.get("owner_contact_url") or DEFAULT_PAYMENT_CONFIG["owner_contact_url"]).strip(),
            "owner_tag": str(raw.get("owner_tag") or DEFAULT_PAYMENT_CONFIG["owner_tag"]).strip(),
            "maintenance_mode": bool(raw.get("maintenance_mode", False)),
            "protect_content": bool(raw.get("protect_content", False)),
            "proxy": (
                os.environ.get("G2S_PROXY")
                if "G2S_PROXY" in os.environ
                else raw.get("proxy")
            ),
            "proxy_expired": bool(raw.get("proxy_expired", False)),
            "proxy_expired_notified_for": str(raw.get("proxy_expired_notified_for") or ""),
            "solver_url": (
                os.environ.get("G2S_SOLVER_URL")
                or raw.get("solver_url")
                or "https://cf.vltcx.eu.cc"
            ).rstrip("/"),
            "solver_api_key": os.environ.get("G2S_SOLVER_API_KEY") or raw.get("solver_api_key"),
            "accel_factor": float(os.environ.get("G2S_ACCEL_FACTOR") or raw.get("accel_factor", 0.1)),
            "timeout": int(os.environ.get("G2S_TIMEOUT") or raw.get("timeout", 300)),
            "stuck_seconds": int(raw.get("stuck_seconds", 100)),
            "cache_enabled": bool(raw.get("cache_enabled", True)),
            "cache_hours": float(os.environ.get("G2S_CACHE_HOURS") or raw.get("cache_hours", 24)),
            "headless": bool(raw.get("headless", False)),
            "show_browser": bool(raw.get("show_browser", False)),
            "no_accel_hosts": list(raw.get("no_accel_hosts") or [
                "get2short.com", "liteshort.com", "nowshort.com", "linksflys.com",
                "vplink.in", "arolinks.com", "babylinks.in", "alpha-links.in", "urllinkshort.in",
                "lksfy.com", "softurl.in", "shortwala.com", "earnlinks.in", "inshorturl.in", "inshorturl.com"
            ]),
            "shortener_tunnels": {
                s["domain"]: bool((raw.get("shortener_tunnels") or {}).get(s["domain"], False))
                for s in DEFAULT_SHORTENERS
            } | {
                str(k).lower().strip(): bool(v)
                for k, v in (raw.get("shortener_tunnels") or {}).items()
                if str(k).strip()
            },
            "custom_shorteners": list(raw.get("custom_shorteners") or []),
            "active_tunnel_device_id": raw.get("active_tunnel_device_id") or None,
            "public_server_url": (raw.get("public_server_url") or "").strip(),
            "ai_auto_heal": bool(raw.get("ai_auto_heal", True)),
            "ai_patrol_enabled": bool(raw.get("ai_patrol_enabled", True)),
            "ai_patrol_interval_minutes": int(raw.get("ai_patrol_interval_minutes", 15)),
            "ai_provider": str(os.environ.get("G2S_AI_PROVIDER") or raw.get("ai_provider") or "auto").strip(),
            "ai_api_key": str(os.environ.get("G2S_AI_API_KEY") or raw.get("ai_api_key") or "").strip(),
            "ai_model": str(os.environ.get("G2S_AI_MODEL") or raw.get("ai_model") or "openai-large").strip(),
            "ai_base_url": str(os.environ.get("G2S_AI_BASE_URL") or raw.get("ai_base_url") or "").strip(),
            "github_token": str(
                os.environ.get("GITHUB_TOKEN")
                or os.environ.get("G2S_GITHUB_TOKEN")
                or raw.get("github_token")
                or ""
            ).strip(),
            "github_repo": str(
                os.environ.get("GITHUB_REPO")
                or raw.get("github_repo")
                or "Urvashi212144/gss-free"
            ).strip(),
            "github_branch": str(
                os.environ.get("GITHUB_BRANCH")
                or raw.get("github_branch")
                or "main"
            ).strip(),
            "dynamic_rules": dict(raw.get("dynamic_rules") or {
                "origin_ips": {
                    "alpha-links.in": "66.116.207.125",
                    "ai3.alpha-links.in": "66.116.207.125",
                    "get2short.com": "66.116.207.125",
                    "link.get2short.com": "66.116.207.125",
                    "lnbz.la": "66.116.207.125",
                    "jkdamours.com": "66.116.207.125",
                    "you.jkdamours.com": "66.116.207.125",
                    "odiadance.com": "66.116.207.125",
                    "sub.odiadance.com": "66.116.207.125",
                    "babylinks.in": "66.116.207.125",
                    "go.babylinks.in": "66.116.207.125",
                    "arolinks.com": "82.25.97.148",
                    "www.arolinks.com": "82.25.97.148",
                    "vplink.in": "82.25.97.148",
                    "www.vplink.in": "82.25.97.148",
                    "liteshort.com": "159.198.79.28",
                    "link.liteshort.com": "159.198.79.28",
                    "nowshort.com": "159.198.79.28",
                    "open.nowshort.com": "159.198.79.28",
                },
                "chain_hosts": [],
                "ad_domains": [],
                "ad_query_keys": [],
                "timer_overrides": {},
            }),
            "stats": {
                "total_bypasses": 0,
                "cache_hits": 0,
                "failed_bypasses": 0,
                "ai_fixes": 0,
            },
        }

    def _load_local_cache(self) -> dict[str, dict]:
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
        return {}

    def _save_local_cache(self):
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.local_cache, f, indent=1)
        except Exception:
            pass

    def save_config_file(self):
        try:
            raw = {}
            if os.path.exists(self.cfg_path):
                try:
                    with open(self.cfg_path, encoding="utf-8") as f:
                        raw = json.load(f)
                except Exception:
                    raw = {}
            keys = (
                "mongo_uri", "brand_name", "admin_password",
                "telegram_bot_token", "telegram_api_id", "telegram_api_hash",
                "owner_id", "admin_ids", "start_photo", "welcome_message",
                "updates_channel", "force_sub_enabled", "force_sub_channels",
                "protected_links_enabled", "protected_bots", "removed_protected_bots",
                "protected_mongo_clusters", "protected_rules", "protected_message",
                "premium_only_enabled", "free_trial_limit", "premium_plans",
                "upi_id", "upi_payee_name", "paytm_mid", "payment_api_url",
                "payment_verify_interval", "payment_max_minutes", "amount_tolerance",
                "payment_log_channel_id", "payment_log_relay_token", "owner_contact_url", "owner_tag",
                "maintenance_mode", "protect_content", "proxy", "proxy_expired",
                "proxy_expired_notified_for",
                "solver_url", "solver_api_key", "accel_factor", "timeout",
                "stuck_seconds", "cache_enabled", "cache_hours", "no_accel_hosts",
                "shortener_tunnels", "custom_shorteners", "active_tunnel_device_id",
                "public_server_url",
            )
            for k in keys:
                if k in self.settings:
                    raw[k] = self.settings[k]
            with open(self.cfg_path, "w", encoding="utf-8") as f:
                json.dump(raw, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print("save_config_file error:", e, flush=True)

    async def connect(self):
        uri = (self.settings.get("mongo_uri") or DEFAULT_MONGO_URI).strip()
        if not HAS_MOTOR or not uri:
            self.connected = False
            self.last_error = "motor not installed or mongo_uri empty"
            return False
        try:
            self.client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=10000)
            await self.client.server_info()
            self.db = self.client["g2sv2"]
            self.connected = True
            self.last_error = None
            await self._sync_on_startup()
            print("✔ Connected to MongoDB Atlas (g2sv2)", flush=True)
            return True
        except Exception as e:
            self.connected = False
            self.last_error = f"{type(e).__name__}: {e}"
            print(f"⚠ MongoDB connection failed ({self.last_error}) — using local JSON fallback", flush=True)
            return False

    async def _sync_on_startup(self):
        if not self.connected or self.db is None:
            return
        try:
            doc = await self.db.settings.find_one({"_id": "global"})
            if doc:
                doc.pop("_id", None)
                env_token = bool(
                    os.environ.get("G2S_BOT_TOKEN")
                    or os.environ.get("TELEGRAM_BOT_TOKEN")
                    or os.environ.get("BOT_TOKEN")
                )
                env_proxy = "G2S_PROXY" in os.environ
                for k, v in doc.items():
                    if k == "telegram_bot_token":
                        if env_token or not str(v or "").strip():
                            continue
                    elif k == "proxy":
                        if env_proxy or not str(v or "").strip():
                            continue
                    elif k in ("telegram_api_hash", "admin_password"):
                        if not str(v or "").strip():
                            continue
                    elif k in ("telegram_api_id", "owner_id"):
                        if not v:
                            continue
                    elif k == "admin_ids" and self.settings.get("admin_ids"):
                        merged = list(self.settings["admin_ids"])
                        for aid in _clean_int_list(v):
                            if aid not in merged:
                                merged.append(aid)
                        self.settings["admin_ids"] = merged
                        continue
                    if v is not None:
                        self.settings[k] = v
                if self.settings.get("owner_id") and self.settings["owner_id"] not in self.settings["admin_ids"]:
                    self.settings["admin_ids"].insert(0, int(self.settings["owner_id"]))
                wm = str(self.settings.get("welcome_message") or "")
                if wm:
                    wm = (
                        wm.replace("<code>{brand}</code>", "@TheDrunkBots")
                        .replace("<code>TheDrunkBots</code>", "@TheDrunkBots")
                        .replace("<code>DrunkBots</code>", "@TheDrunkBots")
                        .replace("@DrunkBots", "@TheDrunkBots")
                    )
                    self.settings["welcome_message"] = wm
                pm = str(self.settings.get("protected_message") or "")
                if pm and "@DrunkBots" in pm:
                    self.settings["protected_message"] = pm.replace("@DrunkBots", "@TheDrunkBots")
                fsub_list = list(self.settings.get("force_sub_channels") or [])
                has_official = False
                for ch in fsub_list:
                    cid_str = str(ch.get("chat_id") or "").strip()
                    if cid_str in ("-1003768452343", "-1004462643599", "@thedrunkbots"):
                        has_official = True
                        if not ch.get("title") or ch.get("title") in ("TheDrunkBots", "-1003768452343"):
                            ch["title"] = "TheDrunkBots Official"
                        ch["api_chat_id"] = "-1004462643599"
                        if not ch.get("invite_link") or "jU3thxiOiyhmNDFl" in str(ch.get("invite_link")):
                            ch["invite_link"] = "https://t.me/+e2xem-7b7-c3ZTM1"
                if not has_official:
                    fsub_list.insert(0, dict(DEFAULT_FORCE_SUB_CHANNELS[0]))
                self.settings["force_sub_channels"] = fsub_list
                if "protected_bots" not in self.settings or (
                    not self.settings.get("protected_bots")
                    and not self.settings.get("removed_protected_bots")
                ):
                    self.settings["protected_bots"] = list(DEFAULT_PROTECTED_BOTS)
                if not self.settings.get("protected_mongo_clusters"):
                    self.settings["protected_mongo_clusters"] = list(DEFAULT_PROTECTED_MONGO_CLUSTERS)
                if not self.settings.get("protected_rules"):
                    self.settings["protected_rules"] = dict(DEFAULT_PROTECTED_RULES)
                if not self.settings.get("protected_message"):
                    self.settings["protected_message"] = DEFAULT_PROTECTED_MESSAGE
                if not self.settings.get("premium_plans"):
                    self.settings["premium_plans"] = [dict(p) for p in DEFAULT_PREMIUM_PLANS]
                for pk, pv in DEFAULT_PAYMENT_CONFIG.items():
                    if pk not in self.settings or self.settings[pk] is None or self.settings[pk] == "":
                        self.settings[pk] = pv
                for s_def in DEFAULT_SHORTENERS:
                    self.settings.setdefault("shortener_tunnels", {}).setdefault(s_def["domain"], False)
                try:
                    from g2s.engine import sanitize_dynamic_rules, set_dynamic_rules
                    self.settings["dynamic_rules"] = sanitize_dynamic_rules(self.settings.get("dynamic_rules") or {})
                    set_dynamic_rules(self.settings["dynamic_rules"])
                except Exception:
                    pass
            await self.db.settings.update_one(
                {"_id": "global"},
                {"$set": {**self.settings, "updated_at": time.time()}},
                upsert=True,
            )
            self.save_config_file()

            # Load users and paytm_orders from MongoDB g2sv2
            try:
                async for udoc in self.db.users.find({}):
                    uid = udoc.get("user_id") or udoc.get("_id")
                    if uid:
                        clean_u = {k: v for k, v in udoc.items() if k != "_id"}
                        clean_u["user_id"] = int(uid)
                        self.local_users[int(uid)] = clean_u
            except Exception:
                pass
            try:
                async for odoc in self.db.paytm_orders.find({}).sort("created_at", -1).limit(500):
                    oid = str(odoc.get("_id") or odoc.get("order_id") or "")
                    if oid:
                        self.local_orders[oid] = dict(odoc)
            except Exception:
                pass

            # Load persisted protected_links from MongoDB g2sv2.protected_links (STRICTLY only for enabled protected_bots)
            try:
                enabled_unames, enabled_dbs, rem_unames, rem_dbs = self._get_protected_bot_sets()
                stale_ids = []
                async for pdoc in self.db.protected_links.find({}):
                    psrc = pdoc.get("source") or pdoc.get("_id")
                    if psrc:
                        p_db = str(pdoc.get("db_name") or "").strip().lower()
                        p_un = str(pdoc.get("username") or pdoc.get("bot_name") or "").strip().lstrip("@").lower()
                        if (p_db and p_db in rem_dbs) or (p_un and p_un in rem_unames):
                            stale_ids.append(pdoc.get("_id"))
                            continue
                        if not ((p_un and p_un in enabled_unames) or (p_db and p_db in enabled_dbs)):
                            stale_ids.append(pdoc.get("_id"))
                            continue
                        self.protected_known_urls[norm_url(str(psrc))] = {
                            k: v for k, v in pdoc.items() if k != "_id"
                        }
                if stale_ids:
                    await self.db.protected_links.delete_many({"_id": {"$in": stale_ids}})
            except Exception:
                pass
            asyncio.create_task(self.sync_protected_masked_links())

            # Purge any poisoned local cache entries
            for src, item in list(self.local_cache.items()):
                if _is_poisoned_destination(
                    src,
                    item.get("url") or "",
                    float(item.get("elapsed") or 0),
                    str(item.get("method") or ""),
                ):
                    self.local_cache.pop(src, None)

            # Load Mongo cache into local mirror & push only missing local cache items to Mongo
            mongo_keys = set()
            async for item in self.db.cache.find({}):
                src = item.get("source") or item.get("_id")
                if src:
                    if _is_poisoned_destination(
                        src,
                        item.get("url") or "",
                        float(item.get("elapsed") or 0),
                        str(item.get("method") or ""),
                    ):
                        await self.db.cache.delete_one({"_id": item.get("_id")})
                        continue
                    mongo_keys.add(src)
                    clean = {k: v for k, v in item.items() if k != "_id"}
                    self.local_cache[src] = clean
            for src, item in list(self.local_cache.items()):
                if src not in mongo_keys:
                    await self.db.cache.update_one(
                        {"_id": src},
                        {"$set": {**item, "source": src}},
                        upsert=True,
                    )
            self._save_local_cache()

            # Load registered tunnel devices from MongoDB g2sv2.tunnels
            async for tdoc in self.db.tunnels.find({}):
                did = tdoc.get("device_id") or tdoc.get("_id")
                if did:
                    clean_t = {k: v for k, v in tdoc.items() if k != "_id"}
                    clean_t["device_id"] = str(did)
                    self.local_tunnels[str(did)] = clean_t
        except Exception as e:
            print("MongoDB startup sync warning:", e, flush=True)

    async def refresh_settings_from_mongo(self) -> dict[str, Any]:
        if self.connected and self.db is not None:
            try:
                doc = await self.db.settings.find_one({"_id": "global"})
                if doc:
                    doc.pop("_id", None)
                    self.settings.update(doc)
            except Exception:
                pass
        return dict(self.settings)

    async def update_settings(self, patch: dict[str, Any], notify: bool = True) -> dict[str, Any]:
        async with self._lock:
            changed_keys = set()
            for k, v in patch.items():
                if k == "owner_id":
                    try:
                        v = int(str(v).strip()) if str(v).strip() else 0
                    except Exception:
                        v = self.settings.get("owner_id", 0)
                elif k == "telegram_api_id":
                    try:
                        v = int(str(v).strip()) if str(v).strip() else 0
                    except Exception:
                        v = self.settings.get("telegram_api_id", 0)
                elif k == "admin_ids":
                    v = _clean_int_list(v)
                elif k == "accel_factor":
                    try:
                        v = max(0.05, min(1.0, float(v)))
                    except Exception:
                        v = self.settings.get("accel_factor", 0.1)
                elif k == "timeout":
                    try:
                        v = max(30, min(900, int(v)))
                    except Exception:
                        v = self.settings.get("timeout", 300)
                elif k == "cache_hours":
                    try:
                        v = max(0.1, float(v))
                    except Exception:
                        v = self.settings.get("cache_hours", 24.0)
                elif k == "proxy":
                    v = (v or "").strip() or None
                if self.settings.get(k) != v:
                    changed_keys.add(k)
                self.settings[k] = v

            owner_id = self.settings.get("owner_id") or 0
            admin_ids = _clean_int_list(self.settings.get("admin_ids") or [])
            if owner_id and owner_id not in admin_ids:
                admin_ids.insert(0, owner_id)
            self.settings["admin_ids"] = admin_ids

            self.save_config_file()
            if self.connected and self.db is not None:
                try:
                    await self.db.settings.update_one(
                        {"_id": "global"},
                        {"$set": {**self.settings, "updated_at": time.time()}},
                        upsert=True,
                    )
                except Exception as e:
                    print("MongoDB update_settings warning:", e, flush=True)

        if notify and changed_keys:
            for cb in self._on_settings_change_cbs:
                try:
                    res = cb(changed_keys, dict(self.settings))
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as e:
                    print("settings callback error:", e, flush=True)
        return dict(self.settings)

    def is_admin(self, user_id: int | str | None) -> bool:
        if not user_id:
            return False
        try:
            uid = int(user_id)
        except Exception:
            return False
        owner = int(self.settings.get("owner_id") or 0)
        admins = _clean_int_list(self.settings.get("admin_ids") or [])
        return (uid == owner and owner != 0) or (uid in admins)

    def is_owner(self, user_id: int | str | None) -> bool:
        if not user_id:
            return False
        try:
            uid = int(user_id)
        except Exception:
            return False
        owner = int(self.settings.get("owner_id") or 0)
        return (uid == owner and owner != 0) or self.is_admin(uid)

    # ------------------------------------------------------------------- stats
    async def increment_stat(self, key: str, delta: int = 1):
        stats = self.settings.setdefault("stats", {"total_bypasses": 0, "cache_hits": 0, "failed_bypasses": 0})
        stats[key] = int(stats.get(key, 0)) + delta
        if self.connected and self.db is not None:
            try:
                await self.db.settings.update_one(
                    {"_id": "global"},
                    {"$inc": {f"stats.{key}": delta}},
                    upsert=True,
                )
            except Exception:
                pass

    # ------------------------------------------------------------------- cache
    @staticmethod
    def _mongo_doc_id(key: str) -> str:
        raw_b = key.encode("utf-8", "ignore")
        if len(raw_b) <= 750:
            return key
        import hashlib
        return f"{key[:200]}#sha256:{hashlib.sha256(raw_b).hexdigest()}"

    async def get_cache(self, url: str, force: bool = False) -> dict | None:
        if force or not self.settings.get("cache_enabled", True):
            return None
        key = norm_url(url)
        if not key or "publicbotshub" in key.lower():
            return None
        ttl = float(self.settings.get("cache_hours", 24)) * 3600.0
        now = time.time()

        keys_to_try = [key]
        if "://vplink.in/" in key:
            prefix, _, slug = key.rpartition("/")
            if slug.startswith("__") and slug.endswith("__") and len(slug) > 4:
                keys_to_try.append(f"{prefix}/{slug[2:-2]}")
            elif slug:
                keys_to_try.append(f"{prefix}/__{slug}__")

        hit = None
        hit_key = key
        for k_try in keys_to_try:
            cand = self.local_cache.get(k_try)
            if (not cand or now - float(cand.get("at", 0)) >= ttl) and self.connected and self.db is not None:
                try:
                    doc = await self.db.cache.find_one({"_id": self._mongo_doc_id(k_try)})
                    if doc:
                        doc.pop("_id", None)
                        self.local_cache[k_try] = doc
                        cand = doc
                except Exception:
                    pass
            if cand:
                if _is_poisoned_destination(
                    k_try,
                    cand.get("url") or "",
                    float(cand.get("elapsed") or 0),
                    str(cand.get("method") or ""),
                ):
                    await self.delete_cache(k_try)
                    continue
                if now - float(cand.get("at", 0)) < ttl:
                    hit = cand
                    hit_key = k_try
                    break

        if not hit:
            return None

        hit["hits"] = int(hit.get("hits", 0)) + 1
        self.local_cache[hit_key] = hit

        async def _bg_inc():
            if self.connected and self.db is not None:
                try:
                    await self.db.cache.update_one({"_id": self._mongo_doc_id(hit_key)}, {"$inc": {"hits": 1}})
                except Exception:
                    pass
            await self.increment_stat("cache_hits", 1)

        asyncio.create_task(_bg_inc())
        return {**hit, "source": key, "cached": True}

    async def set_cache(self, source_url: str, data: dict) -> dict:
        key = norm_url(source_url)
        dest_u = (data.get("url") or "").strip()
        el_val = float(data.get("elapsed") or 0.0)
        m_val = str(data.get("method") or "manual")
        if _is_poisoned_destination(key, dest_u, el_val, m_val):
            return {"source": key, "url": dest_u, "elapsed": el_val, "method": m_val, "skipped": True}
        entry = {
            "source": key,
            "url": dest_u,
            "elapsed": el_val,
            "method": m_val,
            "steps": list(data.get("steps") or []),
            "extra_links": list(data.get("extra_links") or []),
            "at": float(data.get("at") or time.time()),
            "hits": int(data.get("hits") or 0),
        }
        self.local_cache[key] = entry
        self._save_local_cache()
        if self.connected and self.db is not None:
            try:
                await self.db.cache.update_one(
                    {"_id": self._mongo_doc_id(key)},
                    {"$set": entry},
                    upsert=True,
                )
            except Exception as e:
                print("MongoDB set_cache warning:", e, flush=True)
        return entry

    async def delete_cache(self, source_url: str) -> bool:
        key = norm_url(source_url)
        existed = key in self.local_cache
        self.local_cache.pop(key, None)
        if source_url in self.local_cache:
            self.local_cache.pop(source_url, None)
            existed = True
        self._save_local_cache()
        if self.connected and self.db is not None:
            try:
                r = await self.db.cache.delete_one({"_id": self._mongo_doc_id(key)})
                if r.deleted_count:
                    existed = True
            except Exception:
                pass
        return existed

    async def clear_cache(self) -> int:
        cnt = len(self.local_cache)
        self.local_cache.clear()
        self._save_local_cache()
        if self.connected and self.db is not None:
            try:
                r = await self.db.cache.delete_many({})
                cnt = max(cnt, r.deleted_count)
            except Exception:
                pass
        return cnt

    async def list_cache(self, search: str = "", limit: int = 200) -> list[dict]:
        items = []
        if self.connected and self.db is not None:
            try:
                cursor = self.db.cache.find({}).sort("at", -1).limit(500)
                async for doc in cursor:
                    src = doc.get("source") or doc.get("_id")
                    clean = {k: v for k, v in doc.items() if k != "_id"}
                    clean["source"] = src
                    self.local_cache[src] = clean
                    items.append(clean)
            except Exception:
                items = [{"source": k, **v} for k, v in self.local_cache.items()]
        else:
            items = [{"source": k, **v} for k, v in self.local_cache.items()]

        items.sort(key=lambda x: -float(x.get("at", 0)))
        if search:
            q = search.lower().strip()
            items = [
                i for i in items
                if q in (i.get("source") or "").lower() or q in (i.get("url") or "").lower()
            ]
        return items[:limit]

    # -------------------------------------------------------------- error logs
    async def add_error_log(
        self,
        source: str,
        error: str,
        log_lines: list[str],
        origin: str = "web",
        user_id: int | None = None,
        username: str | None = None,
    ) -> dict:
        lid = uuid.uuid4().hex[:10]
        err_s = str(error)
        err_l = err_s.lower()
        auto_note = None
        if "is_premium_only=true" in err_l or "premium-only paywall link" in err_l:
            auto_note = "Creator-locked Linkvertise Premium-Only paywall link (is_premium_only=true; no free access exists)"
        elif "paid qris paywall" in err_l or "real-money" in err_l:
            auto_note = "Paid real-money QRIS paywall link (cannot be bypassed for free)"
        elif (
            "session is invalid or expired" in err_l
            or "one-time verification link on" in err_l
            or "link not found (404" in err_l
            or "link not found (http 404" in err_l
            or "offline (dns lookup failed)" in err_l
        ):
            auto_note = "Confirmed expired one-time verification token, deleted 404 link, or offline domain"
        entry = {
            "id": lid,
            "source": norm_url(source) or source,
            "error": err_s,
            "log": list(log_lines or []),
            "origin": origin,
            "user_id": user_id,
            "username": username,
            "at": time.time(),
            "resolved": bool(auto_note),
            "resolved_by": "Auto-Classifier" if auto_note else None,
            "resolution_note": auto_note,
        }
        self.local_logs.insert(0, entry)
        self.local_logs = self.local_logs[:200]
        self.add_system_log(f"ERROR [{entry['source']}]: {entry['error']}", level="ERROR", component=origin)
        if self.connected and self.db is not None:
            try:
                await self.db.error_logs.insert_one({"_id": lid, **entry})
            except Exception:
                pass
        await self.increment_stat("failed_bypasses", 1)
        for cb in list(self._on_error_log_cbs):
            try:
                r = cb(entry)
                if asyncio.iscoroutine(r):
                    asyncio.create_task(r)
            except Exception:
                pass
        return entry

    async def mark_error_log_resolved(
        self,
        log_id: str,
        resolution_note: str = "Fixed & verified by Autonomous AI Engineer",
        resolved_by: str = "AI-Engineer",
    ) -> bool:
        updated = False
        now = time.time()
        for item in self.local_logs:
            if item.get("id") == log_id:
                item["resolved"] = True
                item["resolved_at"] = now
                item["resolved_by"] = resolved_by
                item["resolution_note"] = resolution_note
                updated = True
        if self.connected and self.db is not None:
            try:
                r = await self.db.error_logs.update_one(
                    {"_id": log_id},
                    {"$set": {
                        "resolved": True,
                        "resolved_at": now,
                        "resolved_by": resolved_by,
                        "resolution_note": resolution_note,
                    }},
                )
                if r.modified_count:
                    updated = True
            except Exception:
                pass
        return updated

    async def list_error_logs(self, limit: int = 100) -> list[dict]:
        if self.connected and self.db is not None:
            try:
                out = []
                cursor = self.db.error_logs.find({}).sort("at", -1).limit(limit)
                async for doc in cursor:
                    doc.pop("_id", None)
                    out.append(doc)
                self.local_logs = out
                return out
            except Exception:
                pass
        return self.local_logs[:limit]

    async def delete_error_log(self, log_id: str) -> bool:
        before = len(self.local_logs)
        self.local_logs = [x for x in self.local_logs if x.get("id") != log_id]
        deleted = len(self.local_logs) < before
        if self.connected and self.db is not None:
            try:
                r = await self.db.error_logs.delete_one({"_id": log_id})
                if r.deleted_count:
                    deleted = True
            except Exception:
                pass
        return deleted

    async def clear_error_logs(self) -> int:
        cnt = len(self.local_logs)
        self.local_logs.clear()
        if self.connected and self.db is not None:
            try:
                r = await self.db.error_logs.delete_many({})
                cnt = max(cnt, r.deleted_count)
            except Exception:
                pass
        return cnt

    # ------------------------------------------------------------------- users
    async def touch_user(self, tg_user: dict, increment_bypass: bool = False) -> dict:
        uid = int(tg_user.get("id") or tg_user.get("user_id") or 0)
        if not uid:
            return {}
        now = time.time()
        existing = self.local_users.get(uid)
        if not existing and self.connected and self.db is not None:
            try:
                doc = await self.db.users.find_one({"_id": uid})
                if doc:
                    doc.pop("_id", None)
                    existing = doc
            except Exception:
                pass

        user_doc = {
            **(existing or {}),
            "user_id": uid,
            "username": tg_user.get("username") or (existing or {}).get("username") or "",
            "first_name": tg_user.get("first_name") or (existing or {}).get("first_name") or "User",
            "last_name": tg_user.get("last_name") or (existing or {}).get("last_name") or "",
            "joined_at": float((existing or {}).get("joined_at") or now),
            "last_active": now,
            "bypass_count": int((existing or {}).get("bypass_count") or 0) + (1 if increment_bypass else 0),
            "banned": bool((existing or {}).get("banned", False)),
            "free_uses_used": int((existing or {}).get("free_uses_used") or 0),
            "premium_until": float((existing or {}).get("premium_until") or 0.0),
            "expiration_timestamp": (existing or {}).get("expiration_timestamp") or "",
            "plan_type": (existing or {}).get("plan_type") or "",
            "plan_label": (existing or {}).get("plan_label") or "",
            "has_ever_bought_plan": bool((existing or {}).get("has_ever_bought_plan", False)),
            "expired_notified": bool((existing or {}).get("expired_notified", False)),
        }
        self.local_users[uid] = user_doc
        if self.connected and self.db is not None:
            try:
                await self.db.users.update_one(
                    {"_id": uid},
                    {"$set": user_doc},
                    upsert=True,
                )
            except Exception:
                pass
        return user_doc

    async def get_user(self, user_id: int) -> dict | None:
        uid = int(user_id)
        if self.connected and self.db is not None:
            try:
                doc = await self.db.users.find_one({"_id": uid})
                if doc:
                    doc.pop("_id", None)
                    self.local_users[uid] = doc
                    return doc
            except Exception:
                pass
        return self.local_users.get(uid)

    async def set_user_banned(self, user_id: int, banned: bool) -> bool:
        uid = int(user_id)
        doc = await self.get_user(uid) or {
            "user_id": uid,
            "username": "",
            "first_name": "User",
            "last_name": "",
            "joined_at": time.time(),
            "last_active": time.time(),
            "bypass_count": 0,
        }
        doc["banned"] = bool(banned)
        self.local_users[uid] = doc
        if self.connected and self.db is not None:
            try:
                await self.db.users.update_one(
                    {"_id": uid},
                    {"$set": doc},
                    upsert=True,
                )
            except Exception:
                pass
        return True

    async def delete_user(self, user_id: int) -> bool:
        uid = int(user_id)
        existed = uid in self.local_users
        self.local_users.pop(uid, None)
        if self.connected and self.db is not None:
            try:
                r = await self.db.users.delete_one({"_id": uid})
                if r.deleted_count:
                    existed = True
            except Exception:
                pass
        return existed

    async def list_users(self, search: str = "", limit: int = 200) -> list[dict]:
        users = []
        if self.connected and self.db is not None:
            try:
                cursor = self.db.users.find({}).sort("last_active", -1).limit(500)
                async for doc in cursor:
                    doc.pop("_id", None)
                    uid = int(doc.get("user_id") or 0)
                    if uid:
                        self.local_users[uid] = doc
                        users.append(doc)
            except Exception:
                users = list(self.local_users.values())
        else:
            users = list(self.local_users.values())
        users.sort(key=lambda x: -float(x.get("last_active", 0)))
        if search:
            q = search.lower().strip()
            users = [
                u for u in users
                if q in str(u.get("user_id", "")).lower()
                or q in (u.get("username") or "").lower()
                or q in (u.get("first_name") or "").lower()
            ]
        return users[:limit]

    async def get_all_user_ids(self, include_banned: bool = False) -> list[int]:
        users = await self.list_users(limit=10000)
        return [
            int(u["user_id"])
            for u in users
            if u.get("user_id") and (include_banned or not u.get("banned"))
        ]

    # ------------------------------------------------- Shortener Tunnel Routing
    def get_shortener_tunnel_list(self) -> list[dict]:
        st_map: dict[str, bool] = dict(self.settings.get("shortener_tunnels") or {})
        custom_list: list[dict] = list(self.settings.get("custom_shorteners") or [])
        seen = set()
        out = []
        for item in DEFAULT_SHORTENERS:
            dom = item["domain"].lower().strip()
            seen.add(dom)
            out.append({
                "domain": dom,
                "name": item["name"],
                "desc": item.get("desc", ""),
                "enabled": bool(st_map.get(dom, False)),
                "custom": False,
            })
        for c in custom_list:
            dom = str(c.get("domain") or "").lower().strip()
            if not dom or dom in seen:
                continue
            seen.add(dom)
            out.append({
                "domain": dom,
                "name": c.get("name") or dom,
                "desc": c.get("desc") or "Custom Shortener",
                "enabled": bool(st_map.get(dom, False)),
                "custom": True,
            })
        for dom, val in st_map.items():
            d = str(dom).lower().strip()
            if d and d not in seen:
                seen.add(d)
                out.append({
                    "domain": d,
                    "name": d,
                    "desc": "Custom Shortener",
                    "enabled": bool(val),
                    "custom": True,
                })
        return out

    async def set_shortener_tunnel(
        self, domain: str, enabled: bool, name: str | None = None, desc: str | None = None
    ) -> list[dict]:
        dom = _extract_shortener_domain(domain) or domain.lower().strip()
        if not dom:
            return self.get_shortener_tunnel_list()
        st_map = dict(self.settings.get("shortener_tunnels") or {})
        for s in DEFAULT_SHORTENERS:
            st_map.setdefault(s["domain"], False)
        st_map[dom] = bool(enabled)

        default_doms = {s["domain"] for s in DEFAULT_SHORTENERS}
        custom_list = list(self.settings.get("custom_shorteners") or [])
        if dom not in default_doms and not any(c.get("domain") == dom for c in custom_list):
            custom_list.append({
                "domain": dom,
                "name": (name or dom).strip(),
                "desc": (desc or "Custom Shortener").strip(),
            })

        await self.update_settings({
            "shortener_tunnels": st_map,
            "custom_shorteners": custom_list,
        })
        return self.get_shortener_tunnel_list()

    async def delete_custom_shortener(self, domain: str) -> list[dict]:
        dom = _extract_shortener_domain(domain) or domain.lower().strip()
        st_map = dict(self.settings.get("shortener_tunnels") or {})
        st_map.pop(dom, None)
        custom_list = [
            c for c in (self.settings.get("custom_shorteners") or [])
            if str(c.get("domain") or "").lower().strip() != dom
        ]
        await self.update_settings({
            "shortener_tunnels": st_map,
            "custom_shorteners": custom_list,
        })
        return self.get_shortener_tunnel_list()

    async def set_all_shortener_tunnels(self, enabled: bool) -> list[dict]:
        st_map = dict(self.settings.get("shortener_tunnels") or {})
        for s in DEFAULT_SHORTENERS:
            st_map[s["domain"]] = bool(enabled)
        for c in (self.settings.get("custom_shorteners") or []):
            d = str(c.get("domain") or "").lower().strip()
            if d:
                st_map[d] = bool(enabled)
        for k in list(st_map.keys()):
            st_map[k] = bool(enabled)
        for direct_only in ("avbypassbot.koyeb.app", "directlinker.com"):
            st_map[direct_only] = False
        st_map["publicbotshub-verify.koyeb.app"] = True
        await self.update_settings({"shortener_tunnels": st_map})
        return self.get_shortener_tunnel_list()

    def should_use_tunnel_for_url(self, url: str) -> bool:
        u_low = (url or "").lower()
        if "publicbotshub-verify.koyeb.app" in u_low:
            return True
        if any(d in u_low for d in ("avbypassbot.koyeb.app", "directlinker.com")):
            return False
        dom = _extract_shortener_domain(url)
        if not dom or dom in ("avbypassbot.koyeb.app", "directlinker.com"):
            return False
        st_map = self.settings.get("shortener_tunnels") or {}
        return bool(st_map.get(dom, False))

    # ---------------------------------------------- Multi-Device Tunnel Pool
    @staticmethod
    def _is_tunnel_doc_online(doc: dict, now: float | None = None) -> bool:
        now = now or time.time()
        if doc.get("status") == "offline":
            return False
        if doc.get("ws_connected"):
            return True
        last_seen = float(doc.get("last_seen") or 0)
        return bool(doc.get("proxy_url")) and (now - last_seen < 110.0)

    async def sync_tunnels_from_mongo(self):
        if not self.connected or self.db is None:
            return
        try:
            seen_ids = set()
            async for doc in self.db.tunnels.find({}):
                did = str(doc.get("device_id") or doc.get("_id") or "").strip()
                if not did:
                    continue
                seen_ids.add(did)
                clean = {k: v for k, v in doc.items() if k != "_id"}
                clean["device_id"] = did
                local = self.local_tunnels.get(did) or {}
                if local.get("ws_connected"):
                    clean["ws_connected"] = True
                    if local.get("ws_bridge_url"):
                        clean["ws_bridge_url"] = local["ws_bridge_url"]
                        if not clean.get("pinggy_proxy"):
                            clean["proxy_url"] = local["ws_bridge_url"]
                self.local_tunnels[did] = clean
        except Exception:
            pass

    async def register_tunnel_device(self, info: dict) -> dict:
        did = str(info.get("device_id") or "").strip()
        if not did:
            did = f"dev-{uuid.uuid4().hex[:8]}"
        now = time.time()
        existing = self.local_tunnels.get(did)
        if not existing and self.connected and self.db is not None:
            try:
                doc = await self.db.tunnels.find_one({"_id": did})
                if doc:
                    doc.pop("_id", None)
                    existing = doc
            except Exception:
                pass

        enabled = bool(
            info["enabled"]
            if "enabled" in info
            else (existing.get("enabled", True) if existing else True)
        )
        is_primary = bool(
            info["is_primary"]
            if "is_primary" in info
            else (existing.get("is_primary", False) if existing else False)
        )
        if not self.settings.get("active_tunnel_device_id") and enabled:
            is_primary = True
            await self.update_settings({"active_tunnel_device_id": did}, notify=False)
        elif self.settings.get("active_tunnel_device_id") == did:
            is_primary = True

        entry = {
            "device_id": did,
            "device_name": str(
                info.get("device_name") or (existing or {}).get("device_name") or did
            ).strip(),
            "device_type": str(
                info.get("device_type") or (existing or {}).get("device_type") or "pc"
            ).lower().strip(),
            "platform_info": str(
                info.get("platform_info") or (existing or {}).get("platform_info") or ""
            ).strip(),
            "tunnel_mode": str(
                info.get("tunnel_mode") or (existing or {}).get("tunnel_mode") or "pinggy"
            ).strip(),
            "proxy_url": (info.get("proxy_url") or (existing or {}).get("proxy_url") or "").strip() or None,
            "pinggy_proxy": (info.get("pinggy_proxy") or (existing or {}).get("pinggy_proxy") or "").strip() or None,
            "ws_bridge_url": (info.get("ws_bridge_url") or (existing or {}).get("ws_bridge_url") or "").strip() or None,
            "public_ip": str(
                info.get("public_ip") or (existing or {}).get("public_ip") or ""
            ).strip(),
            "isp": str(info.get("isp") or (existing or {}).get("isp") or "").strip(),
            "country": str(info.get("country") or (existing or {}).get("country") or "").strip(),
            "enabled": enabled,
            "is_primary": is_primary,
            "status": str(info.get("status") or "online"),
            "ws_connected": bool(info.get("ws_connected", (existing or {}).get("ws_connected", False))),
            "connected_at": float((existing or {}).get("connected_at") or now),
            "last_seen": now,
            "total_requests": int(info.get("total_requests") or (existing or {}).get("total_requests") or 0),
            "failed_requests": int(info.get("failed_requests") or 0),
        }
        self.local_tunnels[did] = entry
        if self.connected and self.db is not None:
            try:
                await self.db.tunnels.update_one(
                    {"_id": did},
                    {"$set": entry},
                    upsert=True,
                )
            except Exception:
                pass
        return entry

    async def heartbeat_tunnel_device(self, device_id: str, patch: dict) -> dict | None:
        did = str(device_id or "").strip()
        if not did:
            return None
        existing = self.local_tunnels.get(did)
        if not existing:
            return await self.register_tunnel_device({"device_id": did, **patch})
        now = time.time()
        for k in (
            "device_name", "device_type", "platform_info", "tunnel_mode",
            "proxy_url", "pinggy_proxy", "ws_bridge_url", "public_ip",
            "isp", "country", "status", "ws_connected", "total_requests",
        ):
            if k in patch and patch[k] is not None:
                existing[k] = patch[k]
        existing["last_seen"] = now
        if patch.get("status") == "online":
            existing["failed_requests"] = 0
        self.local_tunnels[did] = existing
        if self.connected and self.db is not None:
            try:
                await self.db.tunnels.update_one(
                    {"_id": did},
                    {"$set": existing},
                    upsert=True,
                )
            except Exception:
                pass
        return existing

    async def mark_tunnel_ws_disconnected(self, device_id: str):
        did = str(device_id or "").strip()
        doc = self.local_tunnels.get(did)
        if not doc:
            return
        doc["ws_connected"] = False
        doc["ws_bridge_url"] = None
        if doc.get("pinggy_proxy") and (time.time() - float(doc.get("last_seen") or 0) < 90):
            doc["proxy_url"] = doc["pinggy_proxy"]
            doc["tunnel_mode"] = "pinggy"
        else:
            doc["status"] = "offline"
        if self.connected and self.db is not None:
            try:
                await self.db.tunnels.update_one({"_id": did}, {"$set": doc})
            except Exception:
                pass

    async def set_tunnel_device_enabled(self, device_id: str, enabled: bool) -> dict | None:
        did = str(device_id or "").strip()
        await self.sync_tunnels_from_mongo()
        doc = self.local_tunnels.get(did)
        if not doc:
            return None
        doc["enabled"] = bool(enabled)
        if not enabled and self.settings.get("active_tunnel_device_id") == did:
            doc["is_primary"] = False
            next_primary = None
            for other_id, other in self.local_tunnels.items():
                if other_id != did and other.get("enabled") and self._is_tunnel_doc_online(other):
                    other["is_primary"] = True
                    next_primary = other_id
                    if self.connected and self.db is not None:
                        try:
                            await self.db.tunnels.update_one({"_id": other_id}, {"$set": {"is_primary": True}})
                        except Exception:
                            pass
                    break
            await self.update_settings({"active_tunnel_device_id": next_primary}, notify=False)
        elif enabled and not self.settings.get("active_tunnel_device_id"):
            doc["is_primary"] = True
            await self.update_settings({"active_tunnel_device_id": did}, notify=False)

        self.local_tunnels[did] = doc
        if self.connected and self.db is not None:
            try:
                await self.db.tunnels.update_one({"_id": did}, {"$set": doc}, upsert=True)
            except Exception:
                pass
        return doc

    async def set_primary_tunnel_device(self, device_id: str) -> dict | None:
        did = str(device_id or "").strip()
        await self.sync_tunnels_from_mongo()
        if did not in self.local_tunnels:
            return None
        for other_id, doc in self.local_tunnels.items():
            is_p = (other_id == did)
            doc["is_primary"] = is_p
            if is_p:
                doc["enabled"] = True
            if self.connected and self.db is not None:
                try:
                    await self.db.tunnels.update_one(
                        {"_id": other_id},
                        {"$set": {"is_primary": doc["is_primary"], "enabled": doc["enabled"]}},
                    )
                except Exception:
                    pass
        await self.update_settings({"active_tunnel_device_id": did}, notify=False)
        return self.local_tunnels.get(did)

    async def delete_tunnel_device(self, device_id: str) -> bool:
        did = str(device_id or "").strip()
        existed = did in self.local_tunnels
        self.local_tunnels.pop(did, None)
        if self.connected and self.db is not None:
            try:
                r = await self.db.tunnels.delete_one({"_id": did})
                if r.deleted_count:
                    existed = True
            except Exception:
                pass
        if self.settings.get("active_tunnel_device_id") == did:
            await self.update_settings({"active_tunnel_device_id": None}, notify=False)
        return existed

    async def record_tunnel_usage(self, device_id: str, success: bool = True):
        did = str(device_id or "").strip()
        if not did:
            return
        if did == "manual-proxy" and not success:
            self.settings["proxy_expired"] = True
            return
        doc = self.local_tunnels.get(did)
        if not doc:
            return
        if success:
            doc["total_requests"] = int(doc.get("total_requests") or 0) + 1
            doc["failed_requests"] = 0
            doc["status"] = "online"
        else:
            doc["failed_requests"] = int(doc.get("failed_requests") or 0) + 1
            if not doc.get("ws_connected"):
                doc["status"] = "offline"
        if self.connected and self.db is not None:
            try:
                await self.db.tunnels.update_one(
                    {"_id": did},
                    {"$set": {
                        "total_requests": doc["total_requests"],
                        "failed_requests": doc["failed_requests"],
                        "status": doc.get("status", "online"),
                    }},
                )
            except Exception:
                pass

    async def list_tunnel_devices(self) -> list[dict]:
        await self.sync_tunnels_from_mongo()
        now = time.time()
        active_id = self.settings.get("active_tunnel_device_id")

        items = []
        for did, doc in self.local_tunnels.items():
            online = self._is_tunnel_doc_online(doc, now)
            enabled = bool(doc.get("enabled", True))
            is_primary = bool(doc.get("is_primary")) or (did == active_id)
            items.append({
                **doc,
                "device_id": did,
                "online": online,
                "enabled": enabled,
                "is_primary": is_primary,
                "age_seconds": max(0, int(now - float(doc.get("last_seen") or 0))),
            })

        # Sort: online+enabled+primary first, then online+enabled (fallback), then online+disabled, then offline
        items.sort(key=lambda x: (
            0 if (x["online"] and x["enabled"] and x["is_primary"]) else
            1 if (x["online"] and x["enabled"]) else
            2 if x["online"] else 3,
            int(x.get("failed_requests") or 0),
            -float(x.get("last_seen") or 0),
        ))

        assigned_active = False
        for item in items:
            if not item["online"]:
                item["role"] = "OFFLINE"
            elif not item["enabled"]:
                item["role"] = "IDLE (DISABLED)"
            elif not assigned_active:
                item["role"] = "ACTIVE (IN USE)"
                item["is_active_selected"] = True
                assigned_active = True
            else:
                item["role"] = "STANDBY (FALLBACK)"
                item["is_active_selected"] = False
        return items

    async def get_tunnel_candidates_for_url(self, url: str, ignore_shortener_toggle: bool = False) -> list[dict]:
        u_low = (url or "").lower()
        if any(d in u_low for d in ("avbypassbot.koyeb.app", "directlinker.com")):
            return []
        if not ignore_shortener_toggle and not self.should_use_tunnel_for_url(url):
            return []
        devices = await self.list_tunnel_devices()
        candidates = [
            d for d in devices
            if d.get("online") and d.get("enabled") and d.get("proxy_url")
        ]
        # Also include manual proxy in settings as last-resort fallback if configured and not expired
        manual_px = (self.settings.get("proxy") or "").strip()
        if manual_px and not self.settings.get("proxy_expired"):
            if not any(c.get("proxy_url") == manual_px for c in candidates):
                candidates.append({
                    "device_id": "manual-proxy",
                    "device_name": "Manual Configured Tunnel",
                    "device_type": "manual",
                    "proxy_url": manual_px,
                    "role": "ACTIVE (MANUAL)" if not candidates else "STANDBY (MANUAL)",
                })
        return candidates

    def list_tunnel_devices_sync(self) -> list[dict]:
        now = time.time()
        active_id = self.settings.get("active_tunnel_device_id")
        items = []
        for did, doc in self.local_tunnels.items():
            online = self._is_tunnel_doc_online(doc, now)
            enabled = bool(doc.get("enabled", True))
            is_primary = bool(doc.get("is_primary")) or (did == active_id)
            items.append({
                **doc,
                "device_id": did,
                "online": online,
                "enabled": enabled,
                "is_primary": is_primary,
                "age_seconds": max(0, int(now - float(doc.get("last_seen") or 0))),
            })
        items.sort(key=lambda x: (
            0 if (x["online"] and x["enabled"] and x["is_primary"]) else
            1 if (x["online"] and x["enabled"]) else
            2 if x["online"] else 3,
            int(x.get("failed_requests") or 0),
            -float(x.get("last_seen") or 0),
        ))
        assigned_active = False
        for item in items:
            if not item["online"]:
                item["role"] = "OFFLINE"
            elif not item["enabled"]:
                item["role"] = "IDLE (DISABLED)"
            elif not assigned_active:
                item["role"] = "ACTIVE (IN USE)"
                item["is_active_selected"] = True
                assigned_active = True
            else:
                item["role"] = "STANDBY (FALLBACK)"
                item["is_active_selected"] = False
        return items

    # ---------------------------------------------- Compatibility Aliases & Dynamic Rules
    def get_shortener_tunnels_list(self) -> list[dict]:
        return self.get_shortener_tunnel_list()

    def is_shortener_tunnel_enabled(self, domain_or_url: str) -> bool:
        return self.should_use_tunnel_for_url(domain_or_url)

    async def toggle_tunnel_device(self, device_id: str, enabled: bool) -> dict | None:
        return await self.set_tunnel_device_enabled(device_id, enabled)

    async def set_active_tunnel_device(self, device_id: str) -> dict | None:
        return await self.set_primary_tunnel_device(device_id)

    async def update_dynamic_rules(self, patch: dict[str, Any]) -> dict[str, Any]:
        cur = dict(self.settings.get("dynamic_rules") or {})
        for k, v in (patch or {}).items():
            if isinstance(v, dict) and isinstance(cur.get(k), dict):
                merged = dict(cur[k])
                merged.update(v)
                cur[k] = merged
            elif isinstance(v, list) and isinstance(cur.get(k), list):
                merged_l = list(cur[k])
                for item in v:
                    if item not in merged_l:
                        merged_l.append(item)
                cur[k] = merged_l
            else:
                cur[k] = v
        try:
            from g2s.engine import sanitize_dynamic_rules, set_dynamic_rules
            cur = sanitize_dynamic_rules(cur)
            set_dynamic_rules(cur)
        except Exception:
            pass
        await self.update_settings({"dynamic_rules": cur})
        return cur

    def is_strict_owner(self, user_id: int | str | None) -> bool:
        if not user_id:
            return False
        try:
            uid = int(user_id)
        except Exception:
            return False
        owner = int(self.settings.get("owner_id") or 0)
        return uid == owner and owner != 0

    # ---------------------------------------------- Protected Bots & Links Shield
    def _get_protected_bots_list(self) -> list[dict]:
        if "protected_bots" in self.settings and isinstance(self.settings["protected_bots"], list):
            return list(self.settings["protected_bots"])
        return list(DEFAULT_PROTECTED_BOTS)

    def _get_protected_bot_sets(self) -> tuple[set[str], set[str], set[str], set[str]]:
        """Returns (enabled_usernames, enabled_dbs, removed_or_disabled_usernames, removed_or_disabled_dbs)."""
        bots = self._get_protected_bots_list()
        enabled_unames = set()
        enabled_dbs = set()
        disabled_unames = set()
        disabled_dbs = set()
        for b in bots:
            un = str(b.get("username") or "").strip().lstrip("@").lower()
            dbn = str(b.get("db_name") or "").strip().lower()
            if b.get("enabled", True):
                if un:
                    enabled_unames.add(un)
                if dbn:
                    enabled_dbs.add(dbn)
            else:
                if un:
                    disabled_unames.add(un)
                if dbn:
                    disabled_dbs.add(dbn)

        all_def_unames = {
            str(b.get("username") or "").strip().lstrip("@").lower()
            for b in DEFAULT_PROTECTED_BOTS
            if b.get("username")
        }
        all_def_dbs = {
            str(b.get("db_name") or "").strip().lower()
            for b in DEFAULT_PROTECTED_BOTS
            if b.get("db_name")
        }
        explicit_removed = {
            str(x).strip().lstrip("@").lower()
            for x in (self.settings.get("removed_protected_bots") or [])
            if str(x).strip()
        }
        rem_unames = ((all_def_unames - enabled_unames) | disabled_unames | explicit_removed) - enabled_unames
        rem_dbs = ((all_def_dbs - enabled_dbs) | disabled_dbs) - enabled_dbs
        return enabled_unames, enabled_dbs, rem_unames, rem_dbs

    async def _purge_unprotected_bot_links(self, rem_unames: set[str], rem_dbs: set[str]):
        for k, v in list(self.protected_known_urls.items()):
            v_db = str(v.get("db_name") or "").strip().lower()
            v_un = str(v.get("username") or v.get("bot_name") or "").strip().lstrip("@").lower()
            if (v_db and v_db in rem_dbs) or (v_un and v_un in rem_unames):
                self.protected_known_urls.pop(k, None)
                if self.connected and self.db is not None:
                    try:
                        await self.db.protected_links.delete_one({"_id": k})
                    except Exception:
                        pass
        for h, v in list(self.protected_masked_hashes.items()):
            v_db = str(v.get("db_name") or "").strip().lower()
            if v_db and v_db in rem_dbs:
                self.protected_masked_hashes.pop(h, None)

    async def sync_protected_masked_links(self) -> dict[str, Any]:
        if not HAS_MOTOR:
            return {"ok": False, "synced_links": len(self.protected_known_urls)}
        async with self._protected_sync_lock:
            enabled_unames, enabled_dbs, rem_unames, rem_dbs = self._get_protected_bot_sets()
            await self._purge_unprotected_bot_links(rem_unames, rem_dbs)
            clusters = list(self.settings.get("protected_mongo_clusters") or DEFAULT_PROTECTED_MONGO_CLUSTERS)
            total_synced = 0
            clusters_ok = 0

            async def _fetch_cluster(cl: dict):
                nonlocal total_synced, clusters_ok
                if not cl.get("enabled", True):
                    return
                uri = str(cl.get("uri") or "").strip()
                if not uri:
                    return
                db_names = list(cl.get("databases") or [])
                try:
                    c = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=6000)
                    if not db_names:
                        db_names = [
                            d for d in await c.list_database_names()
                            if d not in ("admin", "local", "config")
                        ]
                    for dbn in db_names:
                        if dbn.lower() in rem_dbs:
                            continue
                        try:
                            mdb = c[dbn]
                            cursor = (
                                mdb["masked_links"]
                                .find({}, {"_id": 1, "target": 1})
                                .sort([("$natural", -1)])
                                .limit(2500)
                            )
                            async for doc in cursor:
                                hid = str(doc.get("_id") or "").strip()
                                target = norm_url(str(doc.get("target") or "").strip())
                                if hid:
                                    self.protected_masked_hashes[hid] = {
                                        "hash_id": hid,
                                        "target": target,
                                        "db_name": dbn,
                                        "cluster": cl.get("name") or cl.get("id"),
                                    }
                                if target:
                                    self.protected_known_urls[target] = {
                                        "source": target,
                                        "hash_id": hid,
                                        "db_name": dbn,
                                        "reason": f"Protected bot masked_links ({dbn})",
                                    }
                                    total_synced += 1
                        except Exception:
                            pass
                    clusters_ok += 1
                    c.close()
                except Exception:
                    pass

            await asyncio.gather(*(_fetch_cluster(cl) for cl in clusters), return_exceptions=True)
            self.protected_last_sync = time.time()
            return {
                "ok": True,
                "clusters_checked": len(clusters),
                "clusters_ok": clusters_ok,
                "synced_links": len(self.protected_known_urls),
                "synced_hashes": len(self.protected_masked_hashes),
                "last_sync": self.protected_last_sync,
            }

    async def record_protected_source_url(
        self,
        source_url: str,
        reason: str = "",
        bot_name: str = "",
        username: str = "",
        db_name: str = "",
    ):
        key = norm_url(source_url)
        if not key:
            return
        entry = {
            "source": key,
            "reason": reason or "Protected official bot link",
            "bot_name": bot_name,
            "username": username.lstrip("@").lower() if username else "",
            "db_name": db_name,
            "at": time.time(),
        }
        self.protected_known_urls[key] = entry
        if key in self.local_cache:
            await self.delete_cache(key)
        if self.connected and self.db is not None:
            try:
                await self.db.protected_links.update_one(
                    {"_id": self._mongo_doc_id(key)},
                    {"$set": entry},
                    upsert=True,
                )
            except Exception:
                pass

    def check_protected_destination_url(self, dest_url: str, source_url: str | None = None) -> dict | None:
        if not self.settings.get("protected_links_enabled", True):
            return None
        import re as _re
        from urllib.parse import urlparse

        d = (dest_url or "").strip()
        if not d:
            return None
        d_low = d.lower()
        rules = dict(DEFAULT_PROTECTED_RULES | (self.settings.get("protected_rules") or {}))
        enabled_unames, _, rem_unames, _ = self._get_protected_bot_sets()
        bots = [b for b in self._get_protected_bots_list() if b.get("enabled", True)]

        # Check Telegram bot usernames — ONLY block bots explicitly in our enabled protected_bots list!
        try:
            p = urlparse(d if "://" in d else f"https://{d}")
            host = (p.hostname or "").lower()
            path_seg = p.path.strip("/").split("/")[0] if p.path.strip("/") else ""

            if host in ("t.me", "telegram.me", "telegram.dog", "tx.me") and path_seg:
                uname_low = path_seg.lstrip("@").lower()
                # If this bot is not in enabled_unames (or was removed/disabled), NEVER block it!
                if uname_low in rem_unames or uname_low not in enabled_unames:
                    return None

                for b in bots:
                    b_uname = str(b.get("username") or "").strip().lstrip("@").lower()
                    if b_uname and uname_low == b_uname:
                        info = {
                            "protected": True,
                            "reason": f"Protected official bot (@{b.get('username')})",
                            "bot_name": b.get("name") or f"@{b.get('username')}",
                            "username": b.get("username"),
                        }
                        if source_url:
                            asyncio.create_task(
                                self.record_protected_source_url(
                                    source_url,
                                    info["reason"],
                                    info["bot_name"],
                                    username=str(b.get("username") or ""),
                                    db_name=str(b.get("db_name") or ""),
                                )
                            )
                        return info
        except Exception:
            pass

        # Check explicit admin-configured custom patterns
        for pat in rules.get("custom_patterns") or []:
            pat_s = str(pat or "").strip()
            if not pat_s:
                continue
            try:
                if pat_s.lower() in d_low or _re.search(pat_s, d, _re.I):
                    info = {
                        "protected": True,
                        "reason": f"Matched protected pattern ({pat_s})",
                        "bot_name": "Protected Partner Bot",
                    }
                    if source_url:
                        asyncio.create_task(
                            self.record_protected_source_url(source_url, info["reason"], info["bot_name"])
                        )
                    return info
            except Exception:
                pass
        return None

    def check_protected_source_url(self, url: str) -> dict | None:
        if not self.settings.get("protected_links_enabled", True):
            return None
        import re as _re
        from urllib.parse import urlparse

        key = norm_url(url)
        if not key:
            return None

        enabled_unames, enabled_dbs, rem_unames, rem_dbs = self._get_protected_bot_sets()
        prefix, _, slug = key.rpartition("/")
        alt_key = f"{prefix}/{slug[2:-2]}" if (slug.startswith("__") and slug.endswith("__") and len(slug) > 4) else ""

        # 1. Check if URL is in local_cache first — if cached destination belongs to an unlisted/removed bot, allow it!
        for k_try in (key, alt_key):
            if k_try and k_try in self.local_cache:
                cached_dest = (self.local_cache[k_try] or {}).get("url") or ""
                if cached_dest:
                    dm = self.check_protected_destination_url(cached_dest, source_url=key)
                    if dm:
                        return dm
                    # Destination is known and is NOT in our protected_bots list!
                    return None

        # 2. Direct match in synced masked_links / known protected shortlinks (verify bot is in enabled protected_bots!)
        for k_try in (key, alt_key):
            if k_try and k_try in self.protected_known_urls:
                hit = self.protected_known_urls[k_try]
                h_db = str(hit.get("db_name") or "").strip().lower()
                h_un = str(hit.get("username") or hit.get("bot_name") or "").strip().lstrip("@").lower()
                if (h_db and h_db in rem_dbs) or (h_un and h_un in rem_unames):
                    self.protected_known_urls.pop(k_try, None)
                    continue
                if not ((h_un and h_un in enabled_unames) or (h_db and h_db in enabled_dbs)):
                    self.protected_known_urls.pop(k_try, None)
                    continue
                return {
                    "protected": True,
                    "reason": hit.get("reason") or "Protected official bot shortlink",
                    "bot_name": hit.get("bot_name") or hit.get("db_name") or "Official Partner Bot",
                }

        rules = dict(DEFAULT_PROTECTED_RULES | (self.settings.get("protected_rules") or {}))

        # 3. Check if URL itself is a direct link to an enabled protected bot (e.g. t.me/DDNewsXDBot?start=...)
        dest_match = self.check_protected_destination_url(key)
        if dest_match:
            return dest_match

        try:
            p = urlparse(key)
            path = p.path or ""
            # 4. Check /r/<hash_id> masked redirect link ONLY if hash_id exists in our synced protected_masked_hashes
            m_hash = _re.match(r"^/r/([A-Za-z0-9_-]{6,16})/?$", path)
            if m_hash:
                hid = m_hash.group(1)
                if hid in self.protected_masked_hashes:
                    mh = self.protected_masked_hashes[hid]
                    mh_db = str(mh.get("db_name") or "").lower()
                    if mh_db in enabled_dbs and mh_db not in rem_dbs:
                        return {
                            "protected": True,
                            "reason": f"Protected masked redirect link ({mh.get('db_name')})",
                            "bot_name": mh.get("db_name") or "Official Partner Bot",
                        }
        except Exception:
            pass

        # 5. Check explicit admin-configured custom patterns on source URL
        key_low = key.lower()
        for pat in rules.get("custom_patterns") or []:
            pat_s = str(pat or "").strip()
            if not pat_s:
                continue
            try:
                if pat_s.lower() in key_low or _re.search(pat_s, key, _re.I):
                    return {
                        "protected": True,
                        "reason": f"Matched protected pattern ({pat_s})",
                        "bot_name": "Protected Partner Bot",
                    }
            except Exception:
                pass

        return None

    def get_protected_config(self) -> dict[str, Any]:
        bots = self._get_protected_bots_list()
        clusters = list(self.settings.get("protected_mongo_clusters") or DEFAULT_PROTECTED_MONGO_CLUSTERS)
        safe_clusters = []
        for c in clusters:
            uri = str(c.get("uri") or "")
            import re as _re
            masked_uri = _re.sub(r"(://[^:/@]+:)[^@]+@", r"\1•••@", uri) if uri else ""
            safe_clusters.append({**c, "uri_masked": masked_uri})
        rules = dict(DEFAULT_PROTECTED_RULES | (self.settings.get("protected_rules") or {}))
        payload = {
            "ok": True,
            "enabled": bool(self.settings.get("protected_links_enabled", True)),
            "message": self.settings.get("protected_message") or DEFAULT_PROTECTED_MESSAGE,
            "bots": bots,
            "clusters": safe_clusters,
            "rules": rules,
            "synced_links_count": len(self.protected_known_urls),
            "synced_masked_links_count": len(self.protected_known_urls),
            "synced_hashes_count": len(self.protected_masked_hashes),
            "last_sync": self.protected_last_sync,
        }
        payload["protected"] = dict(payload)
        return payload

    async def add_protected_bot(self, data: dict[str, Any]) -> dict[str, Any]:
        import re as _re
        import aiohttp
        raw_input = str(data.get("username") or data.get("input") or data.get("repo") or "").strip()
        name = str(data.get("name") or "").strip()
        repo = str(data.get("repo") or "").strip()
        db_name = str(data.get("db_name") or "").strip()
        username = str(data.get("username") or "").strip()

        if "github.com/" in raw_input and not repo:
            repo = raw_input
            if raw_input == username:
                username = ""

        if "t.me/" in username:
            username = username.split("t.me/", 1)[1].split("?")[0].strip("/")
        username = username.lstrip("@").strip()

        # Check if it matches one of DEFAULT_PROTECTED_BOTS (works even when GitHub repo is private!)
        for def_b in DEFAULT_PROTECTED_BOTS:
            if (
                (username and str(def_b.get("username") or "").lower() == username.lower())
                or (repo and str(def_b.get("repo") or "").lower().rstrip("/") == repo.lower().rstrip("/"))
                or (name and str(def_b.get("name") or "").lower() == name.lower())
            ):
                username = username or def_b.get("username") or ""
                name = name or def_b.get("name") or ""
                repo = repo or def_b.get("repo") or ""
                db_name = db_name or def_b.get("db_name") or ""
                break

        # Optional public GitHub config.py lookup if a new public repo URL was given
        if repo and "github.com/" in repo and (not username or not name):
            m = _re.search(r"github\.com/([^/]+/[^/#?]+)", repo)
            if m:
                slug = m.group(1).removesuffix(".git")
                if not name:
                    name = slug.split("/")[-1]
                try:
                    async with aiohttp.ClientSession() as s:
                        for br in ("main", "master"):
                            cfg_u = f"https://raw.githubusercontent.com/{slug}/{br}/config.py"
                            async with s.get(cfg_u, timeout=aiohttp.ClientTimeout(total=8)) as r:
                                if r.status == 200:
                                    txt = await r.text()
                                    tok_m = _re.search(r"\d{8,11}:[A-Za-z0-9_-]{30,40}", txt)
                                    if tok_m and not username:
                                        async with s.get(
                                            f"https://api.telegram.org/bot{tok_m.group(0)}/getMe",
                                            timeout=aiohttp.ClientTimeout(total=6),
                                        ) as rm:
                                            dm = await rm.json(content_type=None)
                                            if dm.get("ok"):
                                                username = dm["result"].get("username") or ""
                                    db_m = _re.search(r'DATABASE_NAME\s*=.*?"([^"]+)"', txt)
                                    if db_m and not db_name:
                                        db_name = db_m.group(1)
                                    uri_m = _re.search(r'(mongodb(?:\+srv)?://[^\s"\']+)', txt)
                                    if uri_m and db_name:
                                        await self.add_protected_cluster({
                                            "name": f"{name} Cluster",
                                            "uri": uri_m.group(1),
                                            "databases": [db_name],
                                        })
                                    break
                except Exception:
                    pass

        if not name:
            name = f"@{username}" if username else (repo.split("/")[-1] if repo else "Protected Bot")
        bot_id = _re.sub(r"[^a-z0-9_-]+", "-", (username or name).lower()).strip("-") or uuid.uuid4().hex[:8]

        bots = self._get_protected_bots_list()
        updated = False
        for b in bots:
            if (
                b.get("id") == bot_id
                or (username and str(b.get("username") or "").lower() == username.lower())
            ):
                b["name"] = name or b.get("name")
                if username:
                    b["username"] = username
                if repo:
                    b["repo"] = repo
                if db_name:
                    b["db_name"] = db_name
                b["enabled"] = bool(data.get("enabled", True))
                updated = True
                break
        if not updated:
            bots.append({
                "id": bot_id,
                "name": name,
                "username": username,
                "repo": repo,
                "db_name": db_name,
                "enabled": bool(data.get("enabled", True)),
            })
        rem_list = [
            x for x in (self.settings.get("removed_protected_bots") or [])
            if str(x).lower() not in {bot_id.lower(), username.lower()}
        ]
        await self.update_settings({"protected_bots": bots, "removed_protected_bots": rem_list})
        asyncio.create_task(self.sync_protected_masked_links())
        return self.get_protected_config()

    async def toggle_protected_bot(self, bot_id: str, enabled: bool) -> dict[str, Any]:
        target = str(bot_id or "").lstrip("@").strip().lower()
        bots = self._get_protected_bots_list()
        for b in bots:
            if (
                str(b.get("id") or "").lower() == target
                or str(b.get("username") or "").lstrip("@").lower() == target
            ):
                b["enabled"] = bool(enabled)
        await self.update_settings({"protected_bots": bots})
        _, _, rem_unames, rem_dbs = self._get_protected_bot_sets()
        await self._purge_unprotected_bot_links(rem_unames, rem_dbs)
        if enabled:
            asyncio.create_task(self.sync_protected_masked_links())
        return self.get_protected_config()

    async def delete_protected_bot(self, bot_id: str) -> dict[str, Any]:
        target = str(bot_id or "").lstrip("@").strip().lower()
        cur_bots = self._get_protected_bots_list()
        removed_unames = list(self.settings.get("removed_protected_bots") or [])
        bots = []
        for b in cur_bots:
            bid_l = str(b.get("id") or "").lower()
            bun_l = str(b.get("username") or "").lstrip("@").lower()
            if bid_l == target or bun_l == target:
                if bun_l and bun_l not in removed_unames:
                    removed_unames.append(bun_l)
                if bid_l and bid_l not in removed_unames:
                    removed_unames.append(bid_l)
                continue
            bots.append(b)
        await self.update_settings({"protected_bots": bots, "removed_protected_bots": removed_unames})
        _, _, rem_unames, rem_dbs = self._get_protected_bot_sets()
        await self._purge_unprotected_bot_links(rem_unames, rem_dbs)
        return self.get_protected_config()

    async def add_protected_cluster(self, data: dict[str, Any]) -> dict[str, Any]:
        uri = str(data.get("uri") or "").strip()
        if not uri:
            return self.get_protected_config()
        name = str(data.get("name") or "Protected Bot Cluster").strip()
        dbs = data.get("databases") or []
        if isinstance(dbs, str):
            dbs = [x.strip() for x in dbs.split(",") if x.strip()]
        cid = str(data.get("id") or f"cluster-{uuid.uuid4().hex[:6]}")
        clusters = list(self.settings.get("protected_mongo_clusters") or DEFAULT_PROTECTED_MONGO_CLUSTERS)
        updated = False
        for c in clusters:
            if c.get("uri") == uri or c.get("id") == cid:
                c["name"] = name or c.get("name")
                c["uri"] = uri
                for d in dbs:
                    if d not in c.setdefault("databases", []):
                        c["databases"].append(d)
                c["enabled"] = True
                updated = True
                break
        if not updated:
            clusters.append({
                "id": cid,
                "name": name,
                "uri": uri,
                "databases": list(dbs),
                "enabled": True,
            })
        await self.update_settings({"protected_mongo_clusters": clusters})
        asyncio.create_task(self.sync_protected_masked_links())
        return self.get_protected_config()

    async def delete_protected_cluster(self, cluster_id: str) -> dict[str, Any]:
        clusters = [
            c for c in (self.settings.get("protected_mongo_clusters") or DEFAULT_PROTECTED_MONGO_CLUSTERS)
            if c.get("id") != cluster_id
        ]
        await self.update_settings({"protected_mongo_clusters": clusters})
        return self.get_protected_config()

    async def update_protected_rules(self, data: dict[str, Any]) -> dict[str, Any]:
        patch = {}
        if "enabled" in data:
            patch["protected_links_enabled"] = bool(data["enabled"])
        if "message" in data and str(data["message"]).strip():
            patch["protected_message"] = str(data["message"]).strip()
        cur_rules = dict(DEFAULT_PROTECTED_RULES | (self.settings.get("protected_rules") or {}))
        rsrc = dict(data)
        if isinstance(data.get("rules"), dict):
            rsrc.update(data["rules"])
        for rk in ("block_double_underscore_alias", "block_yu3elk_payload", "block_masked_redirect_routes"):
            if rk in rsrc:
                cur_rules[rk] = bool(rsrc[rk])
        if "block_masked_redirect" in rsrc:
            cur_rules["block_masked_redirect_routes"] = bool(rsrc["block_masked_redirect"])
        if "custom_patterns" in rsrc and isinstance(rsrc["custom_patterns"], list):
            cur_rules["custom_patterns"] = [str(x).strip() for x in rsrc["custom_patterns"] if str(x).strip()]
        if "add_pattern" in rsrc and str(data["add_pattern"]).strip():
            pat = str(data["add_pattern"]).strip()
            if pat not in cur_rules.setdefault("custom_patterns", []):
                cur_rules["custom_patterns"].append(pat)
        if "remove_pattern" in rsrc:
            pat = str(data["remove_pattern"]).strip()
            cur_rules["custom_patterns"] = [x for x in cur_rules.get("custom_patterns", []) if x != pat]
        patch["protected_rules"] = cur_rules
        await self.update_settings(patch)
        return self.get_protected_config()

    # ---------------------------------------------- Premium Plans, Free Trial & Paytm Orders
    def _get_user_lock(self, user_id: int) -> asyncio.Lock:
        uid = int(user_id)
        lk = self._user_locks.get(uid)
        if lk is None:
            lk = asyncio.Lock()
            self._user_locks[uid] = lk
        return lk

    def get_premium_plans(self, only_enabled: bool = False) -> list[dict]:
        raw_plans = self.settings.get("premium_plans")
        if not isinstance(raw_plans, list) or not raw_plans:
            raw_plans = [dict(p) for p in DEFAULT_PREMIUM_PLANS]
        out = []
        for idx, p in enumerate(raw_plans):
            if not isinstance(p, dict):
                continue
            enabled = bool(p.get("enabled", True))
            if only_enabled and not enabled:
                continue
            days = max(1, int(p.get("days") or 30))
            amt = float(p.get("amount") or 100)
            amt_disp = int(amt) if amt == int(amt) else amt
            key = str(p.get("key") or f"plan_{idx+1}").strip()
            name = str(p.get("name") or p.get("label") or f"{days} Days").strip()
            ptype = str(p.get("plan_type") or key).strip()
            pstr = str(p.get("price_str") or f"₹ {amt_disp}").strip()
            badge = str(p.get("badge") or "").strip()
            out.append({
                "key": key,
                "plan_type": ptype,
                "name": name,
                "label": name,
                "days": days,
                "amount": amt_disp,
                "price_str": pstr,
                "badge": badge,
                "enabled": enabled,
            })
        return out

    def get_plan_by_key(self, key: str) -> dict | None:
        k_low = str(key or "").strip().lower()
        for p in self.get_premium_plans(only_enabled=False):
            if (
                p["key"].lower() == k_low
                or p["plan_type"].lower() == k_low
                or p["name"].lower() == k_low
                or f"{p['days']}d" == k_low
                or f"{p['days']}_days" == k_low
            ):
                return p
        return None

    async def save_premium_plans(self, plans: list[dict]) -> list[dict]:
        cleaned = []
        for idx, p in enumerate(plans or []):
            if not isinstance(p, dict):
                continue
            days = max(1, int(p.get("days") or 30))
            amt = float(p.get("amount") or 100)
            amt_disp = int(amt) if amt == int(amt) else amt
            key = str(p.get("key") or f"plan_{days}d_{idx+1}").strip()
            name = str(p.get("name") or p.get("label") or f"{days} Days").strip()
            ptype = str(p.get("plan_type") or key).strip()
            badge = str(p.get("badge") or "").strip()
            cleaned.append({
                "key": key,
                "plan_type": ptype,
                "name": name,
                "label": name,
                "days": days,
                "amount": amt_disp,
                "price_str": f"₹ {amt_disp}",
                "badge": badge,
                "enabled": bool(p.get("enabled", True)),
            })
        if not cleaned:
            cleaned = [dict(p) for p in DEFAULT_PREMIUM_PLANS]
        await self.update_settings({"premium_plans": cleaned})
        return self.get_premium_plans()

    async def upsert_premium_plan(self, plan_data: dict) -> dict[str, Any]:
        plans = self.get_premium_plans(only_enabled=False)
        days = max(1, int(plan_data.get("days") or 30))
        amt = float(plan_data.get("amount") or 100)
        amt_disp = int(amt) if amt == int(amt) else amt
        key = str(plan_data.get("key") or "").strip()
        name = str(plan_data.get("name") or plan_data.get("label") or f"{days} Days").strip()
        ptype = str(plan_data.get("plan_type") or key or f"{days}_days").strip()
        badge = str(plan_data.get("badge") or "").strip()
        if not key:
            import re as _re
            key = "plan_" + (_re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or f"{days}d")

        found = False
        for p in plans:
            if p["key"].lower() == key.lower():
                p["name"] = name
                p["label"] = name
                p["plan_type"] = ptype
                p["days"] = days
                p["amount"] = amt_disp
                p["price_str"] = f"₹ {amt_disp}"
                p["badge"] = badge
                p["enabled"] = bool(plan_data.get("enabled", True))
                found = True
                break
        if not found:
            plans.append({
                "key": key,
                "plan_type": ptype,
                "name": name,
                "label": name,
                "days": days,
                "amount": amt_disp,
                "price_str": f"₹ {amt_disp}",
                "badge": badge,
                "enabled": bool(plan_data.get("enabled", True)),
            })
        await self.update_settings({"premium_plans": plans})
        return await self.get_premium_dashboard_config()

    async def delete_premium_plan(self, plan_key: str) -> dict[str, Any]:
        target = str(plan_key or "").strip().lower()
        plans = [p for p in self.get_premium_plans(only_enabled=False) if p["key"].lower() != target]
        await self.update_settings({"premium_plans": plans})
        return await self.get_premium_dashboard_config()

    def get_user_premium_status(self, user_id: int) -> dict[str, Any]:
        uid = int(user_id or 0)
        now = time.time()
        free_limit = max(0, int(self.settings.get("free_trial_limit", 3)))
        doc = self.local_users.get(uid) or {}
        prem_until = float(doc.get("premium_until") or 0.0)
        exp_iso = str(doc.get("expiration_timestamp") or "")
        if not prem_until and exp_iso:
            try:
                from datetime import datetime
                prem_until = datetime.fromisoformat(exp_iso.replace("Z", "+00:00")).timestamp()
            except Exception:
                prem_until = 0.0

        is_adm = self.is_admin(uid)
        is_prem = is_adm or (prem_until > now)
        has_bought = bool(doc.get("has_ever_bought_plan", False)) or (prem_until > 0)
        was_expired = (not is_prem) and has_bought and (prem_until > 0 and now >= prem_until)
        free_used = int(doc.get("free_uses") if "free_uses" in doc else (doc.get("free_uses_used") or 0))
        if was_expired:
            free_rem = 0
        else:
            free_rem = max(0, free_limit - free_used)

        rem_sec = max(0, int(prem_until - now)) if prem_until > now else 0
        days = rem_sec // 86400
        hours = (rem_sec % 86400) // 3600
        mins = (rem_sec % 3600) // 60
        secs = rem_sec % 60
        rem_str = f"{days}d {hours}h {mins}m {secs}s" if rem_sec > 0 else "0s"

        return {
            "user_id": uid,
            "is_admin": is_adm,
            "is_premium": is_prem,
            "premium_expired": was_expired,
            "was_premium_expired": was_expired,
            "has_ever_bought_plan": has_bought,
            "premium_until": prem_until,
            "expiry_str": "Lifetime (Admin)" if is_adm else (format_ist_expiry(prem_until) if prem_until > 0 else "N/A"),
            "expired_str": format_ist_expiry(prem_until) if prem_until > 0 else "",
            "remaining_seconds": rem_sec,
            "remaining_str": "Unlimited (Admin)" if is_adm else rem_str,
            "plan_type": doc.get("plan_type") or doc.get("premium_plan_type") or ("admin" if is_adm else ""),
            "plan_label": doc.get("plan_label") or doc.get("premium_plan_label") or ("Admin Unlimited" if is_adm else ""),
            "free_used": free_used,
            "free_limit": free_limit,
            "free_left": free_rem,
            "free_remaining": free_rem,
        }

    async def try_consume_access_slot(
        self,
        user_id: int,
        from_user: dict | None = None,
        is_admin: bool | None = None,
    ) -> dict[str, Any]:
        """Atomically checks and consumes 1 access slot for a user.
        Returns a dict with:
          - allowed: bool
          - reason: "admin" | "premium" | "free_trial" | "free_trial_exhausted" | "premium_expired" | "free_mode"
          - consumed_free_slot: bool
          - free_used, free_limit, free_left
        """
        uid = int(user_id or 0)
        async with self._get_user_lock(uid):
            if from_user:
                await self.touch_user(from_user, increment_bypass=False)

            adm = bool(is_admin) if is_admin is not None else self.is_admin(uid)
            st = self.get_user_premium_status(uid)
            if adm:
                return {
                    **st,
                    "allowed": True,
                    "reason": "admin",
                    "mode": "admin",
                    "consumed_free_slot": False,
                }

            if not self.settings.get("premium_only_enabled", True):
                return {
                    **st,
                    "allowed": True,
                    "reason": "free_mode",
                    "mode": "free_mode",
                    "consumed_free_slot": False,
                }

            if st["is_premium"]:
                return {
                    **st,
                    "allowed": True,
                    "reason": "premium",
                    "mode": "premium",
                    "consumed_free_slot": False,
                }

            if st["was_premium_expired"]:
                return {
                    **st,
                    "allowed": False,
                    "reason": "premium_expired",
                    "mode": "expired",
                    "consumed_free_slot": False,
                }

            if st["free_used"] < st["free_limit"]:
                doc = await self.get_user(uid) or {
                    "user_id": uid,
                    "username": (from_user or {}).get("username") or "",
                    "first_name": (from_user or {}).get("first_name") or "User",
                    "last_name": (from_user or {}).get("last_name") or "",
                    "joined_at": time.time(),
                    "last_active": time.time(),
                    "bypass_count": 0,
                    "banned": False,
                }
                cur_used = int(doc.get("free_uses") if "free_uses" in doc else (doc.get("free_uses_used") or 0))
                new_used = cur_used + 1
                doc["free_uses"] = new_used
                doc["free_uses_used"] = new_used
                doc["last_active"] = time.time()
                self.local_users[uid] = doc
                if self.connected and self.db is not None:
                    try:
                        await self.db.users.update_one(
                            {"_id": uid},
                            {"$set": doc},
                            upsert=True,
                        )
                    except Exception:
                        pass
                free_left = max(0, st["free_limit"] - new_used)
                return {
                    **st,
                    "allowed": True,
                    "reason": "free_trial",
                    "mode": "free_trial",
                    "consumed_free_slot": True,
                    "free_used": new_used,
                    "free_left": free_left,
                    "free_remaining": free_left,
                }

            return {
                **st,
                "allowed": False,
                "reason": "free_trial_exhausted",
                "mode": "exhausted",
                "consumed_free_slot": False,
            }

    async def refund_free_slot(self, user_id: int):
        uid = int(user_id or 0)
        async with self._get_user_lock(uid):
            doc = await self.get_user(uid)
            if not doc:
                return
            cur = int(doc.get("free_uses") if "free_uses" in doc else (doc.get("free_uses_used") or 0))
            if cur > 0:
                doc["free_uses"] = cur - 1
                doc["free_uses_used"] = cur - 1
                self.local_users[uid] = doc
                if self.connected and self.db is not None:
                    try:
                        await self.db.users.update_one(
                            {"_id": uid},
                            {"$set": {"free_uses": doc["free_uses"], "free_uses_used": doc["free_uses_used"]}},
                        )
                    except Exception:
                        pass

    async def add_premium_user(
        self,
        user_id: int,
        time_value: float,
        plan_type: str = "premium",
        plan_label: str = "",
        source: str = "manual",
        added_by: int | None = None,
        time_unit: str = "d",
    ) -> dict[str, Any]:
        from datetime import datetime, timezone, timedelta
        uid = int(user_id)
        ist = timezone(timedelta(hours=5, minutes=30))
        now_ts = time.time()
        async with self._get_user_lock(uid):
            doc = await self.get_user(uid) or {
                "user_id": uid,
                "username": "",
                "first_name": "User",
                "last_name": "",
                "joined_at": now_ts,
                "last_active": now_ts,
                "bypass_count": 0,
                "banned": False,
                "free_uses": 0,
                "free_uses_used": 0,
            }
            cur_until = float(doc.get("premium_until") or 0.0)
            base_ts = cur_until if cur_until > now_ts else now_ts

            unit = str(time_unit or "d").strip().lower()
            val = float(time_value)
            if unit.startswith("s"):
                delta_sec = val
            elif unit == "m":
                delta_sec = val * 30.0 * 86400.0
            elif unit.startswith("min"):
                delta_sec = val * 60.0
            elif unit.startswith("h"):
                delta_sec = val * 3600.0
            elif unit.startswith("y"):
                delta_sec = val * 365.0 * 86400.0
            else:
                delta_sec = val * 86400.0

            days_int = max(1, int(round(delta_sec / 86400.0)))
            new_until = base_ts + delta_sec
            exp_dt = datetime.fromtimestamp(new_until, tz=ist)
            exp_iso = exp_dt.isoformat()
            exp_str = exp_dt.strftime("%d %b %Y, %I:%M %p IST")

            if not plan_label:
                matched = self.get_plan_by_key(plan_type)
                if matched:
                    plan_label = f"💎 {matched['name']}"
                else:
                    plan_label = f"💎 {plan_type.upper()} ({days_int} Days)" if days_int > 0 else f"💎 {plan_type.upper()}"

            free_limit = max(3, int(self.settings.get("free_trial_limit", 3)))
            doc["is_premium"] = True
            doc["premium_until"] = new_until
            doc["expiration_timestamp"] = exp_iso
            doc["plan_type"] = str(plan_type or "premium")
            doc["premium_plan_type"] = str(plan_type or "premium")
            doc["plan_label"] = plan_label
            doc["premium_plan_label"] = plan_label
            doc["premium_source"] = source
            doc["premium_added_by"] = added_by
            doc["has_ever_bought_plan"] = True
            doc["expired_notified"] = False
            doc["free_uses"] = max(int(doc.get("free_uses") or 0), free_limit)
            doc["free_uses_used"] = max(int(doc.get("free_uses_used") or 0), free_limit)
            self.local_users[uid] = doc

            if self.connected and self.db is not None:
                try:
                    await self.db.users.update_one(
                        {"_id": uid},
                        {"$set": doc},
                        upsert=True,
                    )
                    await self.db["premium-users"].update_one(
                        {"user_id": uid},
                        {"$set": {
                            "user_id": uid,
                            "expiration_timestamp": exp_iso,
                            "premium_until": new_until,
                            "plan_type": doc["plan_type"],
                            "plan_label": plan_label,
                            "source": source,
                            "updated_at": now_ts,
                        }},
                        upsert=True,
                    )
                except Exception:
                    pass

            return {
                "user_id": uid,
                "is_premium": True,
                "days_added": days_int,
                "premium_until": new_until,
                "expiration_timestamp": exp_iso,
                "expiry_str": exp_str,
                "plan_type": doc["plan_type"],
                "plan_label": plan_label,
                "source": source,
            }

    async def remove_premium_user(self, user_id: int) -> bool:
        uid = int(user_id)
        async with self._get_user_lock(uid):
            doc = await self.get_user(uid)
            if doc:
                doc["is_premium"] = False
                doc["premium_until"] = 0.0
                doc["expiration_timestamp"] = ""
                doc["plan_type"] = ""
                doc["plan_label"] = ""
                doc["has_ever_bought_plan"] = True
                doc["expired_notified"] = True
                self.local_users[uid] = doc
            if self.connected and self.db is not None:
                try:
                    if doc:
                        await self.db.users.update_one({"_id": uid}, {"$set": doc}, upsert=True)
                    await self.db["premium-users"].delete_one({"user_id": uid})
                except Exception:
                    pass
            return True

    async def list_active_premium_users(self) -> list[dict]:
        now = time.time()
        out = []
        for uid, doc in list(self.local_users.items()):
            p_until = float(doc.get("premium_until") or 0.0)
            if p_until > now:
                rem = int(p_until - now)
                d, h, m = rem // 86400, (rem % 86400) // 3600, (rem % 3600) // 60
                out.append({
                    "user_id": uid,
                    "username": doc.get("username") or "",
                    "first_name": doc.get("first_name") or "User",
                    "plan_type": doc.get("plan_type") or doc.get("premium_plan_type") or "premium",
                    "plan_label": doc.get("plan_label") or doc.get("premium_plan_label") or "Premium",
                    "premium_until": p_until,
                    "expiry_str": format_ist_expiry(p_until),
                    "remaining_seconds": rem,
                    "remaining_str": f"{d}d {h}h {m}m",
                    "source": doc.get("premium_source") or "payment",
                })
        out.sort(key=lambda x: x["premium_until"], reverse=True)
        return out

    async def check_and_expire_premium_users(self) -> list[dict]:
        """Finds users whose premium plan just expired and hasn't been notified yet."""
        now = time.time()
        newly_expired = []
        for uid, doc in list(self.local_users.items()):
            p_until = float(doc.get("premium_until") or 0.0)
            if 0 < p_until <= now and not doc.get("expired_notified", False):
                doc["is_premium"] = False
                doc["expired_notified"] = True
                self.local_users[uid] = doc
                newly_expired.append({
                    **doc,
                    "user_id": uid,
                    "expired_str": format_ist_expiry(p_until),
                })
                if self.connected and self.db is not None:
                    try:
                        await self.db.users.update_one(
                            {"_id": uid},
                            {"$set": {"is_premium": False, "expired_notified": True}},
                        )
                        await self.db["premium-users"].delete_one({"user_id": uid})
                    except Exception:
                        pass
        return newly_expired

    # ---------------------------------------------- Paytm Orders Persistence
    async def create_order(
        self,
        order_id: str,
        user_id: int,
        amount: float,
        days: int,
        plan_key: str,
        plan_type: str = "",
        plan_label: str = "",
        gateway: str = "paytm",
        chat_id: int | None = None,
        qr_message_id: int | None = None,
        extra: dict | None = None,
    ) -> dict:
        now = time.time()
        max_min = int(self.settings.get("payment_max_minutes", 15))
        doc = {
            "_id": str(order_id),
            "order_id": str(order_id),
            "user_id": int(user_id),
            "amount": float(amount),
            "payable_amount": float((extra or {}).get("payable_amount") or amount),
            "days": int(days),
            "plan_key": str(plan_key),
            "plan_type": str(plan_type or plan_key),
            "plan_label": str(plan_label or plan_key),
            "gateway": str(gateway or "paytm"),
            "status": "pending",
            "txn_id": None,
            "bank_txn_id": None,
            "txn_date": None,
            "chat_id": int(chat_id) if chat_id is not None else int(user_id),
            "qr_message_id": int(qr_message_id) if qr_message_id is not None else None,
            "created_at": now,
            "expiry_ts": now + (max_min * 60),
            "completed_at": None,
            "extra": dict(extra or {}),
        }
        self.local_orders[str(order_id)] = doc
        if self.connected and self.db is not None:
            try:
                await self.db.paytm_orders.update_one(
                    {"_id": str(order_id)},
                    {"$set": doc},
                    upsert=True,
                )
            except Exception:
                pass
        return doc

    async def get_order(self, order_id: str) -> dict | None:
        oid = str(order_id or "").strip()
        if not oid:
            return None
        if self.connected and self.db is not None:
            try:
                doc = await self.db.paytm_orders.find_one({"_id": oid})
                if doc:
                    self.local_orders[oid] = dict(doc)
                    return dict(doc)
            except Exception:
                pass
        return self.local_orders.get(oid)

    async def get_pending_order_for_user(self, user_id: int) -> dict | None:
        uid = int(user_id)
        max_age = float(self.settings.get("payment_max_minutes", 15)) * 60.0
        cutoff = time.time() - max_age
        for oid, o in list(self.local_orders.items()):
            if int(o.get("user_id") or 0) == uid and o.get("status") == "pending":
                if float(o.get("created_at") or 0) >= cutoff:
                    return o
                else:
                    await self.update_order_status(oid, "expired")
        if self.connected and self.db is not None:
            try:
                doc = await self.db.paytm_orders.find_one({
                    "user_id": uid,
                    "status": "pending",
                    "created_at": {"$gte": cutoff},
                })
                if doc:
                    self.local_orders[str(doc["_id"])] = dict(doc)
                    return dict(doc)
            except Exception:
                pass
        return None

    async def claim_order_processing(self, order_id: str) -> bool:
        oid = str(order_id or "").strip()
        if not oid:
            return False
        now = time.time()
        stale_cutoff = now - 15.0
        if self.connected and self.db is not None:
            try:
                from pymongo import ReturnDocument
                res = await self.db.paytm_orders.find_one_and_update(
                    {
                        "_id": oid,
                        "$or": [
                            {"status": "pending"},
                            {"status": "processing", "claimed_at": {"$lt": stale_cutoff}},
                            {"status": "processing", "claimed_at": {"$exists": False}},
                        ],
                    },
                    {"$set": {"status": "processing", "claimed_at": now}},
                    return_document=ReturnDocument.AFTER,
                )
                if res:
                    self.local_orders[oid] = dict(res)
                    return True
                return False
            except Exception:
                pass
        o = self.local_orders.get(oid)
        if o and (
            o.get("status") == "pending"
            or (o.get("status") == "processing" and float(o.get("claimed_at") or 0) < stale_cutoff)
        ):
            o["status"] = "processing"
            o["claimed_at"] = now
            return True
        return False

    async def update_order_status(
        self,
        order_id: str,
        status: str,
        txn_id: str | None = None,
        txn_info: dict | None = None,
    ) -> bool:
        oid = str(order_id or "").strip()
        if not oid:
            return False
        now = time.time()
        patch: dict[str, Any] = {"status": status, "updated_at": now}
        if status == "success":
            patch["completed_at"] = now
        if txn_id:
            patch["txn_id"] = str(txn_id)
        if txn_info:
            if txn_info.get("bank_txn_id"):
                patch["bank_txn_id"] = str(txn_info["bank_txn_id"])
            if txn_info.get("txn_date"):
                patch["txn_date"] = str(txn_info["txn_date"])
        if oid in self.local_orders:
            self.local_orders[oid].update(patch)
        if self.connected and self.db is not None:
            try:
                await self.db.paytm_orders.update_one({"_id": oid}, {"$set": patch})
            except Exception:
                pass
        return True

    async def cancel_order_if_pending(self, order_id: str, user_id: int | None = None) -> bool:
        oid = str(order_id or "").strip()
        o = await self.get_order(oid)
        if not o or o.get("status") != "pending":
            return False
        if user_id is not None and int(o.get("user_id") or 0) != int(user_id):
            return False
        await self.update_order_status(oid, "cancelled")
        return True

    async def is_txn_id_used(self, txn_id: str) -> bool:
        tid = str(txn_id or "").strip()
        if not tid:
            return False
        for o in self.local_orders.values():
            if o.get("status") == "success" and str(o.get("txn_id") or "") == tid:
                return True
        if self.connected and self.db is not None:
            try:
                doc = await self.db.paytm_orders.find_one({"txn_id": tid, "status": "success"})
                if doc:
                    return True
            except Exception:
                pass
        return False

    async def list_orders(self, limit: int = 100, status: str | None = None) -> list[dict]:
        if self.connected and self.db is not None:
            try:
                q = {"status": status} if status else {}
                out = []
                cursor = self.db.paytm_orders.find(q).sort("created_at", -1).limit(limit)
                async for doc in cursor:
                    d = dict(doc)
                    d["order_id"] = str(d.pop("_id", d.get("order_id", "")))
                    d["created_str"] = format_ist_expiry(d.get("created_at"))
                    out.append(d)
                return out
            except Exception:
                pass
        items = list(self.local_orders.values())
        if status:
            items = [x for x in items if x.get("status") == status]
        items.sort(key=lambda x: float(x.get("created_at") or 0), reverse=True)
        out = []
        for x in items[:limit]:
            d = {k: v for k, v in x.items() if k != "_id"}
            d["order_id"] = str(x.get("order_id") or x.get("_id") or "")
            d["created_str"] = format_ist_expiry(d.get("created_at"))
            out.append(d)
        return out

    async def get_premium_dashboard_config(self) -> dict[str, Any]:
        plans = self.get_premium_plans(only_enabled=False)
        prem_users = await self.list_active_premium_users()
        orders = await self.list_orders(limit=100)
        paid_orders = [o for o in orders if o.get("status") == "success"]
        total_revenue = sum(float(o.get("amount") or 0) for o in paid_orders)
        return {
            "ok": True,
            "premium_only_enabled": bool(self.settings.get("premium_only_enabled", True)),
            "free_trial_limit": int(self.settings.get("free_trial_limit", 3)),
            "plans": plans,
            "upi_id": self.settings.get("upi_id") or DEFAULT_PAYMENT_CONFIG["upi_id"],
            "upi_payee_name": self.settings.get("upi_payee_name") or DEFAULT_PAYMENT_CONFIG["upi_payee_name"],
            "paytm_mid": self.settings.get("paytm_mid") or DEFAULT_PAYMENT_CONFIG["paytm_mid"],
            "payment_api_url": self.settings.get("payment_api_url") or DEFAULT_PAYMENT_CONFIG["payment_api_url"],
            "payment_verify_interval": int(self.settings.get("payment_verify_interval", 12)),
            "payment_max_minutes": int(self.settings.get("payment_max_minutes", 15)),
            "payment_log_channel_id": int(self.settings.get("payment_log_channel_id", -1003270558605)),
            "owner_contact_url": self.settings.get("owner_contact_url") or DEFAULT_PAYMENT_CONFIG["owner_contact_url"],
            "owner_tag": self.settings.get("owner_tag") or DEFAULT_PAYMENT_CONFIG["owner_tag"],
            "active_premium_users": prem_users,
            "active_premium_count": len(prem_users),
            "orders": orders[:50],
            "recent_orders": orders[:50],
            "paid_orders_count": len(paid_orders),
            "total_revenue": total_revenue,
        }

    async def update_payment_settings(self, data: dict[str, Any]) -> dict[str, Any]:
        allowed = (
            "premium_only_enabled",
            "free_trial_limit",
            "upi_id",
            "upi_payee_name",
            "paytm_mid",
            "payment_api_url",
            "payment_verify_interval",
            "payment_max_minutes",
            "amount_tolerance",
            "payment_log_channel_id",
            "owner_contact_url",
            "owner_tag",
        )
        patch = {}
        for k in allowed:
            if k in data and data[k] is not None:
                if k == "premium_only_enabled":
                    patch[k] = bool(data[k])
                elif k in ("free_trial_limit", "payment_verify_interval", "payment_max_minutes", "payment_log_channel_id"):
                    try:
                        patch[k] = int(data[k])
                    except Exception:
                        pass
                elif k == "amount_tolerance":
                    try:
                        patch[k] = float(data[k])
                    except Exception:
                        pass
                else:
                    patch[k] = str(data[k]).strip()
        if "plans" in data and isinstance(data["plans"], list):
            await self.save_premium_plans(data["plans"])
        if patch:
            await self.update_settings(patch)
        return await self.get_premium_dashboard_config()



