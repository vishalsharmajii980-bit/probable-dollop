"""
Paytm Dynamic UPI QR Generator & Auto-Payment Verifier for TheDrunkBots
=======================================================================
Mirrors the exact Paytm Merchant MID, UPI QR format, auto-polling loop,
QR message auto-deletion, user plan activation notification, and
Owner + Payment Logs Channel (-1003270558605) receipt format from
CUTEHEAVEN-BOT-NEW.
"""

from __future__ import annotations

import asyncio
import html
import io
import json
import random
import string
import time
import urllib.parse
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

import aiohttp

from g2s.db import DEFAULT_PAYMENT_CONFIG, Database, format_ist_expiry

_active_verifiers: dict[str, asyncio.Task] = {}
_http_session: aiohttp.ClientSession | None = None
_http_lock = asyncio.Lock()


def esc(val: Any, fallback: str = "N/A") -> str:
    return html.escape(str(fallback if val is None or val == "" else val))


def make_order_id(user_id: int) -> str:
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"ORD-{int(user_id)}-{suffix}"


def _upi_amount(amount: float) -> str:
    value = Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return format(value, "f")


def build_upi_qr_bytes(
    *,
    upi_id: str,
    payee_name: str,
    amount: float,
    order_id: str,
    note: str = "Premium Subscription",
) -> bytes:
    """Builds a standards-compliant UPI deep-link QR PNG image."""
    import qrcode
    import qrcode.constants

    params = [
        ("pa", str(upi_id).strip()),
        ("pn", str(payee_name).strip()),
        ("am", _upi_amount(amount)),
        ("cu", "INR"),
        ("tr", str(order_id).strip()[:35]),
        ("tn", str(note).strip()[:80]),
    ]
    upi_url = "upi://pay?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(upi_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    return bio.getvalue()


async def get_http_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is not None and not _http_session.closed:
        return _http_session
    async with _http_lock:
        if _http_session is None or _http_session.closed:
            _http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"User-Agent": "TheDrunkBots-PayVerifier/2.0"},
            )
    return _http_session


async def verify_paytm_order(db: Database, order: dict) -> dict | None:
    """Queries Paytm Merchant Status API (both direct securegw.paytm.in and
    configured PAYMENT_API_URL proxy) and verifies ORDERID, STATUS, TXNAMOUNT,
    and replay protection.
    """
    if not order:
        return None
    order_id = str(order.get("_id") or order.get("order_id") or "").strip()
    if not order_id:
        return None

    expected = float(order.get("payable_amount") or order.get("amount") or 0)
    mid = str(db.settings.get("paytm_mid") or DEFAULT_PAYMENT_CONFIG["paytm_mid"]).strip()
    api_base = str(db.settings.get("payment_api_url") or DEFAULT_PAYMENT_CONFIG["payment_api_url"]).strip().rstrip("/")
    tolerance = float(db.settings.get("amount_tolerance") or DEFAULT_PAYMENT_CONFIG["amount_tolerance"])

    session = await get_http_session()
    jdata = urllib.parse.quote(json.dumps({"MID": mid, "ORDERID": order_id}))
    candidate_urls = [
        f"https://securegw.paytm.in/order/status?JsonData={jdata}",
    ]
    if api_base:
        candidate_urls.append(f"{api_base}/?mid={urllib.parse.quote(mid)}&oid={urllib.parse.quote(order_id)}")

    data = None
    for url in candidate_urls:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=12)) as resp:
                if resp.status != 200:
                    continue
                res_json = await resp.json(content_type=None)
                if isinstance(res_json, dict) and res_json.get("ORDERID"):
                    data = res_json
                    if data.get("STATUS") == "TXN_SUCCESS":
                        break
        except Exception:
            continue

    if not data or data.get("STATUS") != "TXN_SUCCESS":
        return None
    if str(data.get("ORDERID") or "") != order_id:
        return None
    try:
        paid = float(data.get("TXNAMOUNT") or 0)
        if abs(paid - expected) > tolerance:
            return None
    except (ValueError, TypeError):
        return None

    txn_id = str(data.get("TXNID") or "").strip()
    if txn_id and await db.is_txn_id_used(txn_id):
        return None

    return {
        "txn_id": txn_id or None,
        "bank_txn_id": data.get("BANKTXNID"),
        "txn_amount": paid,
        "txn_date": data.get("TXNDATE") or time.strftime("%Y-%m-%d %H:%M:%S"),
        "gateway": "paytm",
        "payer_name": None,
    }


async def send_payment_log_to_targets(bot: Any, db: Database, log_text: str):
    """Sends the payment receipt to PAYMENT_LOG_CHANNEL_ID (-1003270558605),
    OWNER_ID (8584220782), and all configured admin_ids.
    Uses automatic relay fallback for the log channel if the main bot is not yet
    a member of -1003270558605.
    """
    log_ch_id = int(db.settings.get("payment_log_channel_id") or DEFAULT_PAYMENT_CONFIG["payment_log_channel_id"])
    relay_tok = str(db.settings.get("payment_log_relay_token") or DEFAULT_PAYMENT_CONFIG["payment_log_relay_token"]).strip()
    owner_id = int(db.settings.get("owner_id") or 0)
    admin_ids = [int(x) for x in (db.settings.get("admin_ids") or []) if str(x).lstrip("-").isdigit()]

    targets = set()
    if owner_id:
        targets.add(owner_id)
    targets.update(admin_ids)

    # 1. Send to Owner & Admins via the active bot
    for tid in targets:
        try:
            await bot.send_message(tid, log_text)
        except Exception:
            pass

    # 2. Send to Payment Log Channel (-1003270558605)
    if log_ch_id:
        sent_ok = False
        try:
            res = await bot.send_message(log_ch_id, log_text)
            if res and res.get("ok"):
                sent_ok = True
        except Exception:
            pass

        if not sent_ok and relay_tok:
            try:
                session = await get_http_session()
                relay_url = f"https://api.telegram.org/bot{relay_tok}/sendMessage"
                payload = {
                    "chat_id": log_ch_id,
                    "text": log_text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                async with session.post(relay_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    await r.read()
            except Exception:
                pass


async def on_payment_success(
    bot: Any,
    db: Database,
    order: dict,
    txn_info: dict,
    chat_id: int,
    qr_message_id: int | None = None,
) -> bool:
    """Claims the pending order, activates the user's Premium plan for the exact
    plan duration, deletes the QR/payment message, notifies the user, and logs
    the sale to the Owner & Payment Logs Channel (-1003270558605).
    """
    order_id = str(order.get("_id") or order.get("order_id") or "").strip()
    user_id = int(order.get("user_id") or 0)
    days = int(order.get("days") or 30)
    amount = float(order.get("payable_amount") or order.get("amount") or 0)
    amt_disp = int(amount) if amount == int(amount) else amount
    plan_key = str(order.get("plan_key") or "plan_1m")
    plan_type = str(order.get("plan_type") or plan_key)
    plan_label = str(order.get("plan_label") or f"💎 Premium — {days} Days")

    if not await db.claim_order_processing(order_id):
        return False

    stop_auto_verifier(order_id)

    try:
        prem_res = await db.add_premium_user(
            user_id=user_id,
            time_value=days,
            plan_type=plan_type,
            plan_label=plan_label,
            source="payment",
            time_unit="d",
        )
        await db.update_order_status(
            order_id,
            "success",
            txn_id=txn_info.get("txn_id"),
            txn_info=txn_info,
        )
    except BaseException:
        await db.update_order_status(order_id, "pending")
        return False

    # 1. Delete QR & Payment Details message
    qr_mid = qr_message_id or order.get("qr_message_id")
    if qr_mid:
        try:
            await bot.delete_message(chat_id, int(qr_mid))
        except Exception:
            pass

    expiry_str = prem_res.get("expiry_str") or format_ist_expiry(prem_res.get("premium_until"))

    # 2. Send Plan Activated Automatically message to user & pin it
    user_text = (
        f"<blockquote>💎 <b>ᴘʟᴀɴ ᴀᴄᴛɪᴠᴀᴛᴇᴅ ᴀᴜᴛᴏᴍᴀᴛɪᴄᴀʟʟʏ!</b></blockquote>\n\n"
        f"<blockquote>✅ ʏᴏᴜʀ ᴘᴀʏᴍᴇɴᴛ ʜᴀs ʙᴇᴇɴ ᴠᴇʀɪꜰɪᴇᴅ ᴀɴᴅ ʏᴏᴜʀ ᴘʟᴀɴ ɪs ɴᴏᴡ ᴀᴄᴛɪᴠᴇ.</blockquote>\n"
        f"<blockquote>» ᴘʟᴀɴ: <b>{esc(plan_label)}</b></blockquote>\n"
        f"<blockquote>» ᴅᴜʀᴀᴛɪᴏɴ: <b>{days} ᴅᴀʏs</b></blockquote>\n"
        f"<blockquote>» ᴇxᴘɪʀᴇs: <code>{esc(expiry_str)}</code></blockquote>\n\n"
        f"<blockquote>ᴇɴᴊᴏʏ ᴜɴʟɪᴍɪᴛᴇᴅ ʟɪɴᴋ ʙʏᴘᴀssᴇs ᴡɪᴛʜ ᴢᴇʀᴏ ʟɪᴍɪᴛs. ᴛʜᴀɴᴋ ʏᴏᴜ ꜰᴏʀ ʏᴏᴜʀ ꜱᴜᴘᴘᴏʀᴛ! 🙏</blockquote>"
    )
    kb = {
        "inline_keyboard": [
            [
                {"text": "👑 View My Plan", "callback_data": "usr:myplan", "style": "success"},
                {"text": "🏠 Home", "callback_data": "usr:start"},
            ],
        ]
    }
    try:
        sent = await bot.send_message(chat_id, user_text, reply_markup=kb)
        if sent and sent.get("ok"):
            mid = (sent.get("result") or {}).get("message_id")
            if mid:
                await bot.api(
                    "pinChatMessage",
                    {"chat_id": chat_id, "message_id": mid, "disable_notification": False},
                )
    except Exception:
        pass

    # 3. Send New Premium Sale receipt to Owner, Admins & Payment Logs Channel (-1003270558605)
    payer = txn_info.get("payer_name")
    log_text = (
        f"<blockquote>💰 <b>ɴᴇᴡ ᴘʀᴇᴍɪᴜᴍ sᴀʟᴇ (ᴀᴜᴛᴏ-ᴠᴇʀɪꜰɪᴇᴅ)</b></blockquote>\n\n"
        f"<blockquote>👤 ᴜsᴇʀ ɪᴅ: <code>{esc(user_id)}</code></blockquote>\n"
        f"<blockquote>📦 ᴘʟᴀɴ: <b>{esc(plan_label)} ({days} ᴅᴀʏs)</b></blockquote>\n"
        f"<blockquote>💳 ᴀᴍᴏᴜɴᴛ: <b>₹{esc(amt_disp)}</b></blockquote>\n"
        f"<blockquote>🏷 ɢᴀᴛᴇᴡᴀʏ: <b>ᴘᴀʏᴛᴍ</b></blockquote>\n"
        f"<blockquote>🆔 ᴏʀᴅᴇʀ ɪᴅ: <code>{esc(order_id)}</code></blockquote>\n"
        f"<blockquote>🏦 ᴛxɴ ɪᴅ: <code>{esc(txn_info.get('txn_id'))}</code></blockquote>\n"
        f"<blockquote>🏛 ʙᴀɴᴋ / ᴜᴛʀ: <code>{esc(txn_info.get('bank_txn_id'))}</code></blockquote>\n"
        + (f"<blockquote>🙋 ᴘᴀʏᴇʀ: <code>{esc(payer)}</code></blockquote>\n" if payer else "")
        + f"<blockquote>📅 ᴛxɴ ᴅᴀᴛᴇ: <code>{esc(txn_info.get('txn_date'))}</code></blockquote>\n"
        f"<blockquote>⏳ ᴇxᴘɪʀᴇs: <code>{esc(expiry_str)}</code></blockquote>"
    )
    await send_payment_log_to_targets(bot, db, log_text)
    return True


async def _run_auto_verifier_loop(
    bot: Any,
    db: Database,
    order_id: str,
    chat_id: int,
    qr_message_id: int | None,
    expiry_ts: float,
):
    interval = max(5, int(db.settings.get("payment_verify_interval") or 12))
    minutes = max(1, int(db.settings.get("payment_max_minutes") or 15))
    max_checks = max(1, (minutes * 60) // interval + 5)

    for attempt in range(max_checks):
        await asyncio.sleep(8 if attempt == 0 else interval)

        order = await db.get_order(order_id)
        if not order or order.get("status") not in ("pending", "processing"):
            break

        if time.time() >= expiry_ts:
            if qr_message_id:
                try:
                    await bot.delete_message(chat_id, qr_message_id)
                except Exception:
                    pass

            # 2-minute grace window check for late bank settlement
            await asyncio.sleep(120)
            order = await db.get_order(order_id)
            if order and order.get("status") in ("pending", "processing"):
                result = await verify_paytm_order(db, order)
                if result:
                    await on_payment_success(bot, db, order, result, chat_id, qr_message_id=None)
                    break

                await db.update_order_status(order_id, "expired")
                contact_url = str(
                    db.settings.get("owner_contact_url")
                    or DEFAULT_PAYMENT_CONFIG["owner_contact_url"]
                ).strip()
                if not contact_url.startswith("http"):
                    contact_url = f"https://t.me/{contact_url.lstrip('@')}"
                exp_txt = (
                    f"<blockquote>⏰ <b>ᴘᴀʏᴍᴇɴᴛ sᴇssɪᴏɴ ᴇxᴘɪʀᴇᴅ</b></blockquote>\n\n"
                    f"<blockquote>ʏᴏᴜʀ ᴏʀᴅᴇʀ <code>{esc(order_id)}</code> ʜᴀs ᴇxᴘɪʀᴇᴅ.</blockquote>\n"
                    f"<blockquote>ɪꜰ ʏᴏᴜ ᴀʟʀᴇᴀᴅʏ ᴘᴀɪᴅ, ᴘʟᴇᴀsᴇ ᴄᴏɴᴛᴀᴄᴛ ᴀᴅᴍɪɴ ᴡɪᴛʜ ʏᴏᴜʀ ᴘᴀʏᴍᴇɴᴛ sᴄʀᴇᴇɴsʜᴏᴛ.</blockquote>"
                )
                exp_kb = {
                    "inline_keyboard": [
                        [{"text": "💎 Buy Premium Again", "callback_data": "usr:premium", "style": "success"}],
                        [
                            {"text": "👨‍💻 Contact Admin", "url": contact_url},
                            {"text": "🏠 Home", "callback_data": "usr:start"},
                        ],
                    ]
                }
                try:
                    await bot.send_message(chat_id, exp_txt, reply_markup=exp_kb)
                except Exception:
                    pass
            break

        result = await verify_paytm_order(db, order)
        if result:
            await on_payment_success(bot, db, order, result, chat_id, qr_message_id=qr_message_id)
            break


def start_auto_verifier(
    bot: Any,
    db: Database,
    order_id: str,
    chat_id: int,
    qr_message_id: int | None,
    expiry_ts: float,
):
    existing = _active_verifiers.get(order_id)
    if existing and not existing.done():
        return
    task = asyncio.create_task(
        _run_auto_verifier_loop(bot, db, order_id, chat_id, qr_message_id, expiry_ts)
    )
    _active_verifiers[order_id] = task
    task.add_done_callback(lambda _: _active_verifiers.pop(order_id, None))


def stop_auto_verifier(order_id: str):
    task = _active_verifiers.pop(str(order_id), None)
    if task and not task.done() and task is not asyncio.current_task():
        task.cancel()
