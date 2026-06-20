"""
plugins/ui/handlers_dm.py
──────────────────────────
Semua callback handler DM panel: navigasi, toggle, FSM triggers, dsb.

PERUBAHAN (v2 — admin_session):
  - /start & /antigcast DM handler dipindahkan ke antigcast_group.py
    (terpusat bersama rate-limiting anti-spam DM).
  - cb_manage: memanggil open_session() sebelum buka panel grup.
  - Semua callback sensitif: memanggil verify_admin_session() di awal,
    tolak dengan pesan ramah jika sesi tidak valid/kedaluwarsa.
  - Import admin_session untuk session management.
"""

import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery, Message
from pyrogram.enums import ParseMode
from pyrogram.errors import MessageNotModified, MessageIdInvalid, BadRequest
import pyrogram.raw.functions as _raw_fns
from pyrogram.raw.types import (
    MessageEntityBlockquote as _RawBQ,
    MessageEntityBold       as _RawBold,
)

from database import get_config, update_config, invalidate_count_cache, invalidate_admin_groups_cache
from plugins.ui.pages import (
    page_start, page_guide, page_manage, page_group_log,
    page_regex_tutorial, page_regex_list,
    page_whitelist_text, page_free_list,
    page_cas_panel,
    page_newscore, page_newscore_privs,
)
from plugins.ui.fsm_state import (
    pending_regex_state, pending_free_state, pending_wl_state,
    clear_all_fsm,
    start_regex_fsm, start_free_fsm, start_wl_fsm,
    spawn_regex_timeout, spawn_free_timeout, spawn_wl_timeout,
    free_fsm_timeout,
)
import admin_session as _adm_sess

WAIT_TIMEOUT = 30


# ── Helpers ───────────────────────────────────────────────────────────────────
async def safe_edit(msg, text: str, keyboard=None):
    try:
        await msg.edit(text, reply_markup=keyboard, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except (MessageNotModified, MessageIdInvalid, BadRequest):
        pass
    except Exception as e:
        print(f"[safe_edit] {e}")


async def _safe_cb(cb: CallbackQuery, coro):
    """Jalankan coroutine dalam callback dengan guard exception penuh."""
    try:
        await coro
    except Exception as e:
        print(f"[callback guard] {cb.data}: {e}")


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


async def _deny_session(cb: CallbackQuery) -> None:
    """Tampilkan pesan penolakan saat sesi admin tidak valid."""
    await safe_edit(
        cb.message,
        "<b>❖ SESI TIDAK VALID ❖</b>\n\n"
        "⛔ Akses ditolak. Kemungkinan penyebab:\n"
        "◈ Anda tidak lagi menjadi admin di grup ini.\n"
        "◈ Sesi DM sudah kedaluwarsa (maks. 1 jam).\n\n"
        "<i>Buka panel dari awal untuk memperbarui sesi.</i>",
        InlineKeyboardMarkup([[InlineKeyboardButton("🔙  Kembali", callback_data="admin_menu")]])
    )


async def edit_with_bq(client, msg, text: str, keyboard=None):
    """
    Edit pesan dengan marker kustom untuk formatting:
      [B]...[/B]   → Bold entity
      [BQ]...[/BQ] → Blockquote via raw Pyrogram API

    FIXED: Hapus collapsed=True dari _RawBQ karena parameter ini tidak didukung
    di Pyrogram 2.0.106 (MessageEntityBlockquote.__init__ unexpected keyword).
    Fallback ke safe_edit jika raw API gagal.
    """
    import re as _re
    SPLIT_RE = _re.compile(r'(\[B\]|\[/B\]|\[BQ\]|\[/BQ\])')

    entities   = []
    plain      = ""
    bold_start = None
    bq_start   = None

    for token in SPLIT_RE.split(text):
        if token == "[B]":
            bold_start = _utf16_len(plain)
        elif token == "[/B]":
            if bold_start is not None:
                length = _utf16_len(plain) - bold_start
                if length > 0:
                    entities.append(_RawBold(offset=bold_start, length=length))
                bold_start = None
        elif token == "[BQ]":
            bq_start = _utf16_len(plain)
        elif token == "[/BQ]":
            if bq_start is not None:
                length = _utf16_len(plain) - bq_start
                if length > 0:
                    entities.append(_RawBQ(offset=bq_start, length=length))
                bq_start = None
        else:
            plain += token

    try:
        peer = await client.resolve_peer(msg.chat.id)
        await client.invoke(
            _raw_fns.messages.EditMessage(
                peer=peer,
                id=msg.id,
                message=plain,
                entities=entities,
                no_webpage=True,
            )
        )
        if keyboard:
            try:
                await msg.edit_reply_markup(keyboard)
            except Exception:
                pass
    except (MessageNotModified, MessageIdInvalid):
        pass
    except Exception as e:
        print(f"[edit_with_bq] {e}")
        fallback = (
            text
            .replace("[B]", "<b>").replace("[/B]", "</b>")
            .replace("[BQ]", "<blockquote>").replace("[/BQ]", "</blockquote>")
        )
        await safe_edit(msg, fallback, keyboard)


# ─────────────────────────────────────────────────────────────────────────────
#  Callback: navigasi halaman (tidak butuh admin session — halaman publik)
# ─────────────────────────────────────────────────────────────────────────────
@Client.on_callback_query(filters.regex(r"^start$"))
async def cb_start(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    text, keyboard = await page_start(client)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^guide_(\d+)$"))
async def cb_guide(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    page_num = int(cb.data.split("_")[1])
    text, keyboard = page_guide(page_num)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^admin_menu(_refresh)?$"))
async def cb_admin_menu(client, cb: CallbackQuery):
    is_refresh = cb.data == "admin_menu_refresh"
    if is_refresh:
        invalidate_admin_groups_cache(cb.from_user.id)
        await cb.answer("🔄 Menyinkronisasi ulang daftar grup...")
    else:
        await cb.answer("⏳ Menghubungkan ke database grup...")
    clear_all_fsm(cb.from_user.id)
    from database import get_my_admin_groups
    groups = await get_my_admin_groups(client, cb.from_user.id)

    if not groups:
        await safe_edit(
            cb.message,
            "<b>❖ ＤＡＦＴＡＲ ＧＲＵＰ ❖</b>\n\n"
            "❌ <b>Akses Ditolak: Tidak ada grup terdeteksi.</b>\n\n"
            "Pastikan kondisi berikut terpenuhi:\n"
            "1. Bot sudah dimasukkan ke dalam Grup Anda.\n"
            "2. Anda adalah <b>Admin</b> di grup tersebut.\n"
            "3. Bot sudah diangkat menjadi Admin grup.\n\n"
            "<i>Selesaikan langkah di atas, lalu tekan Refresh.</i>",
            InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄  Refresh Sinkronisasi", callback_data="admin_menu_refresh")],
                [InlineKeyboardButton("🔙  Kembali", callback_data="start")],
            ])
        )
        return

    buttons = [
        [InlineKeyboardButton(f"📂 {g['title']}", callback_data=f"manage_{g['id']}")]
        for g in groups
    ]
    buttons.append([InlineKeyboardButton("🔄  Refresh Sinkronisasi", callback_data="admin_menu_refresh")])
    buttons.append([InlineKeyboardButton("🔙  Kembali ke Dasbor",    callback_data="start")])

    await safe_edit(
        cb.message,
        f"<b>❖ ＤＡＦＴＡＲ ＧＲＵＰ ❖</b>\n\n"
        f"Halo komandan <b>{cb.from_user.first_name}</b>!\n\n"
        f"Sistem mendeteksi Anda memiliki otoritas di <b>{len(groups)} grup</b>. "
        f"Pilih grup yang ingin Anda kelola keamanannya di bawah ini:",
        InlineKeyboardMarkup(buttons)
    )


@Client.on_callback_query(filters.regex(r"^manage_(-?\d+)$"))
async def cb_manage(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id

    # Buka sesi baru — verifikasi ke Telegram bahwa user masih admin
    ok = await _adm_sess.open_session(client, user_id, chat_id)
    if not ok:
        await safe_edit(
            cb.message,
            "<b>❖ AKSES DITOLAK ❖</b>\n\n"
            "⛔ Anda tidak lagi tercatat sebagai admin di grup ini.\n"
            "Minta owner grup untuk mengangkat Anda kembali terlebih dahulu.",
            InlineKeyboardMarkup([[InlineKeyboardButton("🔙  Kembali", callback_data="admin_menu")]])
        )
        return

    text, keyboard = await page_manage(chat_id)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^grp_log_(-?\d+)_(\d+)$"))
async def cb_grp_log(client, cb: CallbackQuery):
    await cb.answer()
    try:
        m       = re.match(r"^grp_log_(-?\d+)_(\d+)$", cb.data)
        chat_id = int(m.group(1))
        page    = int(m.group(2))
        user_id = cb.from_user.id
        if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
            return await _deny_session(cb)
        text, keyboard = await page_group_log(chat_id, page)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_grp_log] {e}")


@Client.on_callback_query(filters.regex(r"^cas_panel_(-?\d+)$"))
async def cb_cas_panel(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)
    text, keyboard = await page_cas_panel(chat_id)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^view_wl_(-?\d+)$"))
async def cb_view_wl(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)
    wl_text = await page_whitelist_text(chat_id)
    await safe_edit(
        cb.message, wl_text,
        InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙  Kembali ke CAS Panel", callback_data=f"cas_panel_{chat_id}")],
        ])
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Callback: toggle on/off
# ─────────────────────────────────────────────────────────────────────────────
@Client.on_callback_query(filters.regex(r"^tgl_(local|global|bio_check)_(-?\d+)$"))
async def cb_toggle(client, cb: CallbackQuery):
    await cb.answer("Memperbarui...")
    try:
        m       = re.match(r"^tgl_(local|global|bio_check)_(-?\d+)$", cb.data)
        key     = m.group(1)
        chat_id = int(m.group(2))
        user_id = cb.from_user.id
        if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
            return await _deny_session(cb)

        # ── Khusus bio_check: cek apakah bot pemantau sudah ready di grup ────
        if key == "bio_check":
            from video_call import check_monitor_is_member
            monitor_ready = await check_monitor_is_member(client, chat_id)
            if not monitor_ready:
                await cb.answer(
                    "⚠️ Bot pemantau belum dipasang di grup ini!\n"
                    "Buka Security OS → Pasang Bot Pemantau terlebih dahulu.",
                    show_alert=True,
                )
                # Arahkan ke panel Security OS
                from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
                await safe_edit(
                    cb.message,
                    "⚠️ <b>Bot Pemantau Belum Siap</b>\n\n"
                    "Fitur <b>Bio Link Detector</b> membutuhkan <b>bot pemantau</b> "
                    "yang sudah dipasang dan aktif di grup ini.\n\n"
                    "Bot pemantau bertugas memeriksa bio profil user secara independen "
                    "dari bot utama.\n\n"
                    "<b>Langkah selanjutnya:</b>\n"
                    "1️⃣ Tekan tombol di bawah untuk membuka panel <b>Security OS</b>.\n"
                    "2️⃣ Tekan <b>🤖 Pasang Bot Pemantau</b> dan ikuti tutorial.\n"
                    "3️⃣ Setelah bot pemantau terpasang, kembali ke sini dan aktifkan Bio.",
                    InlineKeyboardMarkup([
                        [InlineKeyboardButton(
                            "🔐  Buka Security OS → Pasang Bot Pemantau",
                            callback_data=f"secos_panel_{chat_id}"
                        )],
                        [InlineKeyboardButton("🔙  Kembali ke Panel", callback_data=f"manage_{chat_id}")],
                    ])
                )
                return

        cfg = await get_config(chat_id)
        await update_config(chat_id, key, not (cfg[key] is True))
        text, keyboard = await page_manage(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_toggle] {e}")


@Client.on_callback_query(filters.regex(r"^time_(inc|dec)_(-?\d+)$"))
async def cb_time(client, cb: CallbackQuery):
    await cb.answer()
    try:
        m       = re.match(r"^time_(inc|dec)_(-?\d+)$", cb.data)
        action  = m.group(1)
        chat_id = int(m.group(2))
        user_id = cb.from_user.id
        if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
            return await _deny_session(cb)
        cfg     = await get_config(chat_id)
        current = cfg["expiry"]
        new_val = min(43200, current + 600) if action == "inc" else max(600, current - 600)
        await update_config(chat_id, "expiry", new_val)
        text, keyboard = await page_manage(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_time] {e}")


@Client.on_callback_query(filters.regex(r"^noop$"))
async def cb_noop(client, cb: CallbackQuery):
    await cb.answer("ℹ️ Indikator Status Memori.", show_alert=False)


# ─────────────────────────────────────────────────────────────────────────────
#  Callback: panel regex
# ─────────────────────────────────────────────────────────────────────────────
@Client.on_callback_query(filters.regex(r"^rgxpanel_(-?\d+)$"))
async def cb_regex_panel(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)
    text, keyboard = await page_regex_tutorial(chat_id)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^rgxlist_(-?\d+)(?:_(\d+))?$"))
async def cb_regex_list(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    m       = re.match(r"^rgxlist_(-?\d+)(?:_(\d+))?$", cb.data)
    chat_id = int(m.group(1))
    page    = int(m.group(2)) if m.group(2) else 1
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)
    text, keyboard = await page_regex_list(chat_id, page)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^rgxadd_(-?\d+)$"))
async def cb_regex_add(client, cb: CallbackQuery):
    await cb.answer()
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)

    state = start_regex_fsm(user_id, chat_id, cb.message.id)
    await safe_edit(
        cb.message,
        f"<b>❖ ＭＯＤＥ ＩＮＰＵＴ ＡＫＴＩＦ ❖</b>\n"
        f"🆔 <b>Target Grup:</b> <code>{chat_id}</code>\n\n"
        f"Sistem telah siap merekam data firewall baru.\n\n"
        f"<b>Silakan ketik dan kirimkan kata/pola pemblokirannya ke chat ini sekarang.</b>\n"
        f"<i>(⏱ Anda memiliki waktu {WAIT_TIMEOUT} detik untuk mengirimkan pesan)</i>",
        InlineKeyboardMarkup([
            [InlineKeyboardButton("🚫  Batalkan Operasi", callback_data=f"rgxpanel_{chat_id}")]
        ])
    )
    spawn_regex_timeout(user_id, chat_id, cb.message)


@Client.on_callback_query(filters.regex(r"^rgxdel_(-?\d+)_([a-f0-9]{24})$"))
async def cb_regex_del(client, cb: CallbackQuery):
    await cb.answer("⏳ Menghapus...")
    try:
        m       = re.match(r"^rgxdel_(-?\d+)_([a-f0-9]{24})$", cb.data)
        chat_id = int(m.group(1))
        doc_id  = m.group(2)
        user_id = cb.from_user.id
        if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
            return await _deny_session(cb)

        from bson import ObjectId
        from database import db
        _group_regex_db = db["regex_per_group"]
        result = await _group_regex_db.delete_one({"_id": ObjectId(doc_id), "chat_id": chat_id})

        if not result.deleted_count:
            print(f"[cb_regex_del] doc {doc_id} tidak ditemukan di chat {chat_id}")

        from plugins.filters.antispam import invalidate_local_regex_cache
        invalidate_local_regex_cache(chat_id)
        invalidate_count_cache(chat_id)  # refresh count di panel

        text, keyboard = await page_regex_list(chat_id, 1)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_regex_del] {e}")
        try:
            await cb.answer("❌ Gagal menghapus filter.", show_alert=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  Callback: CAS whitelist FSM
# ─────────────────────────────────────────────────────────────────────────────
@Client.on_callback_query(filters.regex(r"^(wl|unwl)_cas_(-?\d+)$"))
async def cb_wl_request(client, cb: CallbackQuery):
    await cb.answer()
    m       = re.match(r"^(wl|unwl)_cas_(-?\d+)$", cb.data)
    action  = m.group(1)
    chat_id = int(m.group(2))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)

    label = "TAMBAH WHITELIST" if action == "wl" else "HAPUS WHITELIST"
    instruksi = (
        "Silakan kirim <b>ID User (Angka)</b> yang ingin dikecualikan dari ban otomatis CAS.\n\n"
        "◈ <b>Contoh ID:</b> <code>123456789</code>\n"
        "◈ <i>Gunakan bot @userinfobot untuk mengetahui ID seseorang.</i>"
    ) if action == "wl" else (
        "Silakan kirim <b>ID User (Angka)</b> yang ingin dicabut hak perlindungannya.\n\n"
        "◈ <b>Contoh ID:</b> <code>123456789</code>\n"
        "◈ <i>User ini akan kembali diperiksa oleh sistem keamanan CAS.</i>"
    )

    state = start_wl_fsm(user_id, action, chat_id, cb.message.id)
    await safe_edit(
        cb.message,
        f"<b>❖ {label} ❖</b>\n"
        f"🆔 <b>Target Grup:</b> <code>{chat_id}</code>\n\n"
        f"<b>▰▰▰ 📌 INSTRUKSI ▰▰▰</b>\n"
        f"{instruksi}\n\n"
        f"<i>⏱ Sesi aktif selama 30 detik. Ketik /batal untuk membatalkan.</i>",
        InlineKeyboardMarkup([
            [InlineKeyboardButton("🚫  Batalkan", callback_data=f"cas_panel_{chat_id}")]
        ])
    )
    spawn_wl_timeout(user_id, chat_id, cb.message)


# ─────────────────────────────────────────────────────────────────────────────
#  Callback: free list & free add & free del
# ─────────────────────────────────────────────────────────────────────────────
@Client.on_callback_query(filters.regex(r"^freelist_(-?\d+)$"))
async def cb_free_list(client, cb: CallbackQuery):
    await cb.answer()
    clear_all_fsm(cb.from_user.id)
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)
    text, keyboard = await page_free_list(chat_id)
    await safe_edit(cb.message, text, keyboard)


@Client.on_callback_query(filters.regex(r"^freeadd_(-?\d+)$"))
async def cb_free_add(client, cb: CallbackQuery):
    await cb.answer()
    chat_id = int(re.search(r"(-?\d+)$", cb.data).group(1))
    user_id = cb.from_user.id
    if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
        return await _deny_session(cb)

    state = start_free_fsm(user_id, chat_id, cb.message.id)
    await safe_edit(
        cb.message,
        f"<b>❖ ＴＡＭＢＡＨ ＭＥＭＢＥＲ ＶＩＰ ❖</b>\n"
        f"🆔 <b>Target Grup:</b> <code>{chat_id}</code>\n\n"
        f"Kirim <b>ID User</b> yang ingin dijadikan Member VIP (bebas dari semua filter).\n\n"
        f"<i>⏱ Sesi aktif 30 detik. Ketik /batal untuk membatalkan.</i>",
        InlineKeyboardMarkup([
            [InlineKeyboardButton("🚫  Batalkan", callback_data=f"freelist_{chat_id}")]
        ])
    )
    spawn_free_timeout(user_id, chat_id, cb.message)


@Client.on_callback_query(filters.regex(r"^freedel_(-?\d+)_(\d+)$"))
async def cb_free_del(client, cb: CallbackQuery):
    await cb.answer("⏳ Menghapus...")
    try:
        m       = re.match(r"^freedel_(-?\d+)_(\d+)$", cb.data)
        chat_id = int(m.group(1))
        target_user_id = int(m.group(2))
        user_id = cb.from_user.id
        if not await _adm_sess.verify_admin_session(client, user_id, chat_id):
            return await _deny_session(cb)

        from database import db
        _free_col = db["free_per_group"]
        await _free_col.delete_one({"chat_id": chat_id, "user_id": target_user_id})

        # Invalidasi cache VIP agar perubahan langsung berlaku.
        try:
            from video_call import invalidate_vip_cache
            invalidate_vip_cache(chat_id, target_user_id)
        except ImportError:
            pass
        invalidate_count_cache(chat_id)  # refresh count di panel

        text, keyboard = await page_free_list(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_free_del] {e}")
        try:
            await cb.answer("❌ Gagal menghapus user VIP.", show_alert=True)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# NEWSCORE CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

# ── FSM state untuk input teks NewsCore ──────────────────────────────────────
_ns_fsm: dict = {}  # user_id → {"chat_id": int, "action": str, "step": int, "val1": int}


@Client.on_callback_query(filters.regex(r"^ns_panel_(-?\d+)$"))
async def cb_ns_panel(client, cb: CallbackQuery):
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_panel_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        text, keyboard = await page_newscore(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_ns_panel] {e}")


@Client.on_callback_query(filters.regex(r"^ns_toggle_(-?\d+)$"))
async def cb_ns_toggle(client, cb: CallbackQuery):
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_toggle_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)

        from database import ns_get_config, ns_update, ns_calc_next_reset
        cfg     = await ns_get_config(chat_id)
        new_val = not cfg.get("enabled", False)
        updates = {"enabled": new_val}
        if new_val and not cfg.get("next_reset"):
            updates["next_reset"] = ns_calc_next_reset(cfg)
        await ns_update(chat_id, updates)
        await cb.answer("✅ NewsCore " + ("diaktifkan!" if new_val else "dimatikan!"), show_alert=False)
        text, keyboard = await page_newscore(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_ns_toggle] {e}")


@Client.on_callback_query(filters.regex(r"^ns_mode_(-?\d+)$"))
async def cb_ns_mode(client, cb: CallbackQuery):
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_mode_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("📆 Per N Hari",         callback_data=f"ns_setmode_day_{chat_id}")],
            [InlineKeyboardButton("📅 Per Tanggal Bulanan", callback_data=f"ns_setmode_date_{chat_id}")],
            [InlineKeyboardButton("📆 Per Hari Minggu",    callback_data=f"ns_setmode_weekday_{chat_id}")],
            [InlineKeyboardButton("🔙  Kembali",           callback_data=f"ns_panel_{chat_id}")],
        ])
        await safe_edit(cb.message, "⚙️ <b>Pilih Mode Penjadwalan Reset NewsCore:</b>", keyboard)
    except Exception as e:
        print(f"[cb_ns_mode] {e}")


@Client.on_callback_query(filters.regex(r"^ns_setmode_(day|date|weekday)_(-?\d+)$"))
async def cb_ns_setmode(client, cb: CallbackQuery):
    await cb.answer()
    try:
        m       = re.match(r"^ns_setmode_(day|date|weekday)_(-?\d+)$", cb.data)
        mode    = m.group(1)
        chat_id = int(m.group(2))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)

        from database import ns_update
        await ns_update(chat_id, {"mode": mode})

        uid = cb.from_user.id

        if mode == "weekday":
            from database import HARI_MAP_NS
            btns = [
                [InlineKeyboardButton(nama, callback_data=f"ns_setwday_{idx}_{chat_id}")]
                for idx, nama in HARI_MAP_NS.items()
            ]
            btns.append([InlineKeyboardButton("🔙  Kembali", callback_data=f"ns_mode_{chat_id}")])
            await safe_edit(cb.message, "📆 <b>Pilih hari reset tiap minggu:</b>", InlineKeyboardMarkup(btns))

        elif mode == "day":
            await safe_edit(
                cb.message,
                "📆 <b>LANGKAH 1/2 — Jumlah Hari</b>\n\n"
                "Ketik berapa hari sekali reset dilakukan.\n"
                "Contoh: <code>7</code>  (reset setiap 7 hari)\n\n"
                "<i>Angka bebas, minimal 1.</i>",
                InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Batal", callback_data=f"ns_panel_{chat_id}")]]),
            )
            _ns_fsm[uid] = {"chat_id": chat_id, "action": "ns_step1_day", "step": 1, "msg_id": cb.message.id}

        else:  # date
            await safe_edit(
                cb.message,
                "📅 <b>LANGKAH 1/2 — Tanggal Reset</b>\n\n"
                "Ketik tanggal reset setiap bulan.\n"
                "Contoh: <code>1</code>  (reset setiap tgl 1)\n\n"
                "<i>Harus angka 1 — 30.</i>",
                InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Batal", callback_data=f"ns_panel_{chat_id}")]]),
            )
            _ns_fsm[uid] = {"chat_id": chat_id, "action": "ns_step1_date", "step": 1, "msg_id": cb.message.id}
    except Exception as e:
        print(f"[cb_ns_setmode] {e}")


@Client.on_callback_query(filters.regex(r"^ns_setwday_(\d+)_(-?\d+)$"))
async def cb_ns_setwday(client, cb: CallbackQuery):
    await cb.answer()
    try:
        m       = re.match(r"^ns_setwday_(\d+)_(-?\d+)$", cb.data)
        wday    = int(m.group(1))
        chat_id = int(m.group(2))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)

        from database import ns_update, HARI_MAP_NS
        await ns_update(chat_id, {"reset_weekday": wday})

        nama = HARI_MAP_NS.get(wday, str(wday))
        await safe_edit(
            cb.message,
            f"⏰ <b>LANGKAH 1/1 — Jam Reset  (setiap {nama})</b>\n\n"
            "Ketik jam dan menit dalam format <code>HH:MM</code>.\n"
            "Contoh: <code>23:59</code>",
            InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Batal", callback_data=f"ns_panel_{chat_id}")]]),
        )
        _ns_fsm[cb.from_user.id] = {"chat_id": chat_id, "action": "ns_input_time", "step": 2, "msg_id": cb.message.id}
    except Exception as e:
        print(f"[cb_ns_setwday] {e}")


@Client.on_callback_query(filters.regex(r"^ns_maxadmin_(-?\d+)$"))
async def cb_ns_maxadmin(client, cb: CallbackQuery):
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_maxadmin_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        btns = [
            [InlineKeyboardButton(f"{i} Admin", callback_data=f"ns_setmax_{i}_{chat_id}")]
            for i in [1, 2, 3]
        ]
        btns.append([InlineKeyboardButton("🔙  Kembali", callback_data=f"ns_panel_{chat_id}")])
        await safe_edit(cb.message, "👑 <b>Jumlah admin diangkat per periode:</b>", InlineKeyboardMarkup(btns))
    except Exception as e:
        print(f"[cb_ns_maxadmin] {e}")


@Client.on_callback_query(filters.regex(r"^ns_setmax_(\d+)_(-?\d+)$"))
async def cb_ns_setmax(client, cb: CallbackQuery):
    await cb.answer()
    try:
        m       = re.match(r"^ns_setmax_(\d+)_(-?\d+)$", cb.data)
        n       = int(m.group(1))
        chat_id = int(m.group(2))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        from database import ns_update
        await ns_update(chat_id, {"max_admins": n})
        await cb.answer(f"✅ Kuota admin diset ke {n}", show_alert=False)
        text, keyboard = await page_newscore(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_ns_setmax] {e}")


@Client.on_callback_query(filters.regex(r"^ns_time_(-?\d+)$"))
async def cb_ns_time(client, cb: CallbackQuery):
    """Ubah jam reset saja (tanpa ubah mode/nilai)."""
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_time_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        await safe_edit(
            cb.message,
            "⏰ <b>Ketik jam reset NewsCore:</b>\n\n"
            "Format: <code>HH:MM</code>\n"
            "Contoh: <code>23:59</code>",
            InlineKeyboardMarkup([[InlineKeyboardButton("🚫 Batal", callback_data=f"ns_panel_{chat_id}")]]),
        )
        _ns_fsm[cb.from_user.id] = {"chat_id": chat_id, "action": "ns_input_time", "step": 2, "msg_id": cb.message.id}
    except Exception as e:
        print(f"[cb_ns_time] {e}")


@Client.on_callback_query(filters.regex(r"^ns_privs_(-?\d+)$"))
async def cb_ns_privs(client, cb: CallbackQuery):
    await cb.answer()
    try:
        chat_id = int(re.match(r"^ns_privs_(-?\d+)$", cb.data).group(1))
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)
        text, keyboard = await page_newscore_privs(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_ns_privs] {e}")


@Client.on_callback_query(filters.regex(r"^ns_priv_"))
async def cb_ns_priv_toggle(client, cb: CallbackQuery):
    await cb.answer()
    try:
        raw     = cb.data[len("ns_priv_"):]
        parts   = raw.rsplit("_", 1)
        chat_id = int(parts[-1]) if parts[-1].lstrip("-").isdigit() else None
        priv_key = parts[0]
        if not chat_id:
            return
        if not await _adm_sess.verify_admin_session(client, cb.from_user.id, chat_id):
            return await _deny_session(cb)

        from database import ns_get_config, ns_update
        cfg   = await ns_get_config(chat_id)
        privs = dict(cfg.get("privileges", {}))
        privs[priv_key] = not privs.get(priv_key, True)
        await ns_update(chat_id, {"privileges": privs})
        text, keyboard = await page_newscore_privs(chat_id)
        await safe_edit(cb.message, text, keyboard)
    except Exception as e:
        print(f"[cb_ns_priv_toggle] {e}")
