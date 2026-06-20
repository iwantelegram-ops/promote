"""
plugins/commands/newscore.py
────────────────────────────
Sistem Skor Keaktifan & Admin Otomatis (NewsCore).

Fitur:
  • Track setiap pesan member (non-admin) → tambah skor di MongoDB
  • Background worker → cek waktu reset, angkat admin otomatis
  • /ns_score  — lihat leaderboard grup (admin only)
  • /ns_reset  — paksa reset sekarang (owner only, dev/test)
"""

import asyncio
from datetime import datetime

from pyrogram import Client, filters
from pyrogram.types import Message, ChatPrivileges
from pyrogram.enums import ParseMode
from pyrogram.errors import FloodWait

from database import (
    ns_get_config, ns_update, ns_calc_next_reset,
    ns_track_message, ns_get_leaderboard, ns_reset_scores,
    ns_get_current_admins, ns_set_current_admins,
    HARI_MAP_NS, is_admin, TZ_WIB,
)

import os
_OWNER_ID = int(os.environ.get("OWNER_ID", 0))


# ─────────────────────────────────────────────────────────────────────────────
#  TRACK PESAN MEMBER (non-admin only)
# ─────────────────────────────────────────────────────────────────────────────

@Client.on_message(filters.group & ~filters.service & ~filters.bot, group=15)
async def ns_track(client, message: Message):
    """
    Hitung skor hanya jika:
    - Pengirim bukan bot
    - Pengirim bukan admin/owner grup, KECUALI admin yang diangkat oleh
      bot ini melalui NewsCore periode sebelumnya (NS admin aktif)
    - Pesan bukan command
    - Pesan TIDAK dihapus oleh worker spam (antispam/bio/cas)
    """
    try:
        if not message.from_user or message.from_user.is_bot:
            return
        if message.text and message.text.startswith("/"):
            return

        chat_id = message.chat.id
        user_id = message.from_user.id

        cfg = await ns_get_config(chat_id)
        if not cfg.get("enabled"):
            return

        # Cek apakah user adalah admin di grup
        if await is_admin(client, chat_id, user_id):
            # Izinkan hanya jika dia adalah NS admin (diangkat bot via NewsCore)
            # Admin lain (manual/owner) tetap di-skip
            ns_admins = await ns_get_current_admins(chat_id)
            ns_admin_ids = {a["user_id"] for a in ns_admins}
            if user_id not in ns_admin_ids:
                return

        # Beri jeda kecil agar antispam/bio/cas sempat mark_message_handled
        await asyncio.sleep(0.35)

        # Jika sudah di-mark oleh worker penghapus → skip, tidak dihitung
        from database import is_message_handled
        if is_message_handled(chat_id, message.id):
            return

        await ns_track_message(
            chat_id=chat_id,
            user_id=user_id,
            user_name=message.from_user.first_name or "User",
        )
    except Exception as e:
        print(f"[NewsCore] track handler error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  LEADERBOARD COMMAND  /ns_score
# ─────────────────────────────────────────────────────────────────────────────

@Client.on_message(filters.command("ns_score") & filters.group, group=20)
async def cmd_ns_score(client, message: Message):
    try:
        chat_id = message.chat.id
        uid     = message.from_user.id if message.from_user else 0
        if not await is_admin(client, chat_id, uid):
            return

        cfg = await ns_get_config(chat_id)
        if not cfg.get("enabled"):
            rep = await message.reply_text(
                "⚠️ <b>NewsCore</b> belum diaktifkan di grup ini.\n"
                "Aktifkan via <b>⚙️ Kelola Grup → 🏆 NewsCore</b>.",
                parse_mode=ParseMode.HTML,
            )
            asyncio.create_task(_auto_del([message, rep], 10))
            return

        top = await ns_get_leaderboard(chat_id, 10)
        if not top:
            rep = await message.reply_text(
                "📭 Belum ada data keaktifan periode ini.",
                parse_mode=ParseMode.HTML,
            )
            asyncio.create_task(_auto_del([message, rep], 10))
            return

        lines = "".join(
            f"{i}. <b>{m['user_name']}</b> — <code>{m['score']}</code> poin\n"
            for i, m in enumerate(top, 1)
        )

        next_r = cfg.get("next_reset")
        next_str = ""
        if next_r:
            try:
                next_str = f"\n📅 Reset berikutnya: <code>{datetime.fromisoformat(next_r).strftime('%d %b %Y %H:%M')}</code> WIB"
            except Exception:
                pass

        rep = await message.reply_text(
            f"🏆 <b>PAPAN SKOR KEAKTIFAN</b>\n"
            f"<code>Grup: {chat_id}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"{lines}"
            f"{next_str}",
            parse_mode=ParseMode.HTML,
        )
        asyncio.create_task(_auto_del([message, rep], 30))
    except Exception as e:
        print(f"[NewsCore] /ns_score error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  FORCE RESET COMMAND  /ns_reset  (owner only)
# ─────────────────────────────────────────────────────────────────────────────

@Client.on_message(filters.command("ns_reset") & filters.group, group=20)
async def cmd_ns_reset(client, message: Message):
    try:
        uid = message.from_user.id if message.from_user else 0
        if uid != _OWNER_ID:
            return
        await message.reply_text("⏳ Memulai simulasi reset NewsCore…")
        await ns_do_reset(client, message.chat.id)
    except Exception as e:
        print(f"[NewsCore] /ns_reset error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CORE RESET JOB
# ─────────────────────────────────────────────────────────────────────────────

async def ns_do_reset(client, chat_id: int):
    """Angkat admin berdasarkan skor tertinggi, lalu reset semua skor."""
    try:
        # Ambil config terbaru dari DB (bukan cache lama)
        cfg        = await ns_get_config(chat_id)
        max_admins = cfg.get("max_admins", 1)
        p          = cfg.get("privileges", {})

        top = await ns_get_leaderboard(chat_id, max_admins)

        # Copot admin lama yang tidak masuk top baru
        old_admins = await ns_get_current_admins(chat_id)
        new_ids    = {m["user_id"] for m in top}
        for old in old_admins:
            if old["user_id"] not in new_ids:
                try:
                    await client.promote_chat_member(
                        chat_id=chat_id, user_id=old["user_id"],
                        privileges=ChatPrivileges(can_manage_chat=False),
                    )
                except Exception:
                    pass

        ann = "📢 <b>PERGANTIAN ADMIN NEWSCORE PERIODE BARU!</b> 📢\n\n"
        new_admin_docs = []

        if top:
            ann += f"🏆 <b>Top {len(top)} member teraktif:</b>\n\n"
            for idx, w in enumerate(top, 1):
                uid   = w["user_id"]
                uname = w["user_name"]
                # Retry sekali jika kena FloodWait, agar promosi benar-benar
                # tereksekusi alih-alih di-skip diam-diam setelah sleep.
                for _attempt in range(2):
                    try:
                        await client.promote_chat_member(
                            chat_id=chat_id, user_id=uid,
                            privileges=ChatPrivileges(
                                can_manage_chat=True,
                                can_delete_messages=p.get("can_delete_messages", True),
                                can_restrict_members=p.get("can_restrict_members", True),
                                can_invite_users=p.get("can_invite_users", True),
                                can_pin_messages=p.get("can_pin_messages", True),
                                can_manage_video_chats=p.get("can_manage_video_chats", False),
                            ),
                        )
                        try:
                            await client.set_chat_administrator_custom_title(
                                chat_id, uid, f"Top Member {idx} 👑"
                            )
                        except Exception:
                            pass
                        new_admin_docs.append({"chat_id": chat_id, "user_id": uid, "user_name": uname})
                        ann += f"{idx}. <a href='tg://user?id={uid}'>{uname}</a> — <code>{w['score']}</code> poin\n"
                        break
                    except FloodWait as fw:
                        await asyncio.sleep(fw.value)
                        continue
                    except Exception as e:
                        print(f"[NewsCore] promote error uid={uid}: {e}")
                        ann += f"{idx}. <b>{uname}</b> (⚠️ gagal dipromosikan)\n"
                        break
                else:
                    # Kedua percobaan kena FloodWait — laporkan sebagai gagal
                    # agar tidak hilang diam-diam dari pengumuman.
                    print(f"[NewsCore] promote uid={uid} gagal setelah retry FloodWait")
                    ann += f"{idx}. <b>{uname}</b> (⚠️ gagal dipromosikan — FloodWait)\n"
        else:
            ann += "Tidak ada aktivitas periode ini. Posisi admin tetap. 🏝️"

        await ns_set_current_admins(chat_id, new_admin_docs)

        # Hitung next_reset dari config terbaru (bukan cfg lama)
        cfg_fresh = await ns_get_config(chat_id)
        new_next  = ns_calc_next_reset(cfg_fresh)
        await ns_update(chat_id, {"next_reset": new_next})

        ann += (
            f"\n\n🔄 <i>Poin direset ke 0!</i>\n"
            f"📅 Reset berikutnya: <code>{datetime.fromisoformat(new_next).strftime('%d %b %Y %H:%M')}</code> WIB"
        )

        try:
            await client.send_message(chat_id=chat_id, text=ann, parse_mode=ParseMode.HTML)
        except Exception as e:
            print(f"[NewsCore] send announcement error: {e}")

        # Reset skor SETELAH pengumuman dikirim
        await ns_reset_scores(chat_id)

    except Exception as e:
        print(f"[NewsCore] ns_do_reset error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  BACKGROUND TIME-CHECKER LOOP
# ─────────────────────────────────────────────────────────────────────────────

_checker_running = False


async def newscore_checker_loop(client):
    global _checker_running
    if _checker_running:
        return
    _checker_running = True
    print("[NewsCore] Time-checker loop started.")
    while True:
        try:
            from database import newscore_cfg_db
            all_cfgs = await newscore_cfg_db.find({"enabled": True}).to_list(length=200)
            # now WIB-aware, agar konsisten dengan next_reset yang dihitung
            # via ns_calc_next_reset() (juga pakai TZ_WIB) — jika tidak,
            # jam reset bisa meleset sebanyak selisih timezone server vs WIB.
            now = datetime.now(TZ_WIB)
            for cfg in all_cfgs:
                cid      = cfg.get("chat_id")
                next_str = cfg.get("next_reset")
                if cid and next_str:
                    try:
                        target = datetime.fromisoformat(next_str)
                        if target.tzinfo is None:
                            # Data lama yang masih naive (tersimpan sebelum
                            # next_reset memakai TZ_WIB) — anggap sebagai WIB
                            # agar tetap bisa dibandingkan tanpa TypeError.
                            target = target.replace(tzinfo=TZ_WIB)
                        if now >= target:
                            print(f"[NewsCore] Waktunya reset untuk grup {cid}")
                            await ns_do_reset(client, cid)
                    except Exception as e:
                        print(f"[NewsCore] checker reset error cid={cid}: {e}")
        except Exception as e:
            print(f"[NewsCore] checker error: {e}")
        await asyncio.sleep(30)


# ─────────────────────────────────────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────────────────────────────────────

async def _auto_del(msgs: list, delay: int):
    await asyncio.sleep(delay)
    for m in msgs:
        try:
            await m.delete()
        except Exception:
            pass

