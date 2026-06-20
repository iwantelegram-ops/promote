"""
video_call.py — Userbot Security OS
════════════════════════════════════════════════════════════════════════════════
Modul userbot Pyrogram yang berjalan berdampingan dengan bot biasa (antigcast.py).

ARSITEKTUR (Database-driven — tidak ada komunikasi di grup):
  ┌─────────────────────────────────────────────────────────────┐
  │  Bot Pemantau (monitor_bot_reference.py)                    │
  │  Scan semua member → simpan bio_profiles ke DB bersama      │
  └────────────────────────┬────────────────────────────────────┘
                           │ DB bersama (MONGO_URL / SQLite sama)
           ┌───────────────┴───────────────────────┐
           ▼                                       ▼
  ┌────────────────┐                    ┌──────────────────────┐
  │   Bot Utama    │  query bio_profiles│      Userbot (ini)   │
  │  (pesan grup)  │  → hapus jika link │  (obrolan suara/VC)  │
  └────────────────┘                    └──────────────────────┘
                                               │ kick dari VC
                                               ↓ (jika has_link)

ATURAN UTAMA:
  - Userbot TIDAK mengirim /checkbio ke grup — query DB langsung.
  - Bot pemantau mengisi bio_profiles secara berkala & saat user join.
  - Userbot hanya memantau obrolan SUARA — pesan/typing ditangani bot biasa.
  - Semua data disimpan ke DB (MongoDB/SQLite) via db[] seperti bot asli.
  - Logika penyimpanan asli tidak diubah sama sekali.

ARSITEKTUR VC (Scheduled Join — bukan keepalive):
  - Security OS aktif → userbot join VC tiap 30 menit (bukan stay permanen).
  - Saat join: scan semua peserta VC sekarang + peserta baru (UpdateGroupCallParticipants).
  - Bot pemantau cek profil tiap user (cache 1 menit) → mute jika link, unmute jika bersih.
  - Telegram kick userbot setelah ~30 detik — tidak masalah, tugas sudah selesai.
  - Tidak ada keepalive, tidak ada rejoin loop — sudah terjadwal.

FLOW STARTUP:
  1. antigcast.py start → bot biasa aktif
  2. start_userbot(app) dipanggil → cek session userbot
  3a. Session ada → userbot langsung aktif
  3b. Session tidak ada → bot masuk mode tunggu (log di console),
      owner kirim /otp <kode> ke bot via DM → userbot login → session disimpan

VARIABEL .env BARU:
  USERBOT_PHONE — nomor HP akun userbot (format: +62xxx)
                  Jika kosong → Security OS tidak tersedia, bot berjalan normal.
"""

from __future__ import annotations

import sys as _sys_path_fix
from pathlib import Path as _Path_fix
_BOT_DIR_VC = str(_Path_fix(__file__).resolve().parent)
if _BOT_DIR_VC not in _sys_path_fix.path:
    _sys_path_fix.path.insert(0, _BOT_DIR_VC)

import os
import asyncio
import time
import re as _re
from pathlib import Path as _Path
from datetime import datetime as _dt_vc, timezone as _tz_vc, timedelta as _td_vc

_WIB_VC = _tz_vc(_td_vc(hours=7))

from pyrogram import Client as _Client, filters as _filters
from pyrogram.enums import ParseMode
from pyrogram.types import Message as _Message, ChatMemberUpdated as _ChatMemberUpdated
from pyrogram.errors import (
    FloodWait,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    SessionPasswordNeeded,
    PhoneNumberInvalid,
    PeerIdInvalid,
)
from dotenv import load_dotenv

load_dotenv(dotenv_path=_Path(__file__).parent / ".env", override=False)

# ── Env ───────────────────────────────────────────────────────────────────────
API_ID        = int(os.environ.get("API_ID", 0))
API_HASH      = os.environ.get("API_HASH", "")
OWNER_ID      = int(os.environ.get("OWNER_ID", 0))
USERBOT_PHONE = os.environ.get("USERBOT_PHONE", "").strip()
LOG_OS        = int(os.environ.get("LOG_OS", 0))

_BOT_DIR    = _Path(__file__).resolve().parent
_UB_SESSION = str(_BOT_DIR / "userbot_security_os")

# ── State global ──────────────────────────────────────────────────────────────
userbot: _Client | None = None   # instance userbot Pyrogram
_bot_ref: _Client | None = None  # referensi bot biasa (untuk kirim peringatan)
_ub_ready: bool = False
_ub_self_id: int = 0             # user_id akun userbot agar tidak kick diri sendiri

# ── OTP flow state ────────────────────────────────────────────────────────────
_otp_event: asyncio.Event | None = None
_otp_value: str = ""

# ── Rate limit per grup — minimum jeda antar pengecekan ──────────────────────
_last_vc_check: dict[int, float] = {}
_VC_CHECK_INTERVAL = 15.0   # detik minimum antar scan VC per grup

# ── Pelacak user yang sedang diproses (hindari double-kick) ──────────────────
_processing_kick: set[tuple[int, int]] = set()   # {(chat_id, user_id)} — cegah double-proses

# ── Cache status member grup (TTL 2 menit) ────────────────────────────────────
_member_cache: dict[tuple[int, int], tuple[bool, float]] = {}
_MEMBER_CACHE_TTL = 120.0   # detik

# ── Cache status VIP per user per grup (TTL 3 menit) ─────────────────────────
# VIP = ada di free_per_group collection → bebas dari SEMUA tindakan Security OS.
_vip_cache: dict[tuple[int, int], tuple[bool, float]] = {}
_VIP_CACHE_TTL = 180.0   # detik

# ── Alasan warning tertunda (dihapus setelah _do_send_warning memakai) ────────
_pending_warn_reason: dict[tuple[int, int], str] = {}

# ── Global lock inspeksi dadakan via /unmutemic (hindari concurrent floodwait) ─
_vc_inspection_lock: asyncio.Lock | None = None

# ══════════════════════════════════════════════════════════════════════════════
# VC JOIN/LEAVE WORKER — Antrean global join/leave obrolan suara
# ══════════════════════════════════════════════════════════════════════════════
#
# MASALAH YANG DISELESAIKAN:
#   Tanpa worker ini, setiap panggilan _vc_scan_and_enforce dan
#   _join_vc_for_group dari banyak grup berjalan paralel serentak.
#   Telegram API tidak toleran terhadap banyak join/leave VC bersamaan
#   dari satu akun userbot — bisa menyebabkan FloodWait, PEER_FLOOD,
#   atau bahkan suspensi sementara akun userbot.
#
# SOLUSI:
#   Semua permintaan join VC (dari scheduler 30 menit, dari enable Security OS,
#   dari follow-up recheck) dimasukkan ke _vc_join_queue.
#   Worker tunggal _vc_join_queue_worker mengeksekusi satu per satu
#   dengan jeda _VC_WORKER_JOIN_DELAY detik antar join ke VC berbeda.
#
# ITEM QUEUE FORMAT:
#   ("scan",    chat_id: int)          → jalankan _vc_scan_and_enforce
#   ("leave",   chat_id: int)          → jalankan _leave_vc_for_group_direct
#   ("join_now", chat_id: int)         → jalankan _join_vc_for_group_direct (darurat/enable)
#
# DEDUPLICATION:
#   _vc_join_pending menyimpan set chat_id yang sudah antri. Jika chat_id
#   sudah di-queue dan belum dikerjakan, permintaan baru TIDAK ditambah
#   kecuali tipenya "leave" atau "join_now" (prioritas lebih tinggi).
# ══════════════════════════════════════════════════════════════════════════════

# Antrean global join/leave VC — tuple (action, chat_id)
_vc_join_queue: asyncio.Queue | None = None

# Set chat_id yang sedang antri "scan" — cegah duplikat scan
_vc_join_pending: set[int] = set()

# Task worker join/leave VC
_vc_join_worker_task: asyncio.Task | None = None

# Jeda antar join VC ke grup berbeda (detik) — aman dari FloodWait
_VC_WORKER_JOIN_DELAY = 8.0   # 8 detik jeda antar join ke grup berbeda

# Jeda antar leave VC ke grup berbeda (detik)
_VC_WORKER_LEAVE_DELAY = 3.0


def _get_vc_join_queue() -> asyncio.Queue:
    """Lazy-init antrean join VC dalam event loop aktif."""
    global _vc_join_queue
    if _vc_join_queue is None:
        _vc_join_queue = asyncio.Queue()
    return _vc_join_queue


def _enqueue_vc_scan(chat_id: int) -> None:
    """
    Masukkan permintaan scan VC grup ke antrean global.
    Jika chat_id sudah antri (tipe scan), request baru diabaikan (deduplicated).
    Spawn worker jika belum ada.
    """
    global _vc_join_worker_task
    q = _get_vc_join_queue()
    if chat_id in _vc_join_pending:
        # Sudah antri — tidak perlu double-queue
        print(f"[VC-Worker] Grup {chat_id} sudah antri scan — skip duplikat.")
        return
    _vc_join_pending.add(chat_id)
    q.put_nowait(("scan", chat_id))
    # Spawn worker jika belum ada atau sudah selesai
    if _vc_join_worker_task is None or _vc_join_worker_task.done():
        _vc_join_worker_task = _safe_task(_vc_join_queue_worker(), tag="vc-join-worker")
        print("[VC-Worker] Worker join VC di-spawn.")


def _enqueue_vc_join_now(chat_id: int) -> None:
    """
    Masukkan permintaan join segera (saat enable Security OS).
    Tipe 'join_now' selalu masuk antrean (tidak deduplicated) — prioritas enable.
    """
    global _vc_join_worker_task
    q = _get_vc_join_queue()
    q.put_nowait(("join_now", chat_id))
    if _vc_join_worker_task is None or _vc_join_worker_task.done():
        _vc_join_worker_task = _safe_task(_vc_join_queue_worker(), tag="vc-join-worker")
        print("[VC-Worker] Worker join VC di-spawn (join_now).")


def _enqueue_vc_leave(chat_id: int) -> None:
    """
    Masukkan permintaan leave VC grup ke antrean global.
    Tipe 'leave' selalu masuk (tidak cek deduplicated) — harus dieksekusi.
    """
    global _vc_join_worker_task
    q = _get_vc_join_queue()
    # Hapus dari pending scan jika ada — leave lebih prioritas
    _vc_join_pending.discard(chat_id)
    q.put_nowait(("leave", chat_id))
    if _vc_join_worker_task is None or _vc_join_worker_task.done():
        _vc_join_worker_task = _safe_task(_vc_join_queue_worker(), tag="vc-join-worker")
        print("[VC-Worker] Worker join VC di-spawn (leave).")


async def _vc_join_queue_worker() -> None:
    """
    Worker tunggal antrean join/leave VC.

    Mengeksekusi satu permintaan pada satu waktu — tidak pernah dua grup
    join/leave VC bersamaan. Jeda _VC_WORKER_JOIN_DELAY detik setelah
    setiap join, _VC_WORKER_LEAVE_DELAY setelah setiap leave.

    Loop berhenti saat antrean kosong — akan di-spawn ulang saat ada item baru.
    """
    q = _get_vc_join_queue()
    print("[VC-Worker] Worker join VC mulai berjalan.")
    while True:
        try:
            action, chat_id = q.get_nowait()
        except asyncio.QueueEmpty:
            break

        try:
            if action == "scan":
                print(f"[VC-Worker] Eksekusi scan VC grup {chat_id}...")
                await _vc_scan_and_enforce(chat_id)
                _vc_join_pending.discard(chat_id)
                if not q.empty():
                    await asyncio.sleep(_VC_WORKER_JOIN_DELAY)

            elif action == "join_now":
                print(f"[VC-Worker] Eksekusi join_now VC grup {chat_id}...")
                await _join_vc_for_group_direct(chat_id)
                if not q.empty():
                    await asyncio.sleep(_VC_WORKER_JOIN_DELAY)

            elif action == "leave":
                print(f"[VC-Worker] Eksekusi leave VC grup {chat_id}...")
                await _leave_vc_for_group_direct(chat_id)
                if not q.empty():
                    await asyncio.sleep(_VC_WORKER_LEAVE_DELAY)

        except FloodWait as fw:
            wait_sec = fw.value + 2
            print(f"[VC-Worker] FloodWait {fw.value}s saat action={action} grup={chat_id} — menunggu {wait_sec}s...")
            _vc_join_pending.discard(chat_id)
            await asyncio.sleep(wait_sec)
        except Exception as e:
            print(f"[VC-Worker] Error saat proses action={action} grup={chat_id}: {e}")
            _vc_join_pending.discard(chat_id)

        q.task_done()

    print("[VC-Worker] Worker join VC selesai (antrean kosong).")


# ══════════════════════════════════════════════════════════════════════════════
# MIC ACTION WORKER — Antrean mute/unmute mic per grup
# ══════════════════════════════════════════════════════════════════════════════
#
# MASALAH YANG DISELESAIKAN:
#   _kick_from_voice dan _unmute_user_in_vc bisa terpanggil bersamaan
#   untuk banyak user di grup yang sama dalam satu siklus scan.
#   Eksekusi bersamaan membebani API dan menyebabkan FloodWait.
#   Juga: tindakan mic untuk grup yang berbeda bisa berjalan paralel
#   tanpa batas, memperparah kondisi flood.
#
# SOLUSI:
#   Setiap tindakan mute/unmute mic dimasukkan ke _mic_queues[chat_id].
#   Satu worker per grup mengeksekusi tindakan mic satu per satu
#   dengan jeda _MIC_WORKER_DELAY detik antar tindakan.
#
# ITEM QUEUE FORMAT:
#   ("mute",   user_id: int, call_input, reason: str)
#   ("unmute", user_id: int, call_input, reason: str)
# ══════════════════════════════════════════════════════════════════════════════

# Antrean mic per grup — {chat_id: asyncio.Queue}
_mic_queues: dict[int, asyncio.Queue] = {}

# Task worker mic per grup — {chat_id: asyncio.Task}
_mic_workers: dict[int, asyncio.Task] = {}

# Set (chat_id, user_id) yang sudah antri mic action — cegah duplikat per user per grup
_mic_pending: set[tuple[int, int]] = set()

# Jeda antar tindakan mic dalam satu grup (detik)
_MIC_WORKER_DELAY = 2.0


def _get_mic_queue(chat_id: int) -> asyncio.Queue:
    """Dapatkan / buat antrean mic untuk grup ini."""
    if chat_id not in _mic_queues:
        _mic_queues[chat_id] = asyncio.Queue()
    return _mic_queues[chat_id]


def _enqueue_mute_mic(
    chat_id: int,
    user_id: int,
    call_input,
    reason: str = "bio mengandung link",
) -> None:
    """
    Masukkan permintaan mute mic ke antrean grup ini.
    Jika (chat_id, user_id) sudah antri tindakan mic, skip duplikat.
    Spawn worker jika belum ada.
    """
    key = (chat_id, user_id)
    if key in _mic_pending:
        print(f"[Mic-Worker] uid={user_id} grup={chat_id} sudah antri mic action — skip duplikat.")
        return
    _mic_pending.add(key)
    q = _get_mic_queue(chat_id)
    q.put_nowait(("mute", user_id, call_input, reason))
    _ensure_mic_worker(chat_id)


def _enqueue_unmute_mic(
    chat_id: int,
    user_id: int,
    call_input,
    reason: str = "bio bersih",
) -> None:
    """
    Masukkan permintaan unmute mic ke antrean grup ini.
    Jika (chat_id, user_id) sudah antri tindakan mic, skip duplikat.
    Spawn worker jika belum ada.
    """
    key = (chat_id, user_id)
    if key in _mic_pending:
        print(f"[Mic-Worker] uid={user_id} grup={chat_id} sudah antri unmute — skip duplikat.")
        return
    _mic_pending.add(key)
    q = _get_mic_queue(chat_id)
    q.put_nowait(("unmute", user_id, call_input, reason))
    _ensure_mic_worker(chat_id)


def _ensure_mic_worker(chat_id: int) -> None:
    """Spawn worker mic untuk grup jika belum ada atau sudah selesai."""
    existing = _mic_workers.get(chat_id)
    if existing is None or existing.done():
        task = _safe_task(_mic_action_worker(chat_id), tag=f"mic-worker-{chat_id}")
        _mic_workers[chat_id] = task


async def _mic_action_worker(chat_id: int) -> None:
    """
    Worker antrean mute/unmute mic per grup.

    Mengeksekusi tindakan mic satu per satu dengan jeda _MIC_WORKER_DELAY
    detik antar tindakan. Berhenti saat antrean kosong — akan di-spawn
    ulang oleh _enqueue_mute_mic/_enqueue_unmute_mic saat ada item baru.
    """
    q = _get_mic_queue(chat_id)
    print(f"[Mic-Worker] Worker mic grup {chat_id} mulai berjalan.")
    while True:
        try:
            item = q.get_nowait()
        except asyncio.QueueEmpty:
            break

        action, user_id, call_input, reason = item
        key = (chat_id, user_id)
        try:
            if action == "mute":
                print(f"[Mic-Worker] Mute mic uid={user_id} grup={chat_id} — alasan: {reason}")
                await _kick_from_voice(chat_id, user_id, call_input)
            elif action == "unmute":
                print(f"[Mic-Worker] Unmute mic uid={user_id} grup={chat_id} — alasan: {reason}")
                await _unmute_user_in_vc(chat_id, user_id, call_input)
        except FloodWait as fw:
            wait_sec = fw.value + 2
            print(f"[Mic-Worker] FloodWait {fw.value}s saat {action} uid={user_id} grup={chat_id} — menunggu {wait_sec}s...")
            await asyncio.sleep(wait_sec)
        except Exception as e:
            print(f"[Mic-Worker] Error {action} uid={user_id} grup={chat_id}: {e}")
        finally:
            _mic_pending.discard(key)

        q.task_done()
        if not q.empty():
            await asyncio.sleep(_MIC_WORKER_DELAY)

    # Worker selesai — hapus referensi agar bisa dibuat ulang
    _mic_workers.pop(chat_id, None)
    print(f"[Mic-Worker] Worker mic grup {chat_id} selesai (antrean kosong).")


def get_vc_inspection_lock() -> asyncio.Lock:
    """Return (atau buat) lock inspeksi dadakan. Aman dipanggil dari event loop manapun."""
    global _vc_inspection_lock
    if _vc_inspection_lock is None:
        _vc_inspection_lock = asyncio.Lock()
    return _vc_inspection_lock


def _safe_task(coro, *, tag: str = "") -> asyncio.Task:
    """
    asyncio.create_task dengan exception logging agar task tidak crash diam-diam.
    Semua exception dicatat ke console tanpa membunuh event loop.
    Gunakan untuk semua create_task di hot path Security OS.
    """
    async def _guarded():
        try:
            await coro
        except Exception as _exc:
            _pfx = f"[{tag}] " if tag else ""
            print(f"[UB-Task] {_pfx}{type(_exc).__name__}: {_exc}")
    return asyncio.create_task(_guarded())

# ── Pelacak keberadaan userbot di VC per grup ─────────────────────────────────
# Di-set saat join berhasil, dihapus saat leave/disabled.
_ub_in_vc_groups: set[int] = set()   # {chat_id}

# ══════════════════════════════════════════════════════════════════════════════
# SECOS MUTE TRACKING — Pelacak mute khusus Security OS (Fitur 1-4)
# ══════════════════════════════════════════════════════════════════════════════
#
# "peer invalid" = bot pemantau (bot biasa, bukan userbot) GAGAL resolve peer
#   user karena user belum pernah berinteraksi di grup, sehingga _fetch_bio
#   return None (semua 4 fallback gagal). Kondisi ini berbeda dari has_link=True.
#
# Dua kondisi yang dicatat di _secos_muted_users (cache 30 detik):
#   "non_member"   → user bukan anggota grup tapi naik ke VC
#   "peer_invalid" → user member grup tapi bot pemantau return None (gagal fetch)
#
# Flow (Fitur 2, 3, 4):
#   Mute terjadi → tunggu 1 menit → naik VC cek ulang (Fitur 2)
#   Jika masih invalid → tunggu 5 menit → naik VC lagi (Fitur 3)
#   Setelah itu → kembali ke jadwal 30 menit normal (Fitur 4)
# ══════════════════════════════════════════════════════════════════════════════

# Cache mute khusus Security OS (non-member / peer_invalid) — TTL 30 detik
# Key: (chat_id, user_id), Value: (reason_type: str, muted_at: float)
_SECOS_MUTE_CACHE_TTL = 30.0   # detik — sesuai spesifikasi Fitur 1
_secos_muted_users: dict[tuple[int, int], tuple[str, float]] = {}

# Pelacak follow-up task per grup — cegah double-spawn
# Key: chat_id, Value: asyncio.Task yang sedang berjalan
_secos_followup_tasks: dict[int, asyncio.Task] = {}

# ── Cooldown join per grup ────────────────────────────────────────────────────
# Mencegah multi-join cepat dari jalur manapun (UpdateGroupCall, OnJoin, keepalive).
# Value: waktu monotonic saat join terakhir.
_vc_join_last_ts: dict[int, float] = {}   # {chat_id: monotonic_time}
_VC_JOIN_COOLDOWN      = 15.0      # detik — minimal jeda antar join ke VC yang sama
_VC_SCHEDULED_INTERVAL = 30 * 60   # 30 menit — jeda antar siklus join per grup
_VC_SCAN_DURATION      = 20        # detik stay di VC untuk scan peserta saat ini

# ── Cache admin grup per chat_id (TTL 5 menit) ──────────────────────────────
_admin_cache: dict[int, tuple[set[int], float]] = {}   # {chat_id: (admin_ids, ts)}
_ADMIN_CACHE_TTL = 300.0   # 5 menit — refresh admin list tiap 5 menit

# ── Cache bio per user per grup (dua lapis) ──────────────────────────────────
# Lapisan 1 (di sini, video_call.py): cache in-memory userbot, TTL 60 detik.
#   → Setelah 60 detik, saat user naik VC lagi → trigger force_check_vc_join().
# Lapisan 2 (di MonitorInstance): cache VC khusus, juga TTL 60 detik.
#   → MonitorInstance tidak hit Telegram API jika < 60 detik sejak cek VC.
#
# Kombinasi dua lapis ini memastikan:
#   • Data bio SELALU fresh (≤ 60 detik) saat user naik VC.
#   • Telegram API tidak di-spam jika user keluar-masuk VC berulang.
# Key: (chat_id, user_id) — cache TIDAK pernah dipakai lintas grup.
_bio_cache: dict[tuple[int, int], tuple[bool, float]] = {}
# FIX: sebelumnya hardcoded 60.0 — tidak ikut berubah saat user mengubah
# BIO_TTL_SECS di .env, sehingga cache userbot bisa lebih basi/lebih segar
# daripada TTL Mongo & throttle bot pemantau. Sekarang ikut env yang sama
# agar semua lapisan cache (Mongo TTL, bot pemantau, bot utama, userbot)
# selalu konsisten satu nilai.
_BIO_CACHE_TTL = float(os.environ.get("BIO_TTL_SECS", 60))

# ── Penanda pesan jawaban bot pemantau ───────────────────────────────────────
_pending_checks: dict[tuple[int, int], int] = {}

# ── Mapping call_id → chat_id untuk UpdateGroupCallParticipants ──────────────
# Dideklarasikan di sini (global) agar _on_vc_update bisa mengaksesnya.
_call_id_to_chat: dict[int, int] = {}

# ── Mapping call_id → access_hash (wajib untuk InputGroupCall di raw API) ────
# update.call di UpdateGroupCallParticipants hanya berisi .id (GroupCallReference),
# TIDAK mengandung access_hash. access_hash hanya ada di UpdateGroupCall (saat VC
# dimulai) dan di GetFullChannel. Kita simpan di sini agar bisa build InputGroupCall
# yang valid saat memanggil phone.EditGroupCallParticipant.
_call_id_to_access_hash: dict[int, int] = {}

# ── Global semaphore — batasi concurrent /checkbio ke seluruh Telegram API ───
# Maks 3 query paralel di seluruh sistem (lintas semua grup).
# Diinisialisasi lazy di start_userbot().
_api_semaphore: asyncio.Semaphore | None = None
_API_CONCURRENCY = 3   # konservatif: 3 checkbio parallel max

# ── Per-grup semaphore — batasi checkbio berurutan per grup ──────────────────
# Setiap grup punya semaphore sendiri: maks 1 /checkbio berjalan di waktu yg sama
# per grup. Ini agar bot pemantau di grup A tidak dibanjiri pertanyaan serentak.
_group_semaphores: dict[int, asyncio.Semaphore] = {}

def _get_group_semaphore(chat_id: int) -> asyncio.Semaphore:
    """1 slot per grup — /checkbio diproses satu per satu per grup."""
    if chat_id not in _group_semaphores:
        _group_semaphores[chat_id] = asyncio.Semaphore(1)
    return _group_semaphores[chat_id]

# ── Per-grup antrean notifikasi (warn) ───────────────────────────────────────
# Notifikasi kick dikumpulkan per grup, lalu dikirim dengan jeda.
# Mencegah bot utama mengirim 10 pesan beruntun ke grup dalam 1 detik.
_warn_queues: dict[int, asyncio.Queue] = {}
_warn_workers: dict[int, asyncio.Task] = {}

# Jeda minimum antar pesan warn dalam 1 grup (detik)
_WARN_INTERVAL = 2.5

def _get_warn_queue(chat_id: int) -> asyncio.Queue:
    """Dapatkan / buat antrean warn untuk grup ini."""
    if chat_id not in _warn_queues:
        _warn_queues[chat_id] = asyncio.Queue()
    return _warn_queues[chat_id]

async def _get_group_admin_ids(chat_id: int) -> set[int]:
    """
    Ambil set user_id admin grup, dengan cache 5 menit.
    Return set kosong jika error — lebih aman skip check daripada false-kick admin.
    Dipanggil sebelum loop scan peserta VC untuk skip admin dari pengecekan.
    """
    cached = _admin_cache.get(chat_id)
    if cached:
        ids, ts = cached
        if time.monotonic() - ts < _ADMIN_CACHE_TTL:
            return ids
    if not userbot:
        return set()
    try:
        from pyrogram.enums import ChatMembersFilter
        admin_ids: set[int] = set()
        async for member in userbot.get_chat_members(chat_id, filter=ChatMembersFilter.ADMINISTRATORS):
            if member.user and member.user.id:
                admin_ids.add(member.user.id)
        _admin_cache[chat_id] = (admin_ids, time.monotonic())
        print(f"[UB-VC] Admin grup {chat_id}: {len(admin_ids)} admin di-cache.")
        return admin_ids
    except FloodWait as fw:
        await asyncio.sleep(fw.value + 1)
        return _admin_cache.get(chat_id, (set(), 0.0))[0]
    except Exception as e:
        print(f"[UB-VC] Gagal ambil admin grup {chat_id}: {e}")
        return _admin_cache.get(chat_id, (set(), 0.0))[0]


async def _warn_worker(chat_id: int) -> None:
    """
    Worker per-grup: ambil user_id dari antrean, kirim peringatan, tunggu jeda.
    Berjalan sampai antrean kosong, lalu berhenti (worker-on-demand).
    """
    q = _get_warn_queue(chat_id)
    while True:
        try:
            user_id = q.get_nowait()
        except asyncio.QueueEmpty:
            break
        try:
            await _do_send_warning(chat_id, user_id)
        except FloodWait as fw:
            wait_sec = fw.value + 2
            print(f"[UB-Warn] FloodWait {fw.value}s di warn worker grup={chat_id} uid={user_id} — menunggu {wait_sec}s...")
            await asyncio.sleep(wait_sec)
        except Exception as e:
            print(f"[UB-Warn] Worker error uid={user_id} grup={chat_id}: {e}")
        q.task_done()
        if not q.empty():
            await asyncio.sleep(_WARN_INTERVAL)
    # Worker selesai — hapus referensi agar bisa dibuat ulang
    _warn_workers.pop(chat_id, None)

def _enqueue_warning(chat_id: int, user_id: int) -> None:
    """Masukkan user_id ke antrean warn grup. Spawn worker jika belum ada."""
    q = _get_warn_queue(chat_id)
    q.put_nowait(user_id)
    # Spawn worker hanya jika tidak ada yang berjalan
    existing = _warn_workers.get(chat_id)
    if existing is None or existing.done():
        task = _safe_task(_warn_worker(chat_id), tag=f"warn-worker-{chat_id}")
        _warn_workers[chat_id] = task

# ── Throttle scan grup aktif — cegah spawn task tak terbatas ─────────────────
# Maks grup yang di-scan paralel per siklus monitor (10 detik).
_MAX_PARALLEL_GROUP_SCANS = 4


def _get_api_semaphore() -> asyncio.Semaphore:
    """Lazy-init semaphore di dalam event loop yang aktif."""
    global _api_semaphore
    if _api_semaphore is None:
        _api_semaphore = asyncio.Semaphore(_API_CONCURRENCY)
    return _api_semaphore


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE HELPERS — pakai db[] dari database.py (logika asli TIDAK diubah)
# ══════════════════════════════════════════════════════════════════════════════

def _get_db():
    """Lazy import untuk menghindari circular import saat modul pertama di-load."""
    from database import db, save_bot_config, get_bot_config
    return db, save_bot_config, get_bot_config


async def _sec_os_get(chat_id: int) -> dict:
    """
    Ambil dokumen Security OS untuk satu grup dari DB.

    Schema:
      chat_id        : int   — ID grup Telegram
      enabled        : bool  — apakah Security OS aktif untuk grup ini
      monitor_token  : str   — token bot pemantau (disimpan di DB)
      monitor_bot_id : int   — user_id Telegram bot pemantau
      monitor_chat   : int   — chat_id grup (sama dengan chat_id, redundan tapi eksplisit)
    """
    db, _, _ = _get_db()
    doc = await db["security_os"].find_one({"chat_id": chat_id})
    if doc is None:
        doc = {
            "chat_id":        chat_id,
            "enabled":        False,
            "monitor_token":  "",
            "monitor_bot_id": 0,
            "monitor_chat":   chat_id,
        }
    return doc


async def _sec_os_save(doc: dict) -> None:
    db, _, _ = _get_db()
    # Exclude _id dari $set — MongoDB tidak izinkan update field immutable _id
    payload = {k: v for k, v in doc.items() if k != "_id"}
    await db["security_os"].update_one(
        {"chat_id": doc["chat_id"]},
        {"$set": payload},
        upsert=True,
    )


async def _sec_os_set_enabled(chat_id: int, enabled: bool) -> None:
    doc = await _sec_os_get(chat_id)
    doc["enabled"] = enabled
    await _sec_os_save(doc)


async def _sec_os_set_monitor(chat_id: int, token: str, bot_id: int) -> None:
    doc = await _sec_os_get(chat_id)
    doc["monitor_token"]  = token
    doc["monitor_bot_id"] = bot_id
    doc["monitor_chat"]   = chat_id
    await _sec_os_save(doc)


# ── DB helpers: lacak mute yang dilakukan userbot ─────────────────────────────
# Collection: vc_muted_by_ub → {chat_id, user_id, ts}
# Tujuan:
#   - Userbot HANYA membuka mute user yang dia sendiri yang mute-kan.
#   - Jika admin lain mute, userbot tidak ikut campur (tidak unmute).
#   - Saat userbot unmute → entri dihapus dari collection ini.

async def _record_ub_muted(chat_id: int, user_id: int) -> None:
    """Catat bahwa userbot yang mute user ini di grup ini."""
    try:
        db, _, _ = _get_db()
        await db["vc_muted_by_ub"].update_one(
            {"chat_id": chat_id, "user_id": user_id},
            {"$set": {"chat_id": chat_id, "user_id": user_id, "ts": time.time()}},
            upsert=True,
        )
    except Exception as e:
        print(f"[UB-MuteDB] Gagal catat mute uid={user_id} grup={chat_id}: {e}")


async def _remove_ub_muted(chat_id: int, user_id: int) -> None:
    """Hapus catatan mute userbot untuk user ini di grup ini (setelah unmute)."""
    try:
        db, _, _ = _get_db()
        await db["vc_muted_by_ub"].delete_one({"chat_id": chat_id, "user_id": user_id})
    except Exception as e:
        print(f"[UB-MuteDB] Gagal hapus mute uid={user_id} grup={chat_id}: {e}")


async def _ub_muted_this_user(chat_id: int, user_id: int) -> bool:
    """Return True jika userbot yang pernah mute user ini di grup ini."""
    try:
        db, _, _ = _get_db()
        doc = await db["vc_muted_by_ub"].find_one({"chat_id": chat_id, "user_id": user_id})
        return doc is not None
    except Exception:
        return False


# ── Session userbot ke/dari MongoDB ──────────────────────────────────────────

async def _save_ub_session() -> None:
    """Simpan .session userbot ke MongoDB (sama polanya dengan bot biasa)."""
    import base64
    _, save_bot_config, _ = _get_db()
    try:
        from database import get_active_backend
        if get_active_backend() != "mongo":
            return
        path = _UB_SESSION + ".session"
        if not _Path(path).exists():
            return
        with open(path, "rb") as f:
            raw = f.read()
        await save_bot_config("ub_session_data", base64.b64encode(raw).decode())
        print("[UB] ✅ Session userbot disimpan ke MongoDB.")
    except Exception as e:
        print(f"[UB] ⚠️  Gagal simpan session ke MongoDB: {e}")


async def _restore_ub_session() -> bool:
    """Pulihkan .session userbot dari MongoDB jika file lokal tidak ada."""
    import base64
    _, _, get_bot_config = _get_db()
    try:
        from database import get_active_backend
        if get_active_backend() != "mongo":
            return False
        path = _UB_SESSION + ".session"
        if _Path(path).exists():
            return False
        saved = await get_bot_config("ub_session_data")
        if not saved:
            return False
        with open(path, "wb") as f:
            f.write(base64.b64decode(saved.encode()))
        print("[UB] ✅ Session userbot dipulihkan dari MongoDB.")
        return True
    except Exception as e:
        print(f"[UB] ⚠️  Gagal pulihkan session: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# OTP LOGIN FLOW
# Saat session belum ada:
#   bot biasa → kirim instruksi ke OWNER_ID
#   owner → balas OTP
#   bot biasa → teruskan ke receive_otp_from_bot()
#   userbot → login dengan OTP
# ══════════════════════════════════════════════════════════════════════════════

def receive_otp_from_bot(text: str) -> None:
    """Dipanggil dari handler bot biasa saat owner membalas OTP/2FA."""
    global _otp_value
    _otp_value = text.strip()
    if _otp_event and not _otp_event.is_set():
        _otp_event.set()


def register_otp_handler(bot: _Client) -> None:
    """
    Pasang handler di bot biasa untuk menangkap OTP dari owner.
    Owner harus mengirim perintah: /otp <kode>
    Handler ini HANYA aktif saat _otp_event belum di-set (sedang menunggu OTP).
    Menggunakan group=99 agar tidak bentrok dengan handler asli bot.
    """

    @bot.on_message(
        _filters.private & _filters.user(OWNER_ID) & _filters.text,
        group=99,
    )
    async def _catch_otp(_client: _Client, msg: _Message):
        txt = (msg.text or "").strip()

        # Tangkap format /otp <kode> dari owner
        if txt.lower().startswith("/otp "):
            otp_code = txt[5:].strip()
            if otp_code:
                if _otp_event and not _otp_event.is_set():
                    # Sedang menunggu OTP -> teruskan ke login flow
                    receive_otp_from_bot(otp_code)
                    await msg.reply(
                        f"\u2705 <b>OTP diterima:</b> <code>{otp_code}</code>\n"
                        "Mencoba login userbot...",
                        parse_mode=ParseMode.HTML,
                    )
                else:
                    await msg.reply(
                        "\u26a0\ufe0f Bot tidak sedang menunggu OTP. "
                        "Pastikan userbot belum login atau restart bot terlebih dahulu.",
                        parse_mode=ParseMode.HTML,
                    )
            else:
                await msg.reply(
                    "\u274c Format salah. Gunakan: <code>/otp 12345</code>",
                    parse_mode=ParseMode.HTML,
                )


async def _prompt_owner(bot: _Client, html_msg: str) -> str:
    """
    Tunggu OTP dari owner (maks 10 menit).
    Owner harus mengirim /otp <kode> ke bot ini secara DM.
    Return teks OTP, atau "" jika timeout.
    """
    global _otp_event, _otp_value
    _otp_event = asyncio.Event()
    _otp_value = ""

    # Log ke console — owner harus kirim /otp sendiri ke bot
    print("[UB-OTP] Menunggu owner kirim OTP via DM bot dengan format: /otp <kode>")

    try:
        await asyncio.wait_for(_otp_event.wait(), timeout=600.0)
        return _otp_value
    except asyncio.TimeoutError:
        print("[UB-OTP] Timeout menunggu OTP dari owner (10 menit). Restart bot untuk mencoba lagi.")
        return ""


async def _do_login(bot: _Client) -> bool:
    """
    Login userbot dengan flow OTP interaktif.
    Owner harus mengirim /otp <kode> ke bot ini via DM.
    Return True jika berhasil, False jika gagal/timeout.
    """
    global userbot

    if not USERBOT_PHONE:
        print("[UB] ⚠️  USERBOT_PHONE tidak diset — Security OS tidak tersedia.")
        return False

    print("[UB] 🔄 Session userbot belum ada. Meminta kode OTP ke Telegram...")
    print(f"[UB] 📱 Nomor: {USERBOT_PHONE}")
    print("[UB] ⏳ Kirim OTP via DM bot dengan format: /otp <kode>")

    # Buat client userbot (mode user, bukan bot)
    ub = _Client(
        _UB_SESSION,
        api_id=API_ID,
        api_hash=API_HASH,
        device_model="Samsung Galaxy S24",
        system_version="Android 14",
        app_version="10.14.5",
    )

    try:
        await ub.connect()
    except Exception as e:
        print(f"[UB] Gagal connect: {e}")
        return False

    # Minta kode OTP ke Telegram
    try:
        sent = await ub.send_code(USERBOT_PHONE)
    except PhoneNumberInvalid:
        print(f"[UB] \u274c USERBOT_PHONE tidak valid: '{USERBOT_PHONE}' — periksa format di .env (contoh: +628123456789)")
        await ub.disconnect()
        return False
    except FloodWait as fw:
        print(f"[UB] FloodWait {fw.value}s saat send_code.")
        await asyncio.sleep(fw.value)
        await ub.disconnect()
        return False
    except Exception as e:
        print(f"[UB] Gagal send_code: {e}")
        await ub.disconnect()
        return False

    # Tampilkan petunjuk di console — owner harus kirim /otp sendiri ke bot
    phone_hint = (
        USERBOT_PHONE[:3] + "****" + USERBOT_PHONE[-3:]
        if len(USERBOT_PHONE) > 6 else "****"
    )
    print(f"[UB-OTP] \U0001f510 OTP Telegram dikirim ke {phone_hint}")
    print("[UB-OTP] Kirim OTP ke bot via DM dengan format: /otp <kode>")
    print("[UB-OTP] Menunggu owner kirim OTP... (timeout 10 menit)")
    otp = await _prompt_owner(bot, "")

    if not otp:
        await ub.disconnect()
        return False

    # Sign in dengan OTP
    try:
        await ub.sign_in(USERBOT_PHONE, sent.phone_code_hash, otp)

    except PhoneCodeInvalid:
        print("[UB-OTP] \u274c OTP salah. Restart bot untuk mencoba lagi.")
        await ub.disconnect()
        return False

    except PhoneCodeExpired:
        print("[UB-OTP] \u274c OTP sudah kadaluarsa. Restart bot untuk mencoba lagi.")
        await ub.disconnect()
        return False

    except SessionPasswordNeeded:
        # Akun menggunakan 2FA
        print("[UB-OTP] \U0001f511 Akun menggunakan 2FA. Kirim password via DM bot: /otp <password>")
        print("[UB-OTP] Menunggu password 2FA dari owner... (timeout 10 menit)")
        pw = await _prompt_owner(bot, "")
        if not pw:
            await ub.disconnect()
            return False
        try:
            await ub.check_password(pw)
        except Exception as e2:
            print(f"[UB-OTP] \u274c Password 2FA salah: {e2} — Restart bot untuk mencoba lagi.")
            await ub.disconnect()
            return False

    except Exception as e:
        print(f"[UB] Gagal sign_in: {e}")
        await ub.disconnect()
        return False

    # Login berhasil — userbot sudah connected via connect()+sign_in()
    # JANGAN panggil start() lagi, karena client sudah connected
    userbot = ub
    await _save_ub_session()

    try:
        me = await ub.get_me()
        _ub_self_id_val = me.id
        print(f"[UB] \u2705 Userbot Security OS berhasil login! Akun: {me.first_name} (id={me.id})")
        print("[UB] \U0001f6e1\ufe0f Security OS siap dikonfigurasi di panel grup.")
        return True, _ub_self_id_val
    except Exception as e:
        print(f"[UB] ⚠️  Login berhasil tapi gagal get_me: {e}")
        return True, 0


# ══════════════════════════════════════════════════════════════════════════════
# USERBOT — START & STOP
# ══════════════════════════════════════════════════════════════════════════════

async def start_userbot(bot: _Client) -> None:
    """
    Entry point dipanggil dari antigcast.py setelah bot biasa aktif.
    Non-blocking — langsung return setelah create_task background loop.
    """
    global userbot, _bot_ref, _ub_ready, _ub_self_id
    _bot_ref = bot

    # Inisialisasi semaphore di dalam event loop yang aktif
    _get_api_semaphore()

    # Pasang OTP handler di bot biasa (sebelum apapun)
    register_otp_handler(bot)

    # Pasang handler auto-kenali bot pemantau saat masuk grup
    register_monitor_join_handler(bot)

    # Coba pulihkan session dari MongoDB (setelah Railway redeploy)
    await _restore_ub_session()

    session_file = _UB_SESSION + ".session"

    if _Path(session_file).exists():
        # Session tersedia — coba langsung start
        try:
            ub = _Client(
                _UB_SESSION,
                api_id=API_ID,
                api_hash=API_HASH,
                device_model="Samsung Galaxy S24",
                system_version="Android 14",
                app_version="10.14.5",
            )
            await ub.start()
            me = await ub.get_me()
            userbot    = ub
            _ub_self_id = me.id
            _ub_ready  = True
            print(f"[UB] ✅ Userbot aktif: {me.first_name} (id={me.id})")
            await _save_ub_session()
            # Log berapa grup Security OS yang sudah terdaftar di DB
            await _log_registered_groups()
            _safe_task(_voice_chat_monitor_loop(), tag="vc-monitor-loop")
            return
        except Exception as e:
            print(f"[UB] ⚠️  Session ada tapi gagal start ({type(e).__name__}): {e}")
            # Hapus session rusak agar bisa login ulang
            try:
                _Path(session_file).unlink(missing_ok=True)
            except Exception:
                pass

    # Tidak ada session / session rusak
    if not USERBOT_PHONE:
        print("[UB] ℹ️  USERBOT_PHONE tidak diset — Security OS tidak tersedia.")
        return

    print("[UB] ℹ️  Session userbot tidak ada → mulai OTP login flow...")
    result = await _do_login(bot)

    # _do_login sekarang return (ok, self_id) — userbot sudah connected, JANGAN start() lagi
    if isinstance(result, tuple):
        ok, self_id = result
    else:
        ok, self_id = result, 0

    if ok and userbot:
        try:
            # Userbot sudah connected via connect()+sign_in() — set state langsung
            _ub_self_id = self_id
            _ub_ready   = True
            await _log_registered_groups()
            _safe_task(_voice_chat_monitor_loop(), tag="vc-monitor-loop")
        except Exception as e:
            print(f"[UB] Gagal aktivasi setelah login: {e}")
    else:
        print("[UB] ❌ Login userbot gagal — Security OS tidak aktif.")


async def stop_userbot() -> None:
    """Hentikan userbot dengan bersih. Dipanggil dari graceful_shutdown()."""
    global userbot, _ub_ready
    _ub_ready = False
    if userbot:
        try:
            await userbot.stop()
            print("[UB] ✅ Userbot berhenti dengan bersih.")
        except Exception as e:
            print(f"[UB] stop error: {e}")
        userbot = None


# ══════════════════════════════════════════════════════════════════════════════
# VOICE CHAT MONITOR LOOP
# Polling ringan per-grup, hanya mengamati obrolan SUARA.
# Pesan/typing tetap sepenuhnya di tangan bot biasa (tidak disentuh).
# ══════════════════════════════════════════════════════════════════════════════


async def _log_registered_groups() -> None:
    """
    Saat startup, log berapa grup Security OS yang sudah tersimpan di MongoDB,
    lalu lakukan warm-up BERTAHAP (staggered) — resolve peer setiap grup dengan
    jeda kecil agar userbot tidak memicu FloodWait karena mengakses
    banyak grup sekaligus saat redeploy.
    """
    db, _, _ = _get_db()
    try:
        total  = await db["security_os"].count_documents({})
        active = await db["security_os"].count_documents({"enabled": True})
        print(
            f"[UB] 📋 Security OS DB: {total} grup terdaftar, "
            f"{active} aktif — semua dikenali otomatis dari MongoDB."
        )
    except Exception as e:
        print(f"[UB] ⚠️  Tidak bisa baca hitungan grup dari DB: {e}")
        return

    # ── Warm-up bertahap: resolve peer setiap grup dengan jeda ───────────────
    # Mencegah userbot "hadir" di banyak grup sekaligus saat redeploy,
    # yang bisa memicu FloodWait atau deteksi anomali Telegram.
    _STARTUP_STAGGER = 3.0   # detik jeda antar grup
    try:
        docs = await db["security_os"].find({}, {"chat_id": 1}).to_list(None)
    except Exception:
        return

    if not docs:
        return

    print(f"[UB] ⏳ Startup stagger: warm-up {len(docs)} grup "
          f"(jeda {_STARTUP_STAGGER}s per grup)...")
    for i, doc in enumerate(docs):
        if not userbot or not _ub_ready:
            break
        chat_id = doc.get("chat_id")
        if not chat_id:
            continue
        try:
            await userbot.resolve_peer(chat_id)
        except FloodWait as fw:
            print(f"[UB-Startup] FloodWait {fw.value}s saat resolve grup {chat_id} — menunggu...")
            await asyncio.sleep(fw.value + 1)
        except Exception:
            pass   # Grup mungkin dihapus/userbot tidak ada — lewati
        if i < len(docs) - 1:
            await asyncio.sleep(_STARTUP_STAGGER)

    print("[UB] ✅ Startup stagger selesai — userbot siap.")
    # Join grup dilakukan oleh _vc_scheduled_loop setiap 30 menit


async def _voice_chat_monitor_loop() -> None:
    """
    Background task — pasang handler raw update untuk menangkap
    UpdateGroupCallParticipants secara event-driven.

    ── CARA KERJA: MENURUNKAN USER BIO-LINK DARI OBROLAN SUARA ─────────────
    1. Userbot menjadi member grup (bukan peserta VC).
    2. Telegram API secara otomatis mengirim UpdateGroupCallParticipants
       ke semua member grup setiap ada user yang JOIN obrolan suara/video.
       ➜ Ini adalah perilaku resmi Telegram API — tidak memerlukan join VC.
    3. Setiap user yang join VC dicek: apakah bio-nya mengandung link?
       • Cek cache in-memory dulu (TTL 10 menit).
       • Jika tidak ada cache → query bio_profiles di DB (diisi bot pemantau).
    4. Jika has_link=True → userbot memanggil phone.EditGroupCallParticipant
       (muted=True, video_stopped=True) → user diturunkan dari obrolan suara.
    5. Bot biasa mengirim peringatan di grup lalu menghapus pesan setelah 10 detik.

    ── KENAPA USERBOT HARUS JOIN VC ─────────────────────────────────────────
    UpdateGroupCallParticipants HANYA dikirim Telegram ke klien yang sudah
    berada di dalam VC (subscriber aktif call). Userbot yang hanya jadi member
    grup biasa TIDAK akan menerima event peserta join/leave.

    Oleh karena itu:
      • Saat VC baru dimulai (UpdateGroupCall) → userbot join VC otomatis.
      • Saat startup/redeploy dan VC sudah aktif → userbot join via startup scan.
      • phone.EditGroupCallParticipant (mute mic) wajib dipanggil dari dalam VC
        ATAU oleh admin dengan izin "Kelola Obrolan Video" — userbot join VC
        memastikan kedua kondisi terpenuhi.
    """
    print("[UB] \U0001f3a4 Voice chat monitor dimulai (event-driven).")

    if not userbot:
        return

    # ── Init MonitorInstance dari DB DULU sebelum handler VC aktif ───────────
    # Wajib sebelum @on_raw_update didaftarkan agar force_check_vc_join tidak
    # return None karena _active_instances masih kosong saat event pertama masuk.
    try:
        from monitor_bot_reference import _load_instances_from_db, _periodic_session_backup
        await _load_instances_from_db()
        print("[UB-Monitor] ✅ MonitorInstance dimuat dari DB.")
        # Backup periodik session tiap monitor (peer cache ikut terbawa saat redeploy)
        import asyncio as _asyncio_mon
        _asyncio_mon.create_task(_periodic_session_backup())
    except Exception as _e_mon:
        print(f"[UB-Monitor] ⚠️  Gagal load MonitorInstance: {_e_mon}")

    # ── Sync dialog agar Telegram kirim UpdateGroupCall ke sesi ini ──────────
    try:
        print("[UB-VC] Sinkronisasi dialog untuk subscribe update VC...")
        async for _ in userbot.get_dialogs():
            pass
        print("[UB-VC] ✅ Dialog tersinkronisasi.")
    except FloodWait as fw:
        print(f"[UB-VC] FloodWait {fw.value}s saat get_dialogs")
        await asyncio.sleep(fw.value + 1)
    except Exception as e:
        print(f"[UB-VC] get_dialogs error (tidak fatal): {e}")

    @userbot.on_raw_update()
    async def _on_vc_update(client, update, users, chats):
        if not _ub_ready:
            return
        try:
            from pyrogram.raw.types import (
                UpdateGroupCallParticipants,
                UpdateGroupCall,
                GroupCallParticipant,
                GroupCallDiscarded,
            )
        except ImportError:
            return

        # ── Tangkap voice chat baru dimulai → daftarkan call_id + access_hash ─
        if isinstance(update, UpdateGroupCall):
            chat_id_raw = getattr(update, "chat_id", None)
            if chat_id_raw:
                # Telegram kirim chat_id sebagai angka positif untuk supergroup
                chat_id_neg = int(f"-100{chat_id_raw}") if chat_id_raw > 0 else chat_id_raw
                call_obj = getattr(update, "call", None)
                if call_obj:
                    # ── FILTER: skip VC yang sudah berakhir (GroupCallDiscarded) ──
                    # Telegram kirim UpdateGroupCall + GroupCallDiscarded saat VC selesai.
                    # Jangan proses sebagai VC baru — cukup bersihkan mapping.
                    if isinstance(call_obj, GroupCallDiscarded):
                        disc_id = getattr(call_obj, "id", None)
                        if disc_id:
                            _call_id_to_chat.pop(disc_id, None)
                            _call_id_to_access_hash.pop(disc_id, None)
                        return

                    # ── FILTER: skip live stream channel (bukan obrolan suara grup) ──
                    # GroupCall.is_stream = True  → Live stream / channel broadcast → skip
                    # GroupCall.is_stream = False/None → Obrolan suara grup → proses
                    # Telegram membedakan keduanya via flag ini di object GroupCall.
                    is_stream = getattr(call_obj, "is_stream", False)
                    if is_stream:
                        print(
                            f"[UB-VC] Skip live stream (bukan obrolan suara grup) "
                            f"di chat {chat_id_neg}"
                        )
                        return

                    call_id = getattr(call_obj, "id", None)
                    # BUG FIX: simpan access_hash — hanya tersedia di UpdateGroupCall,
                    # TIDAK ada di UpdateGroupCallParticipants (GroupCallReference).
                    # Tanpa access_hash, phone.EditGroupCallParticipant akan gagal
                    # dengan ACCESS_HASH_INVALID atau serupa.
                    access_hash = getattr(call_obj, "access_hash", None)
                    if call_id:
                        # Simpan selalu — filter enabled dicek saat ada peserta join
                        _call_id_to_chat[call_id] = chat_id_neg
                        if access_hash is not None:
                            _call_id_to_access_hash[call_id] = access_hash
                        # Log semua VC yang terdeteksi (debug)
                        sec = await _sec_os_get(chat_id_neg)
                        enabled = sec.get("enabled", False)
                        print(
                            f"[UB-VC] Obrolan suara grup {chat_id_neg} "
                            f"(call_id={call_id}, enabled={enabled}, "
                            f"access_hash={'✅' if access_hash else '⚠️ tidak ada'})"
                        )
                        # Userbot harus JOIN VC segera saat VC dimulai.
                        #
                        # KENAPA WAJIB JOIN:
                        # UpdateGroupCallParticipants HANYA dikirim Telegram ke klien
                        # yang sudah berada di dalam VC (subscriber aktif call).
                        # Jika userbot tidak join, ia tidak akan pernah menerima event
                        # peserta join/leave — sehingga pemantauan bio-link tidak berjalan.
                        #
                        # UpdateGroupCall (event VC mulai) dikirim ke SEMUA member grup,
                        # sehingga inilah satu-satunya kesempatan reliable untuk join.
                        # Scheduler 30 menit akan join pada waktunya — tidak auto-join di sini.
                        if enabled:
                            print(
                                f"[UB-VC] VC dimulai di grup {chat_id_neg} "
                                f"(call_id={call_id}) — dijadwal tiap 30 menit."
                            )
            return

        if not isinstance(update, UpdateGroupCallParticipants):
            return

        call_id = update.call.id
        chat_id = _call_id_to_chat.get(call_id)
        if not chat_id:
            # ── FALLBACK: mapping belum terisi (warmup gagal/terlewat) ───────
            # Coba resolve langsung dengan cocokkan call.id ke grup Security OS
            # yang terdaftar. Hasil yang cocok di-cache agar event berikutnya
            # tidak perlu resolve ulang.
            chat_id = await _resolve_chat_for_call_id(call_id)
            if not chat_id:
                return
            _call_id_to_chat[call_id] = chat_id
            print(f"[UB-VC] Fallback resolve: call_id={call_id} → grup {chat_id}")

        sec_doc = await _sec_os_get(chat_id)
        if not sec_doc.get("enabled"):
            return

        # ARSITEKTUR DB-DRIVEN: monitor_bot_id tidak wajib untuk query bio.
        # Userbot langsung baca collection bio_profiles yang diisi bot pemantau.
        # Catatan: Security OS tetap membutuhkan bot pemantau untuk mengisi DB,
        # tapi userbot tidak perlu tahu monitor_bot_id untuk cek bio.
        monitor_id = sec_doc.get("monitor_bot_id", 0)  # dipertahankan untuk logging

        # Tidak ada auto-join — scheduler 30 menit yang menangani join VC.

        # FIX 4: Ambil daftar admin grup (cached 5 menit) — admin di-skip
        _vc_admin_ids = await _get_group_admin_ids(chat_id)

        for p in update.participants:
            if not isinstance(p, GroupCallParticipant):
                continue
            if getattr(p, "left", False):
                # User keluar dari VC — skip
                continue

            peer = getattr(p, "peer", None)
            if peer is None:
                continue
            uid = getattr(peer, "user_id", None)
            if not uid or uid == _ub_self_id:
                continue
            # FIX 4: Skip admin grup
            if uid in _vc_admin_ids:
                continue

            # Pisahkan "muted mic oleh admin" vs "mute sendiri" vs "muted di typing (chat)"
            # muted=True + can_self_unmute=False → admin mute mic (yang userbot pedulikan)
            # muted=True + can_self_unmute=True  → self-mute (BUKAN urusan userbot)
            # Restrict typing (chat ban) TIDAK ada kaitannya dengan field VC ini.
            _p_muted    = bool(getattr(p, "muted", False))
            _can_self   = bool(getattr(p, "can_self_unmute", True))
            is_muted    = _p_muted and not _can_self   # True hanya jika admin-muted
            # BUG 2: muted_by_you = field Telegram API, True jika userbot sendiri yang mute
            muted_by_you = bool(getattr(p, "muted_by_you", False))

            key = (chat_id, uid)
            if key in _processing_kick:
                continue

            # Cek in-memory cache dulu (TTL 1 menit)
            cached = _bio_cache.get(key)
            if cached:
                has_link, cache_ts = cached
                if time.monotonic() - cache_ts < _BIO_CACHE_TTL:
                    if has_link:
                        # Jika admin lain sudah unmute (is_muted=False) tapi
                        # bio masih ada link → mute ulang dengan notifikasi baru.
                        _processing_kick.add(key)
                        call_input = _build_input_group_call(call_id)
                        if not is_muted:
                            print(
                                f"[UB-VC] uid={uid} grup={chat_id}: di-unmute admin lain "
                                "tapi bio masih ada link → mute mic ulang."
                            )
                        _safe_task(
                            _execute_kick(chat_id, uid, call_input, was_already_muted=is_muted),
                            tag="exec-kick-cache",
                        )
                    elif is_muted:
                        # bio bersih/kosong tapi mic muted → cek fresh dari bot pemantau
                        _processing_kick.add(key)
                        call_input = _build_input_group_call(call_id)
                        _safe_task(
                            _query_monitor_then_kick(
                                chat_id, uid, monitor_id, call_input,
                                is_muted=True, muted_by_you=muted_by_you,
                            ),
                            tag="query-muted",
                        )
                    continue

            # Query DB (bot pemantau sudah mengisi bio_profiles)
            _processing_kick.add(key)
            call_input = _build_input_group_call(call_id)
            _safe_task(
                _query_monitor_then_kick(
                    chat_id, uid, monitor_id, call_input,
                    is_muted=is_muted, muted_by_you=muted_by_you,
                )
            )

    # Warmup: isi _call_id_to_chat dari grup Security OS yang sudah punya VC aktif
    await _warmup_active_calls()

    # Join VC yang sudah aktif saat startup/redeploy.
    #
    # KENAPA WAJIB JOIN SAAT STARTUP:
    # UpdateGroupCallParticipants HANYA dikirim Telegram ke klien yang sudah
    # berada di dalam VC. Jika VC sudah aktif sebelum bot start (dan tidak ada
    # UpdateGroupCall baru yang diterima), userbot tidak akan pernah masuk VC
    # kecuali join manual di sini.
    asyncio.ensure_future(_safe_task(_vc_scheduled_loop(), tag="vc-scheduled-loop"))
    print("[UB-VC] Scheduler join VC 30 menit dimulai.")

    # Cache cleanup loop — bersihkan entri cache kedaluwarsa tiap 10 menit
    asyncio.ensure_future(_safe_task(_cache_cleanup_loop(), tag="cache-cleanup-loop"))
    print("[UB-Cache] Cache cleanup loop dimulai (interval 10 menit).")

    # Jaga task tetap hidup
    while _ub_ready and userbot:
        await asyncio.sleep(30)
    print("[UB] \U0001f507 Voice chat monitor berhenti.")



async def _vc_join_raw(chat_id: int, call_id: int, access_hash: int) -> bool:
    """
    Join VC via raw MTProto pyrogram.
    Telegram akan kick userbot setelah ~30 detik — tidak masalah, tugasnya sudah selesai.
    Return True jika berhasil (atau sudah ada di VC), False jika gagal.
    """
    if not userbot:
        return False
    import random as _random
    import json as _json
    from pyrogram.raw import functions as _rf
    from pyrogram.raw.types import InputGroupCall, DataJSON

    ssrc  = _random.randint(1, 0xFFFFFFFF)
    ufrag = "".join(_random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    pwd   = "".join(_random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=22))
    params = DataJSON(data=_json.dumps({
        "ufrag": ufrag,
        "pwd":   pwd,
        "fingerprints": [],
        "ssrc": ssrc,
    }))
    input_call = InputGroupCall(id=call_id, access_hash=access_hash)
    try:
        await userbot.invoke(
            _rf.phone.JoinGroupCall(
                call=input_call,
                join_as=await userbot.resolve_peer("me"),
                params=params,
                muted=True,
                video_stopped=True,
            )
        )
        print(f"[UB-VC-Join] ✅ Join VC grup {chat_id} berhasil (raw MTProto, ssrc={ssrc})")
        return True
    except FloodWait as fw:
        print(f"[UB-VC-Join] FloodWait {fw.value}s saat join VC grup {chat_id}")
        await asyncio.sleep(fw.value + 1)
        return False
    except Exception as e:
        err_str = str(e).lower()
        if "already" in err_str:
            return True   # Sudah di VC — anggap berhasil
        print(f"[UB-VC-Join] Gagal join VC grup {chat_id}: {e}")
        return False


async def _vc_get_call_info(chat_id: int):
    """
    Ambil (call_id, access_hash) dari GetFullChannel.
    Return (call_id, access_hash) atau (None, None) jika tidak ada VC aktif.
    """
    if not userbot:
        return None, None
    from pyrogram.raw import functions as _rf
    try:
        chat_peer = await userbot.resolve_peer(chat_id)
        full = await userbot.invoke(_rf.channels.GetFullChannel(channel=chat_peer))
        call_obj = getattr(full.full_chat, "call", None)
        if not call_obj:
            return None, None
        call_id     = call_obj.id
        access_hash = getattr(call_obj, "access_hash", None)
        if access_hash:
            _call_id_to_chat[call_id]        = chat_id
            _call_id_to_access_hash[call_id] = access_hash
        return call_id, access_hash
    except FloodWait as fw:
        print(f"[UB-VC] FloodWait {fw.value}s saat GetFullChannel grup {chat_id}")
        await asyncio.sleep(fw.value + 1)
        return None, None
    except Exception as e:
        print(f"[UB-VC] Gagal GetFullChannel grup {chat_id}: {e}")
        return None, None


async def _vc_scan_and_enforce(chat_id: int) -> None:
    """
    Satu siklus Security OS untuk satu grup:
      1. Ambil info VC aktif (GetFullChannel)
      2. Join VC via raw MTProto
      3. Ambil semua peserta VC via GetGroupParticipants
      4. Cek bio tiap peserta (cache 1 menit) → mute jika link, unmute jika bersih
      5. Tunggu _VC_SCAN_DURATION detik (sambil handle user baru yg join via UpdateGroupCallParticipants)
      6. Leave VC (Telegram mungkin sudah kick duluan — tidak masalah)

    Semua langkah diproteksi FloodWait. Antar grup ada stagger 10 detik di scheduler.
    """
    if not userbot or not _ub_ready:
        return

    sec_doc = await _sec_os_get(chat_id)
    if not sec_doc.get("enabled"):
        return
    monitor_id = sec_doc.get("monitor_bot_id", 0)

    print(f"[UB-VC-Sched] Grup {chat_id}: mulai siklus scan VC...")

    # ── 1. Ambil info VC aktif ───────────────────────────────────────────────
    call_id, access_hash = await _vc_get_call_info(chat_id)
    if not call_id or not access_hash:
        print(f"[UB-VC-Sched] Grup {chat_id}: tidak ada VC aktif — skip siklus ini.")
        return

    # ── 2. Join VC ───────────────────────────────────────────────────────────
    ok = await _vc_join_raw(chat_id, call_id, access_hash)
    if not ok:
        print(f"[UB-VC-Sched] Grup {chat_id}: gagal join VC — skip siklus ini.")
        return

    _ub_in_vc_groups.add(chat_id)
    _vc_join_last_ts[chat_id] = time.monotonic()

    # ── 3. Scan peserta saat ini via GetGroupParticipants ────────────────────
    from pyrogram.raw import functions as _rf
    from pyrogram.raw.types import InputGroupCall
    input_call = InputGroupCall(id=call_id, access_hash=access_hash)
    try:
        result = await userbot.invoke(
            _rf.phone.GetGroupParticipants(
                call=input_call,
                ids=[],
                sources=[],
                offset="",
                limit=200,
            )
        )
        participants = getattr(result, "participants", [])
        print(f"[UB-VC-Sched] Grup {chat_id}: {len(participants)} peserta ditemukan di VC.")

        # Ambil daftar admin grup — admin di-skip, tidak di-mute oleh userbot
        admin_ids = await _get_group_admin_ids(chat_id)

        for p in participants:
            peer = getattr(p, "peer", None)
            if peer is None:
                continue
            uid = getattr(peer, "user_id", None)
            if not uid or uid == _ub_self_id:
                continue
            # FIX 4: Skip admin grup — userbot tidak memeriksa atau mute admin
            if uid in admin_ids:
                continue
            # Hanya admin-muted yang dihitung — bukan self-muted atau chat restriction (typing ban)
            _pm  = bool(getattr(p, "muted", False))
            _cs  = bool(getattr(p, "can_self_unmute", True))
            is_muted     = _pm and not _cs       # True hanya jika mic di-mute oleh admin
            # BUG 2: field Telegram API — True jika userbot sendiri yang mute mic user ini
            muted_by_you = bool(getattr(p, "muted_by_you", False))
            key = (chat_id, uid)
            if key in _processing_kick:
                continue
            _processing_kick.add(key)
            call_input = _build_input_group_call(call_id)
            _safe_task(
                _query_monitor_then_kick(
                    chat_id, uid, monitor_id, call_input,
                    is_muted=is_muted, muted_by_you=muted_by_you,
                ),
                tag="scan-enforce",
            )
    except FloodWait as fw:
        print(f"[UB-VC-Sched] FloodWait {fw.value}s saat GetGroupParticipants grup {chat_id}")
        await asyncio.sleep(fw.value + 1)
    except Exception as e:
        print(f"[UB-VC-Sched] Gagal GetGroupParticipants grup {chat_id}: {e}")

    # ── 4. Tunggu sambil handle user baru yang join via UpdateGroupCallParticipants ─
    # Handler _on_vc_update sudah aktif — user baru yang join selama window ini
    # akan otomatis dicek oleh handler tersebut (karena chat_id in _ub_in_vc_groups).
    await asyncio.sleep(_VC_SCAN_DURATION)

    # ── 5. Leave VC (Telegram mungkin sudah kick duluan) ────────────────────
    _ub_in_vc_groups.discard(chat_id)
    print(f"[UB-VC-Sched] Grup {chat_id}: siklus selesai, keluar dari VC.")
    try:
        await userbot.invoke(_rf.phone.LeaveGroupCall(call=input_call, source=0))
    except Exception:
        pass   # Sudah dikick atau tidak di VC — tidak masalah


async def _vc_scheduled_loop() -> None:
    """
    Scheduler utama Security OS:
    Setiap _VC_SCHEDULED_INTERVAL (30 menit), untuk tiap grup yang Security OS-nya aktif
    → jalankan satu siklus _vc_scan_and_enforce.

    Stagger antar grup: 10 detik jeda untuk cegah FloodWait ke Telegram API.
    Siklus pertama dimulai 60 detik setelah startup (beri waktu warmup selesai).
    """
    print("[UB-VC-Sched] ⏰ Scheduler join VC 30 menit aktif.")
    await asyncio.sleep(60)   # beri waktu startup/warmup selesai

    while _ub_ready and userbot:
        db, _, _ = _get_db()
        try:
            docs = await db["security_os"].find({"enabled": True}).to_list(None)
        except Exception:
            await asyncio.sleep(60)
            continue

        if docs:
            print(f"[UB-VC-Sched] Mulai siklus — {len(docs)} grup aktif → antri ke VC worker.")
            for doc in docs:
                if not userbot or not _ub_ready:
                    break
                chat_id = doc.get("chat_id")
                if not chat_id:
                    continue
                # Antri ke worker — worker yang atur jeda antar grup, tidak parallel
                _enqueue_vc_scan(chat_id)
        else:
            print("[UB-VC-Sched] Tidak ada grup aktif — tidur 60 detik.")
            await asyncio.sleep(60)
            continue

        print(f"[UB-VC-Sched] Tidur {_VC_SCHEDULED_INTERVAL // 60} menit hingga siklus berikutnya...")
        await asyncio.sleep(_VC_SCHEDULED_INTERVAL)



async def _resolve_chat_for_call_id(call_id: int) -> int | None:
    """
    Fallback saat _call_id_to_chat tidak punya entri untuk call_id ini
    (warmup gagal/terlewat, atau VC dimulai sebelum warmup selesai).

    Iterasi grup Security OS aktif, GetFullChannel tiap grup, cocokkan
    call.id dengan call_id yang sedang diproses. Sekali ketemu langsung
    return — hasil di-cache oleh caller ke _call_id_to_chat.

    Tidak dipanggil sering: hanya saat terjadi cache-miss pada
    _call_id_to_chat, jadi aman dari segi rate limit (di-throttle
    dengan sleep kecil + FloodWait handling).
    """
    if not userbot:
        return None
    db, _, _ = _get_db()
    try:
        docs = await db["security_os"].find({"enabled": True}).to_list(None)
    except Exception:
        return None

    from pyrogram.raw import functions as _rf
    for doc in docs:
        chat_id = doc.get("chat_id")
        if not chat_id:
            continue
        try:
            chat_peer = await userbot.resolve_peer(chat_id)
            full = await userbot.invoke(_rf.channels.GetFullChannel(channel=chat_peer))
            call_obj = getattr(full.full_chat, "call", None)
            if call_obj and call_obj.id == call_id:
                # BUG FIX: simpan access_hash dari fallback resolve juga
                access_hash = getattr(call_obj, "access_hash", None)
                if access_hash is not None:
                    _call_id_to_access_hash[call_id] = access_hash
                return chat_id
        except FloodWait as fw:
            await asyncio.sleep(fw.value + 1)
        except Exception:
            pass
        await asyncio.sleep(0.5)

    return None


async def _warmup_active_calls() -> None:
    """
    Saat startup, cari grup Security OS aktif yang sudah punya voice chat
    berjalan dan isi _call_id_to_chat agar event pertama langsung dikenali.
    """
    if not userbot:
        return
    db, _, _ = _get_db()
    try:
        docs = await db["security_os"].find({"enabled": True}).to_list(None)
    except Exception:
        return

    from pyrogram.raw import functions as _rf
    for doc in docs:
        chat_id = doc.get("chat_id")
        if not chat_id:
            continue
        try:
            chat_peer = await userbot.resolve_peer(chat_id)
            full = await userbot.invoke(_rf.channels.GetFullChannel(channel=chat_peer))
            call_obj = getattr(full.full_chat, "call", None)
            if call_obj:
                _call_id_to_chat[call_obj.id] = chat_id
                # BUG FIX: simpan access_hash dari GetFullChannel — ini sumber
                # access_hash yang valid untuk InputGroupCall saat warmup.
                access_hash = getattr(call_obj, "access_hash", None)
                if access_hash is not None:
                    _call_id_to_access_hash[call_obj.id] = access_hash
                print(
                    f"[UB-VC] Warmup: grup {chat_id} punya voice chat aktif "
                    f"(call_id={call_obj.id}, access_hash={'✅' if access_hash else '⚠️ tidak ada'})"
                )
        except FloodWait as fw:
            await asyncio.sleep(fw.value + 1)
        except Exception:
            pass
        await asyncio.sleep(2)


async def _leave_vc_for_group_direct(chat_id: int) -> None:
    """
    [INTERNAL] Paksa userbot keluar dari obrolan suara grup ini.
    Dipanggil HANYA oleh _vc_join_queue_worker — jangan panggil langsung.
    Gunakan _enqueue_vc_leave(chat_id) untuk antri permintaan leave.

    Menggunakan phone.LeaveGroupCall (MTProto raw API).
    Jika userbot tidak ada di VC, operasi ini aman (tidak error fatal).
    """
    if not userbot or not _ub_ready:
        return

    from pyrogram.raw import functions as _rf
    from pyrogram.raw.types import InputGroupCall

    try:
        chat_peer = await userbot.resolve_peer(chat_id)
        full = await userbot.invoke(_rf.channels.GetFullChannel(channel=chat_peer))
        call_obj = getattr(full.full_chat, "call", None)
        if not call_obj:
            # Tidak ada VC aktif di grup — tidak perlu leave
            print(f"[UB-VC-Leave] Grup {chat_id}: tidak ada VC aktif — skip leave.")
            return
        call_id     = call_obj.id
        access_hash = getattr(call_obj, "access_hash", None)
        if not access_hash:
            print(f"[UB-VC-Leave] Grup {chat_id}: access_hash tidak tersedia — skip leave.")
            return

        # Dapatkan call_id dari mapping
        _lv_call_id = None
        for _cid, _chid in list(_call_id_to_chat.items()):
            if _chid == chat_id:
                _lv_call_id = _cid
                break
        if _lv_call_id:
            from pyrogram.raw import functions as _rf_lv
            from pyrogram.raw.types import InputGroupCall as _IPC_lv
            _lv_ah = _call_id_to_access_hash.get(_lv_call_id)
            if _lv_ah:
                try:
                    await userbot.invoke(
                        _rf_lv.phone.LeaveGroupCall(
                            call=_IPC_lv(id=_lv_call_id, access_hash=_lv_ah),
                            source=0,
                        )
                    )
                except Exception:
                    pass
        _ub_in_vc_groups.discard(chat_id)
        print(f"[UB-VC-Leave] ✅ Userbot keluar dari VC grup {chat_id} (Security OS dinonaktifkan).")
    except FloodWait as fw:
        print(f"[UB-VC-Leave] FloodWait {fw.value}s saat leave VC grup {chat_id}.")
        await asyncio.sleep(fw.value + 1)
    except Exception as e:
        err_str = str(e).lower()
        if "not_in_call" in err_str or "not in call" in err_str:
            print(f"[UB-VC-Leave] Grup {chat_id}: userbot memang tidak di VC — OK.")
        else:
            print(f"[UB-VC-Leave] Grup {chat_id}: error leave VC — {e}")


async def _join_vc_for_group_direct(chat_id: int) -> None:
    """
    [INTERNAL] Dipanggil saat admin mengaktifkan Security OS.
    Dipanggil HANYA oleh _vc_join_queue_worker — jangan panggil langsung.
    Gunakan _enqueue_vc_join_now(chat_id) untuk antri permintaan join darurat.
    """
    if not userbot or not _ub_ready:
        return
    print(f"[UB-VC-Join] Security OS diaktifkan grup {chat_id} — jalankan siklus scan segera.")
    await _vc_scan_and_enforce(chat_id)


async def _leave_vc_for_group(chat_id: int) -> None:
    """
    Antri permintaan leave VC untuk grup ini ke _vc_join_queue_worker.
    Dieksekusi berurutan — tidak pernah bersamaan dengan join/leave grup lain.
    """
    _enqueue_vc_leave(chat_id)


async def _join_vc_for_group(chat_id: int) -> None:
    """
    Antri permintaan join/scan VC untuk grup ini ke _vc_join_queue_worker.
    Dieksekusi berurutan — tidak pernah bersamaan dengan join/leave grup lain.
    """
    _enqueue_vc_join_now(chat_id)


def _build_input_group_call(call_id: int):
    """
    Bangun InputGroupCall yang valid untuk raw API phone.EditGroupCallParticipant.

    UpdateGroupCallParticipants hanya membawa GroupCallReference (.id saja).
    phone.EditGroupCallParticipant WAJIB menerima InputGroupCall (.id + .access_hash).
    Tanpa access_hash yang benar, Telegram mengembalikan ACCESS_HASH_INVALID.

    access_hash di-cache dari UpdateGroupCall (saat VC mulai) dan dari
    GetFullChannel (saat warmup). Jika tidak ditemukan (cache miss), gunakan 0
    sebagai fallback — beberapa implementasi Pyrogram versi lama toleran terhadap
    ini, tapi idealnya selalu tersedia dari cache.
    """
    from pyrogram.raw.types import InputGroupCall
    access_hash = _call_id_to_access_hash.get(call_id, 0)
    if not access_hash:
        print(
            f"[UB-VC] ⚠️  access_hash untuk call_id={call_id} tidak ditemukan di cache. "
            "Pastikan UpdateGroupCall (VC start) diterima sebelum UpdateGroupCallParticipants."
        )
    return InputGroupCall(id=call_id, access_hash=access_hash)


async def _scan_active_groups() -> None:
    """Stub — arsitektur lama (polling). Tidak dipakai lagi."""
    pass


async def _check_one_group(sec_doc: dict) -> None:
    """Stub — arsitektur lama (polling). Tidak dipakai lagi."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# KOMUNIKASI USERBOT ↔ BOT PEMANTAU (DI DALAM GRUP)
#
# Mekanisme:
#   1. Userbot mengirim `/checkbio <user_id>` ke bot pemantau DI GRUP ITU SENDIRI
#      via pesan grup (mention bot pemantau agar hanya ia yang merespons)
#   2. Userbot memantau pesan baru di grup, menunggu jawaban dari bot pemantau
#   3. Bot pemantau menjawab: "HAS_LINK" atau "NO_LINK"
#   4. Userbot memproses jawaban
#
# Catatan keamanan:
#   - Pesan /checkbio dikirim sebagai pesan grup biasa (userbot sebagai member).
#   - Bot pemantau HARUS sudah join di grup itu agar bisa menerima & membalas.
#   - Jika bot pemantau tidak ada di grup, tidak ada jawaban → tidak ada eksekusi.
# ══════════════════════════════════════════════════════════════════════════════

async def _query_monitor_then_kick(
    chat_id: int,
    user_id: int,
    monitor_bot_id: int,
    call_input,
    is_muted: bool = False,
    muted_by_you: bool = False,
) -> None:
    """
    Perintahkan bot pemantau cek bio user → mute mic jika ada link, unmute jika bersih.

    ARSITEKTUR DB-DRIVEN (Security OS — BUKAN kick dari grup, hanya mute mic VC):
      Userbot memerintahkan bot pemantau (via force_check_vc_join) untuk
      fetch bio fresh dari Telegram API saat user naik ke voice chat.
      Hasilnya disimpan ke DB dan dikembalikan ke sini.

    Alur (sesuai 4 poin aturan moderasi mic VC):
      1. Tidak dikenali sama sekali / bukan member grup → mute mic langsung,
         terlepas ada link atau tidak (mengabaikan syarat bio).

      2. Member, TAPI bio tidak dapat dilihat bot pemantau — baik karena:
         - monitor_unavailable: bot pemantau grup ini BELUM TERDAFTAR di
           registry sama sekali, ATAU
         - has_link=None: bot pemantau AKTIF tapi gagal resolve bio user ini
           (peer tidak dikenal / privasi / semua fallback gagal)
         → dianggap AMAN: unmute mic jika sebelumnya di-mute userbot, skip
           (tidak ada tindakan) jika mic sudah unmuted.

      3. Member dengan link di bio (has_link=True) → mute mic (via _execute_kick).

      4. Member VIP → unmute tanpa syarat (ditangani VIP Guard di awal fungsi,
         sebelum poin 1-3 dievaluasi).

      has_link=False (bio bersih, berhasil dibaca, tidak ada link) → sama
      seperti poin 2: unmute mic jika sebelumnya di-mute userbot, abaikan jika
      muted oleh admin lain.

    Isolasi per grup: chat_id memastikan setiap grup hanya diperiksa
    oleh bot pemantau grup tersebut. Data grup A tidak mencemari grup B.

    BUG 2 FIX — Deteksi "siapa yang mute" dua lapis (dipakai untuk skenario
    monitor_unavailable dan has_link=False, BUKAN untuk has_link=None/stranger):
      1. muted_by_you (bool dari Telegram API GroupCallParticipant.muted_by_you)
         — field langsung dari Telegram, paling andal, tapi hanya ada saat scan/event
      2. _ub_muted_this_user (DB collection vc_muted_by_ub)
         — persisten antar siklus, backup jika field Telegram tidak tersedia
      Unmute dibolehkan jika SALAH SATU dari keduanya True.
      Jika admin lain yang mute (muted_by_you=False AND DB miss) → tidak di-unmute.
    """
    try:
        # ── VIP Guard: cek paling awal — sebelum non-member dan bio check ─────
        # User VIP (free_per_group) bebas dari aturan mute Security OS.
        # TAPI: jika VIP sedang/pernah di-mute oleh userbot (vc_muted_by_ub)
        # → unmute mic VIP tersebut.
        # Ini dipakai saat VIP kirim /unmutemic dan userbot naik VC untuk scan.
        #
        # FIX: jangan gate dengan `is_muted` (snapshot live can_self_unmute dari
        # Telegram) — field ini tidak selalu sinkron tepat setelah userbot baru
        # join VC, sehingga unmute bisa gagal terpicu meski DB sudah mencatat
        # bahwa userbot yang mute user ini. DB vc_muted_by_ub / muted_by_you
        # adalah sumber kebenaran yang lebih andal; is_muted hanya dipakai
        # sebagai info log, bukan syarat wajib.
        if await _is_vip_user(chat_id, user_id):
            was_ub_muted = muted_by_you or await _ub_muted_this_user(chat_id, user_id)
            if was_ub_muted:
                print(
                    f"[UB-VC] uid={user_id} grup={chat_id}: VIP + tercatat di-mute userbot "
                    f"(is_muted_live={is_muted}) → unmute mic VIP."
                )
                _enqueue_unmute_mic(chat_id, user_id, call_input, "VIP — mic diaktifkan kembali")
            elif is_muted:
                print(
                    f"[UB-VC] uid={user_id} grup={chat_id}: VIP muted oleh admin lain "
                    "→ tidak di-unmute userbot."
                )
            else:
                print(f"[UB-VC] uid={user_id} grup={chat_id}: VIP → skip semua cek Security OS.")
            _processing_kick.discard((chat_id, user_id))
            return

        # ── Perubahan 1: Non-member → mute mic langsung tanpa cek bio ────────
        # User yang bukan anggota grup tidak boleh di obrolan suara grup.
        # Mute dilakukan terlepas ada/tidaknya link di bio, lalu dicatat di DB.
        is_member = await _is_group_member(chat_id, user_id)
        if is_member is False:
            reason_nm = "non-member grup naik ke obrolan suara"
            print(
                f"[UB-VC] uid={user_id} grup={chat_id}: "
                f"non-member → mute mic langsung (tanpa cek bio)."
            )
            # Invalidasi cache member agar dicek ulang jika kondisi berubah
            _member_cache.pop((chat_id, user_id), None)
            await _execute_kick(
                chat_id, user_id, call_input,
                was_already_muted=is_muted,
                reason=reason_nm,
            )
            # Fitur 1: Catat ke secos_muted_users (TTL 30 detik)
            _secos_record_mute(chat_id, user_id, "non_member")
            # Fitur 2: Jadwalkan follow-up recheck 1 menit kemudian
            _secos_schedule_followup(chat_id, [(user_id, "non_member")])
            return

        has_link, monitor_unavailable = await _query_bio_from_db(chat_id, user_id)

        # Cache hanya hasil definitif True/False, dan HANYA jika benar-benar
        # hasil cek bio (bukan dari monitor_unavailable — itu bukan hasil cek,
        # harus selalu dicek ulang begitu bot pemantau terdaftar).
        if not monitor_unavailable:
            if has_link is True:
                _bio_cache[(chat_id, user_id)] = (True, time.monotonic())
            elif has_link is False:
                _bio_cache[(chat_id, user_id)] = (False, time.monotonic())

        if monitor_unavailable:
            # ── Skenario 1: bot pemantau grup ini BELUM TERDAFTAR di registry ──
            # Tidak ada cara untuk memverifikasi bio sama sekali — ini bukan
            # kesalahan/kecurigaan terhadap user, melainkan keterbatasan sistem.
            # Diperlakukan sebagai NO LINK (sama seperti bio bersih):
            #   mic muted (tercatat di-mute userbot) → unmute.
            #   mic sudah unmuted                    → skip, tidak ada tindakan.
            _processing_kick.discard((chat_id, user_id))
            was_ub_muted = muted_by_you or await _ub_muted_this_user(chat_id, user_id)
            if was_ub_muted:
                print(
                    f"[UB-VC] uid={user_id} grup={chat_id}: bio tidak tersedia dari bot "
                    f"pemantau (belum terdaftar) — dianggap no link → unmute mic."
                )
                _enqueue_unmute_mic(
                    chat_id, user_id, call_input,
                    "bio tidak tersedia dari bot pemantau — dianggap no link",
                )
            elif is_muted:
                print(
                    f"[UB-VC] uid={user_id} grup={chat_id}: muted oleh admin lain — "
                    "userbot tidak membuka mute mic (bot pemantau belum terdaftar)."
                )
            else:
                print(
                    f"[UB-VC] uid={user_id} grup={chat_id}: bio tidak tersedia dari bot "
                    f"pemantau (belum terdaftar) — dianggap no link, mic sudah unmuted, skip."
                )
                # Tidak di-mute live DAN tidak ada record DB → bersihkan
                # record stale jika ada.
                _safe_task(_remove_ub_muted(chat_id, user_id), tag="rm-muted-stale")
            return

        if has_link is True:
            await _execute_kick(
                chat_id, user_id, call_input,
                was_already_muted=is_muted,
                reason="bio mengandung link",
            )
            # has_link=True dari bot pemantau = bio berhasil dibaca & ada link.
            # Ini BUKAN peer_invalid — tidak perlu follow-up khusus.
        elif has_link is None:
            # ── Golongan 1: member TAPI benar-benar TIDAK DIKENALI bot
            # pemantau — semua fallback fetch bio gagal total (peer tidak
            # bisa di-resolve sama sekali). Ini BUKAN bio kosong/privasi
            # (itu Golongan 2, lihat has_link=False di bawah — _fetch_bio
            # mengembalikan string kosong "" untuk privasi/kosong, BUKAN None).
            # Golongan 1 → MUTE mic, mengabaikan status mute sebelumnya.
            print(
                f"[UB-VC] uid={user_id} grup={chat_id}: tidak dikenali sama sekali "
                f"oleh bot pemantau (semua fallback gagal resolve peer) → mute mic."
            )
            await _execute_kick(
                chat_id, user_id, call_input,
                was_already_muted=is_muted,
                reason="tidak dikenali bot pemantau (peer tidak dapat di-resolve)",
            )
            _secos_record_mute(chat_id, user_id, "peer_invalid")
            _secos_schedule_followup(chat_id, [(user_id, "peer_invalid")])
        else:
            # has_link = False → bio bersih, tidak ada link
            _processing_kick.discard((chat_id, user_id))

            # FIX: jangan gate cek unmute dengan `is_muted` (snapshot live
            # can_self_unmute dari Telegram) — field ini tidak selalu sinkron
            # tepat setelah userbot baru join VC, sehingga unmute via
            # /unmutemic bisa gagal terpicu meski DB vc_muted_by_ub sudah
            # mencatat userbot yang mute user ini. Cek DB/muted_by_you dulu
            # sebagai sumber kebenaran utama; is_muted hanya info pendukung.
            was_ub_muted = muted_by_you or await _ub_muted_this_user(chat_id, user_id)
            if was_ub_muted:
                src_label = "Telegram API" if muted_by_you else "DB record"
                print(
                    f"[UB-Unmute] uid={user_id} grup={chat_id}: "
                    f"bio bersih ({src_label}, is_muted_live={is_muted}) → antri unmute mic ke worker."
                )
                # Antri unmute ke worker (bukan panggil langsung — aman API per grup)
                _enqueue_unmute_mic(chat_id, user_id, call_input, "bio bersih")
            elif is_muted:
                print(
                    f"[UB-Unmute] uid={user_id} grup={chat_id}: "
                    "muted oleh admin lain — userbot tidak membuka mute mic"
                )
            else:
                # Tidak di-mute live DAN tidak ada record DB → bersihkan
                # record stale jika ada (misal: admin sudah unmute duluan,
                # record userbot belum terhapus).
                _safe_task(_remove_ub_muted(chat_id, user_id), tag="rm-muted-stale")

    except Exception as e:
        print(f"[UB-Query] Error uid={user_id} chat={chat_id}: {e}")
        _processing_kick.discard((chat_id, user_id))


async def _query_bio_from_db(chat_id: int, user_id: int) -> tuple[bool | None, bool]:
    """
    Perintahkan bot pemantau cek bio user secara fresh saat naik ke VC.

    ALUR:
      Selalu panggil force_check_vc_join() → bot pemantau fetch bio fresh
      dari Telegram API → simpan ke DB → kembalikan hasilnya.

      force_check_vc_join sudah punya cache internal 60 detik (VC_JOIN_RECHECK_SECS):
        • Jika user naik VC lagi dalam 60 detik → pakai cache, tidak spam API.
        • Setelah 60 detik → fetch fresh dari Telegram API.

      Data lama di DB TIDAK dipakai langsung — userbot selalu tunggu konfirmasi
      fresh dari bot pemantau sebelum memutuskan mute/unmute.

    Return: (has_link, monitor_unavailable)
      has_link:
        True  → ada link di bio (data fresh dari bot pemantau)
        False → tidak ada link di bio (data fresh dari bot pemantau), ATAU
                 bot pemantau grup ini belum terdaftar (lihat monitor_unavailable
                 — has_link dipaksa False sebagai default aman)
        None  → bot pemantau AKTIF tapi gagal resolve peer user ini sepenuhnya
                 (semua fallback gagal / peer belum dikenal bot / belum ada
                 di DB / FloodWait) → TIDAK bertindak seolah no-link, dianggap
                 orang asing oleh pemanggil.
      monitor_unavailable:
        True  → instance bot pemantau untuk grup ini TIDAK ADA sama sekali di
                 registry (belum terdaftar / belum disetup) — ini keterbatasan
                 sistem, bukan kesalahan/kecurigaan terhadap user.
        False → instance ada (baik berhasil fetch atau gagal resolve peer).
    """
    from monitor_bot_reference import force_check_vc_join, _active_instances
    # FIX 5: Isolasi per grup — HANYA gunakan bot pemantau milik chat_id ini.
    # force_check_vc_join(chat_id, user_id) membaca _active_instances[chat_id],
    # sehingga data grup A tidak pernah dicek oleh bot pemantau grup B.
    instance = _active_instances.get(chat_id)
    if instance is None:
        print(
            f"[UB-Bio] chat={chat_id} uid={user_id} "
            "bio tidak tersedia dari bot pemantau (belum terdaftar di registry) "
            "— dianggap no link"
        )
        return False, True
    # ── Instance ada → minta fresh check dari bot pemantau GRUP INI saja ─────
    result = await force_check_vc_join(chat_id, user_id)
    if result is None:
        # None dari force_check_vc_join = bot AKTIF tapi bio tidak tersedia
        # (semua fallback gagal / peer belum dikenal bot / belum ada di DB /
        # FloodWait). Ini BUKAN "instance mati" — jangan log menyesatkan.
        print(
            f"[UB-Bio] chat={chat_id} uid={user_id} "
            "bio tidak tersedia (peer belum dikenal bot / belum ada di DB) — skip"
        )
    else:
        print(
            f"[UB-Bio] chat={chat_id} uid={user_id} "
            f"has_link={result} (fresh dari bot pemantau)"
        )
    return result, False


# ── _get_monitor_username dipertahankan untuk kebutuhan setup_monitor_bot ─────
# (tidak dipakai lagi untuk checkbio, tapi masih dipakai di panel Security OS)

# ══════════════════════════════════════════════════════════════════════════════
# SECOS MUTE HELPERS — Fitur 1: Pencatatan & pembacaan mute khusus keamanan
# ══════════════════════════════════════════════════════════════════════════════

def _secos_record_mute(chat_id: int, user_id: int, reason_type: str) -> None:
    """
    Catat mute Security OS khusus ke cache 30 detik.

    reason_type:
      "non_member"   — user bukan anggota grup tapi naik VC
      "peer_invalid" — user member grup tapi bot pemantau gagal fetch bio
                       (user belum pernah berinteraksi di grup → PeerIdInvalid)

    Hanya dua kondisi ini yang memicu follow-up recheck (Fitur 2 & 3).
    Mute biasa karena has_link=True TIDAK dicatat di sini.
    """
    _secos_muted_users[(chat_id, user_id)] = (reason_type, time.monotonic())
    print(
        f"[SecOS-Mute] uid={user_id} grup={chat_id}: "
        f"dicatat sebagai '{reason_type}' (TTL {_SECOS_MUTE_CACHE_TTL:.0f}s)"
    )


def _secos_get_mute_reason(chat_id: int, user_id: int) -> str | None:
    """
    Cek apakah user masih tercatat dalam mute Security OS (dalam 30 detik).

    Return:
      "non_member" | "peer_invalid" — jika masih dalam TTL 30 detik
      None                          — jika sudah lewat 30 detik atau tidak ada
    """
    entry = _secos_muted_users.get((chat_id, user_id))
    if entry is None:
        return None
    reason_type, ts = entry
    if time.monotonic() - ts <= _SECOS_MUTE_CACHE_TTL:
        return reason_type
    # Expired — hapus otomatis
    _secos_muted_users.pop((chat_id, user_id), None)
    return None


def _secos_clear_mute(chat_id: int, user_id: int) -> None:
    """Hapus catatan mute Security OS untuk user ini (status sudah berubah jadi valid)."""
    _secos_muted_users.pop((chat_id, user_id), None)


# ══════════════════════════════════════════════════════════════════════════════
# SECOS FOLLOW-UP RECHECK — Fitur 2, 3, 4
# ══════════════════════════════════════════════════════════════════════════════

async def _secos_followup_recheck(chat_id: int, muted_users: list[tuple[int, str]]) -> None:
    """
    Follow-up recheck Security OS setelah mute non-member atau peer-invalid.

    Fitur 2: Tunggu 1 menit → naik VC cek ulang (di luar jadwal 30 menit rutin).
    Fitur 3: Jika user yang sama masih belum valid → tunggu 5 menit → naik lagi.
    Fitur 4: Setelah itu kembali ke jadwal 30 menit normal (tidak perlu aksi,
             _vc_scheduled_loop tetap berjalan sendiri).

    muted_users: list of (user_id, reason_type) yang baru di-mute
    """
    if not userbot or not _ub_ready:
        _secos_followup_tasks.pop(chat_id, None)
        return

    print(
        f"[SecOS-FollowUp] Grup {chat_id}: menunggu 1 menit sebelum cek ulang "
        f"({len(muted_users)} user: {[u for u, _ in muted_users]})"
    )

    # ── Fitur 2: Tunggu 1 menit ──────────────────────────────────────────────
    await asyncio.sleep(60)

    if not userbot or not _ub_ready:
        _secos_followup_tasks.pop(chat_id, None)
        return

    sec_doc = await _sec_os_get(chat_id)
    if not sec_doc.get("enabled"):
        _secos_followup_tasks.pop(chat_id, None)
        return

    print(f"[SecOS-FollowUp] Grup {chat_id}: 1 menit berlalu — antri scan VC ke worker.")

    # Invalidasi cache member & bio semua user yang di-mute agar cek fresh
    for uid, _ in muted_users:
        _member_cache.pop((chat_id, uid), None)
        _bio_cache.pop((chat_id, uid), None)

    # Antri scan ke worker (bukan langsung — aman API, tidak bentrok dengan siklus lain)
    _enqueue_vc_scan(chat_id)
    # Tunggu sebentar agar worker sempat proses scan sebelum kita cek hasilnya
    await asyncio.sleep(_VC_WORKER_JOIN_DELAY + _VC_SCAN_DURATION + 15)   # jeda join + estimasi durasi scan + buffer

    # ── Periksa siapa yang masih belum valid setelah cek 1 menit ─────────────
    # Catatan: hanya reason_type "non_member" yang bisa masuk sini sekarang.
    # "peer_invalid" tidak lagi di-mute (lihat poin 2 spek moderasi mic VC —
    # member dengan bio tidak terbaca dianggap aman/unmute), sehingga tidak
    # pernah lagi tercatat via _secos_record_mute dengan reason ini.
    still_invalid: list[tuple[int, str]] = []
    for uid, reason_type in muted_users:
        if reason_type == "non_member":
            # Cek apakah sudah bergabung jadi member
            is_mem = await _is_group_member(chat_id, uid)
            if is_mem is True:
                print(f"[SecOS-FollowUp] uid={uid} grup={chat_id}: sudah jadi member ✓ — clear.")
                _secos_clear_mute(chat_id, uid)
            else:
                still_invalid.append((uid, reason_type))
                print(f"[SecOS-FollowUp] uid={uid} grup={chat_id}: masih non-member setelah 1 menit.")

    if not still_invalid:
        print(
            f"[SecOS-FollowUp] Grup {chat_id}: semua user sudah valid — "
            f"kembali ke jadwal 30 menit normal. ✓"
        )
        _secos_followup_tasks.pop(chat_id, None)
        return

    # ── Fitur 3: Ada yang masih invalid → tunggu 5 menit, naik lagi ─────────
    print(
        f"[SecOS-FollowUp] Grup {chat_id}: {len(still_invalid)} user masih invalid "
        f"({[u for u, _ in still_invalid]}) — menunggu 5 menit sebelum cek terakhir."
    )
    await asyncio.sleep(5 * 60)

    if not userbot or not _ub_ready:
        _secos_followup_tasks.pop(chat_id, None)
        return

    sec_doc = await _sec_os_get(chat_id)
    if not sec_doc.get("enabled"):
        _secos_followup_tasks.pop(chat_id, None)
        return

    print(f"[SecOS-FollowUp] Grup {chat_id}: 5 menit berlalu — antri scan VC terakhir ke worker.")

    # Invalidasi cache lagi sebelum scan ulang
    for uid, _ in still_invalid:
        _member_cache.pop((chat_id, uid), None)
        _bio_cache.pop((chat_id, uid), None)

    # Antri scan ke worker untuk cek terakhir
    _enqueue_vc_scan(chat_id)
    # Tunggu agar worker sempat proses sebelum follow-up task selesai
    await asyncio.sleep(_VC_WORKER_JOIN_DELAY + _VC_SCAN_DURATION + 15)   # jeda join + estimasi durasi scan + buffer

    # ── Fitur 4: Selesai — kembali ke jadwal 30 menit normal ─────────────────
    # _vc_scheduled_loop tetap berjalan sendiri, tidak perlu tindakan tambahan.
    print(
        f"[SecOS-FollowUp] Grup {chat_id}: follow-up selesai — "
        f"kembali ke jadwal 30 menit normal. ✓"
    )
    _secos_followup_tasks.pop(chat_id, None)


def _secos_schedule_followup(chat_id: int, muted_users: list[tuple[int, str]]) -> None:
    """
    Jadwalkan follow-up recheck Security OS untuk grup ini.

    Jika sudah ada follow-up task yang aktif untuk grup ini, tambahkan
    user baru ke dalam follow-up yang sudah berjalan dengan meluncurkan
    task terpisah (karena task yang berjalan sudah punya snapshot muted_users-nya).

    Dalam praktik, skenario overlap sangat jarang (mute terjadi dalam hitungan
    detik satu sama lain). Task lama yang sudah sleep(60) tidak terpengaruh.

    muted_users: list of (user_id, reason_type) yang baru di-mute
    """
    if not muted_users:
        return

    existing = _secos_followup_tasks.get(chat_id)
    if existing and not existing.done():
        # Sudah ada follow-up berjalan — spawn task terpisah untuk batch baru
        # agar tidak kehilangan user yang di-mute belakangan
        print(
            f"[SecOS-FollowUp] Grup {chat_id}: sudah ada follow-up berjalan, "
            f"spawn task tambahan untuk {[u for u, _ in muted_users]}."
        )
        _safe_task(
            _secos_followup_recheck(chat_id, muted_users),
            tag=f"secos-followup-extra-{chat_id}",
        )
        return

    task = _safe_task(
        _secos_followup_recheck(chat_id, muted_users),
        tag=f"secos-followup-{chat_id}",
    )
    _secos_followup_tasks[chat_id] = task
    print(
        f"[SecOS-FollowUp] Grup {chat_id}: follow-up task di-spawn untuk "
        f"{len(muted_users)} user ({[u for u, _ in muted_users]})."
    )


_monitor_username_cache: dict[int, str] = {}


# ══════════════════════════════════════════════════════════════════════════════
# LOG OS — kirim log mute/unmute userbot ke channel khusus LOG_OS
# ══════════════════════════════════════════════════════════════════════════════

async def _log_os_action(chat_id: int, user_id: int, action: str, reason: str) -> None:
    """
    Kirim log tindakan userbot (mute/unmute mic) ke channel LOG_OS.

    action : label singkat, contoh "MUTE-MIC" atau "UNMUTE-MIC"
    reason : keterangan detail, contoh "bio mengandung link" atau "non-member grup"
    """
    if not LOG_OS or not _bot_ref:
        return
    try:
        name  = str(user_id)
        uname = f"id:{user_id}"
        try:
            u = await _bot_ref.get_users(user_id)
            name  = u.first_name or str(user_id)
            uname = f"@{u.username}" if u.username else f"id:{user_id}"
        except Exception:
            pass

        icon   = "🔇" if "MUTE" in action.upper() and "UNMUTE" not in action.upper() else "🔊"
        waktu  = _dt_vc.now(_WIB_VC).strftime("%H:%M:%S · %d %b %Y WIB")
        text = (
            f"{icon} <b>Security OS — {action}</b>\n"
            f"<code>Grup : {chat_id}</code>\n"
            f"👤 {name} (<code>{user_id}</code>) {uname}\n"
            f"📌 Alasan : {reason}\n"
            f"🕐 {waktu}"
        )
        await _bot_ref.send_message(LOG_OS, text, parse_mode=ParseMode.HTML)
    except FloodWait as fw:
        await asyncio.sleep(fw.value + 1)
    except Exception as e:
        print(f"[UB-LogOS] Gagal kirim log ke LOG_OS: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CEK KEANGGOTAAN GRUP — untuk mute non-member di obrolan suara
# ══════════════════════════════════════════════════════════════════════════════

async def _is_group_member(chat_id: int, user_id: int) -> bool | None:
    """
    Cek apakah user adalah anggota grup.

    Return:
      True  → user adalah anggota grup (owner/admin/member/restricted)
      False → user bukan anggota (LEFT/BANNED atau UserNotParticipant)
      None  → tidak bisa menentukan (error lain, FloodWait, dsb)

    Hasil di-cache 2 menit.
    API call di-throttle via _get_api_semaphore() agar aman di banyak grup.
    """
    if not userbot:
        return None

    key = (chat_id, user_id)
    cached = _member_cache.get(key)
    if cached:
        is_mem, ts = cached
        if time.monotonic() - ts < _MEMBER_CACHE_TTL:
            return is_mem

    # Gunakan semaphore global untuk batasi concurrent API call (maks 3 paralel)
    sem = _get_api_semaphore()
    try:
        from pyrogram.enums import ChatMemberStatus
        async with sem:
            member = await userbot.get_chat_member(chat_id, user_id)
        is_member = member.status not in (
            ChatMemberStatus.BANNED,
            ChatMemberStatus.LEFT,
        )
        _member_cache[key] = (is_member, time.monotonic())
        return is_member
    except FloodWait as fw:
        wait = fw.value + 1
        print(f"[UB-Member] FloodWait {fw.value}s saat cek member uid={user_id} grup={chat_id} — tunggu {wait}s")
        await asyncio.sleep(wait)
        return None   # Tidak retry — caller akan skip atau cek ulang di siklus berikutnya
    except Exception as e:
        err = str(e).lower()
        if "user_not_participant" in err or "not_participant" in err or "member_not_found" in err:
            _member_cache[key] = (False, time.monotonic())
            return False
        # Error lain (peer tidak dikenal, dsb) → tidak bisa menentukan
        return None


async def _is_vip_user(chat_id: int, user_id: int) -> bool:
    """
    Cek apakah user adalah Member VIP di grup ini.

    VIP = ada di colle
