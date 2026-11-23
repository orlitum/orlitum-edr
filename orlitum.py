#!/usr/bin/env python3
# Copyright (c) 2026 Orlitum EDR <zxclow663@gmail.com>
__author__ = "Orlitum EDR <zxclow663@gmail.com>"
"""
Orlitum EDR Community Edition
"""

import os
import re
import io
import csv
import sys
import pwd
import ssl
import hmac
import gzip
import time
import ctypes
import ctypes.util
import shutil
import secrets
import getpass
import hashlib
import resource
import argparse
import json
import math
import mmap
import subprocess
import threading
import signal
import sqlite3
import urllib.request
import urllib.parse
from itertools import islice
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_BOLD = "\033[1m"
CLR_RESET = "\033[0m"

_START_TIME = time.time()
_MLOCKED_BUFFERS = []

WHITELIST_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".cargo", "target", "projects", "проекты"
}

TRUSTED_SYSTEM_PREFIXES = (
    "/bin/", "/usr/", "/sbin/", "/lib/", "/lib64/",
    "/opt/", "/etc/", "/boot/", "/proc/", "/sys/", "/dev/", "/var/lib/edr-guard/"
)

INTERPRETER_REGEX = re.compile(
    r"^(sh|bash|dash|zsh|python\d*(\.\d+)?|perl|php\d*(\.\d+)?|ruby|node|nodejs|deno|bun)$"
)

SUSPICIOUS_TMP_EXEC_REGEX = re.compile(
    r"(/tmp/|/var/tmp/|/dev/shm/)[^\s#;\"']*\.(sh|py|elf|bin|pl|php)|"
    r"(?:sh|bash|python\d*|perl|nohup|chmod\s+\+x)\s+.*(?:/tmp/|/var/tmp/|/dev/shm/)"
)

SKIPPED_VERDICTS = {
    "Ignored",
    "Ignored Internal File",
    "Temporary File",
    "Whitelisted Directory",
    "Skipped (Not a regular file)",
    "Skipped (Size)",
    "Access Denied"
}

_NOTIFY_CACHE = {}
_NOTIFY_LOCK = threading.Lock()
_LAST_CACHE_CLEANUP = 0.0

_TG_LOCK = threading.Lock()
_TG_LAST_SENT = 0.0

_TG_CONFIG = {
    "token": os.environ.get("EDR_TG_TOKEN", ""),
    "chat_id": os.environ.get("EDR_TG_CHAT_ID", ""),
    "healthcheck_url": os.environ.get("EDR_HEALTHCHECK_URL", "")
}


def harden_process_memory():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass

    try:
        libc_name = ctypes.util.find_library("c")
        if libc_name:
            libc = ctypes.CDLL(libc_name, use_errno=True)
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        pass


def mlock_bytes(data: bytes) -> bool:
    if not isinstance(data, (bytes, bytearray)) or not data:
        return False
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        addr = ctypes.addressof(buf)
        if libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(data))) == 0:
            libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(len(data)), ctypes.c_int(16))
            _MLOCKED_BUFFERS.append(buf)
            return True
    except Exception:
        pass
    return False


def is_being_traced() -> bool:
    try:
        with open("/proc/self/status", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) > 0
    except Exception:
        pass
    return False


class PinCryptoVault:
    ITERATIONS = 600_000

    @staticmethod
    def _derive_key(pin: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, PinCryptoVault.ITERATIONS, dklen=32)

    @staticmethod
    def _keystream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
        out = bytearray(len(data))
        counter = 0
        idx = 0
        while idx < len(data):
            counter_bytes = counter.to_bytes(8, "big")
            block_key = hashlib.sha256(key + nonce + counter_bytes).digest()
            chunk_len = min(len(data) - idx, len(block_key))
            for i in range(chunk_len):
                out[idx + i] = data[idx + i] ^ block_key[i]
            idx += chunk_len
            counter += 1
        return bytes(out)

    @classmethod
    def encrypt_blob(cls, plaintext: bytes, pin: str) -> bytes:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(16)
        master_key = cls._derive_key(pin, salt)
        enc_key = hashlib.sha256(master_key + b":enc").digest()
        mac_key = hashlib.sha256(master_key + b":mac").digest()

        ciphertext = cls._keystream_xor(plaintext, enc_key, nonce)
        tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        return salt + nonce + tag + ciphertext

    @classmethod
    def decrypt_blob(cls, blob: bytes, pin: str):
        if len(blob) < 64:
            return None
        salt = blob[:16]
        nonce = blob[16:32]
        tag = blob[32:64]
        ciphertext = blob[64:]

        master_key = cls._derive_key(pin, salt)
        enc_key = hashlib.sha256(master_key + b":enc").digest()
        mac_key = hashlib.sha256(master_key + b":mac").digest()

        expected_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            return None
        return cls._keystream_xor(ciphertext, enc_key, nonce)

    @classmethod
    def get_pin_file(cls, base_dir: str) -> str:
        return os.path.join(base_dir, "pin.vault")

    @classmethod
    def setup_pin(cls, base_dir: str, secret_payload: bytes = b"EDR_PIN_VALIDATED_V3.2") -> bool:
        if is_being_traced():
            print(f"{CLR_RED}[✖] БЛОКИРОВКА: Обнаружен отладчик (TracerPid != 0). Ввод PIN отменен.{CLR_RESET}")
            return False

        pin_file = cls.get_pin_file(base_dir)
        if os.path.exists(pin_file):
            print(f"{CLR_YELLOW}[*] Для смены существующего PIN подтвердите текущий PIN:{CLR_RESET}")
            if not cls.verify_pin(base_dir):
                return False

        print(f"\n{CLR_BOLD}=== УСТАНОВКА ЗАЩИТНОГО PIN-КОДА EDR (PBKDF2-SHA256) ==={CLR_RESET}")
        try:
            pin1 = getpass.getpass("Придумайте PIN (минимум 6 символов): ")
            pin2 = getpass.getpass("Повторите PIN: ")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Отменено.")
            return False

        if pin1 != pin2:
            print(f"{CLR_RED}[✖] PIN-коды не совпадают.{CLR_RESET}")
            return False
        if len(pin1) < 6:
            print(f"{CLR_RED}[✖] PIN должен содержать не менее 6 символов.{CLR_RESET}")
            return False

        os.makedirs(base_dir, exist_ok=True)
        encrypted_vault = cls.encrypt_blob(secret_payload, pin1)
        with open(pin_file, "wb") as f:
            f.write(encrypted_vault)
        try:
            os.chmod(pin_file, 0o600)
        except OSError:
            pass
        print(f"{CLR_GREEN}[✔] PIN-код успешно зашифрован и сохранен в {pin_file}{CLR_RESET}\n")
        return True

    @classmethod
    def verify_pin(cls, base_dir: str, max_attempts: int = 3) -> bool:
        if is_being_traced():
            print(f"{CLR_RED}[✖] БЛОКИРОВКА БЕЗОПАСНОСТИ: Обнаружена трассировка процесса (strace/ptrace)!{CLR_RESET}")
            send_telegram_alert("🚨 EDR Security Alert", "Попытка перехвата PIN через ptrace/strace!")
            return False

        pin_file = cls.get_pin_file(base_dir)
        if not os.path.exists(pin_file):
            print(f"{CLR_YELLOW}[i] Защитный PIN еще не установлен (рекомендуется: --setup-pin).{CLR_RESET}")
            return True

        try:
            with open(pin_file, "rb") as f:
                blob = f.read()
        except OSError as e:
            print(f"{CLR_RED}[!] Ошибка чтения файла PIN: {e}{CLR_RESET}")
            return False

        for attempt in range(1, max_attempts + 1):
            try:
                pin = getpass.getpass(f"🔐 Введите защитный PIN EDR ({attempt}/{max_attempts}): ")
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Ввод прерван.")
                return False

            decrypted = cls.decrypt_blob(blob, pin)
            if decrypted is not None:
                print(f"{CLR_GREEN}[✔] PIN подтвержден. Доступ разрешен.{CLR_RESET}")
                return True

            print(f"{CLR_RED}[✖] Неверный PIN-код!{CLR_RESET}")
            if attempt < max_attempts:
                time.sleep(2 ** attempt)

        msg = f"Превышено число попыток ввода PIN ({max_attempts} неудачных попыток)!"
        print(f"{CLR_RED}{CLR_BOLD}[✖] {msg}{CLR_RESET}")
        send_desktop_notification("🚨 EDR Ошибка PIN", msg)
        return False


def set_immutable_flag(path: str, enable: bool = True) -> bool:
    if not os.path.exists(path):
        return False
    flag = "+i" if enable else "-i"
    try:
        res = subprocess.run(
            ["chattr", flag, path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return res.returncode == 0
    except (FileNotFoundError, PermissionError):
        return False


def manage_agent_immutable_protection(base_dir: str, enable: bool = True):
    action_title = "ВКЛЮЧЕНИЕ ЗАЩИТЫ CHATTR +I" if enable else "СНЯТИЕ ЗАЩИТЫ CHATTR -I"
    print(f"\n{CLR_BOLD}=== {action_title} ==={CLR_RESET}")
    targets = [
        os.path.realpath(__file__),
        os.path.join(base_dir, "secret.key"),
        os.path.join(base_dir, "pin.vault"),
        os.path.join(base_dir, "agent_self.sha256"),
        "/etc/systemd/system/orlitum.service",
        os.path.join(get_real_user_home(), ".config/systemd/user/orlitum.service")
    ]
    count = 0
    for t in targets:
        if os.path.exists(t):
            if set_immutable_flag(t, enable=enable):
                count += 1
                state_str = "заблокирован (chattr +i)" if enable else "разблокирован (chattr -i)"
                print(f"  {CLR_GREEN}[✔] {t} -> {state_str}{CLR_RESET}")
    print(f"{CLR_GREEN}[✔] Обработано защищенных файлов: {count}{CLR_RESET}\n")


def get_real_user_home():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def get_default_base_dir():
    user_base = os.environ.get("ORLITUM_HOME") or (os.path.dirname(os.path.dirname(os.path.abspath(__file__))) if os.path.basename(os.path.dirname(os.path.abspath(__file__))) == "core" else os.path.dirname(os.path.abspath(__file__)))
    if os.geteuid() == 0 and os.environ.get("EDR_SYSTEM_MODE") == "1":
        base = "/var/lib/edr-guard"
        os.makedirs(base, mode=0o700, exist_ok=True)
        try:
            return base
        except Exception:
            pass
    return user_base


def send_telegram_alert(title, message, silent=False):
    token = _TG_CONFIG.get("token")
    chat_id = _TG_CONFIG.get("chat_id")
    if not token or not chat_id:
        return

    global _TG_LAST_SENT
    now = time.time()
    with _TG_LOCK:
        if now - _TG_LAST_SENT < 1.0:
            return
        _TG_LAST_SENT = now

    def _send():
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = urllib.parse.urlencode({
                "chat_id": chat_id,
                "text": (f"🛡 *{title}*\n"
                         f"{message}"),
                "parse_mode": "Markdown",
                "disable_notification": "true" if silent else "false"
            }).encode("utf-8")
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, data=payload, headers={"User-Agent": "Orlitum-EDR-Community/1.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                response.read()
        except Exception:
            pass

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def send_heartbeat():
    hostname = os.uname().nodename
    uptime_min = int((time.time() - _START_TIME) // 60)
    send_telegram_alert("💚 EDR Heartbeat", f"Хост: `{hostname}`\nСтатус: Активен\nАптайм: {uptime_min} мин.", silent=True)

    hc_url = _TG_CONFIG.get("healthcheck_url")
    if hc_url and hc_url.startswith(("https://", "http://")):
        def _ping():
            try:
                ctx = ssl.create_default_context()
                req = urllib.request.Request(hc_url, headers={"User-Agent": "Orlitum-EDR-Community/1.0"})
                with urllib.request.urlopen(req, timeout=10, context=ctx):
                    pass
            except Exception:
                pass
        threading.Thread(target=_ping, daemon=True).start()


def send_desktop_notification(title, message, icon=None):
    send_telegram_alert(title, message)
    cmd = ["notify-send", "-u", "critical"]
    if icon:
        cmd.extend(["-i", icon])
    cmd.extend([title, message])

    sudo_user = os.environ.get("SUDO_USER")
    sudo_uid = os.environ.get("SUDO_UID")
    try:
        if os.geteuid() == 0 and sudo_user and sudo_uid:
            bus_path = f"unix:path=/run/user/{sudo_uid}/bus"
            sudo_cmd = [
                "sudo", "-u", sudo_user,
                f"DBUS_SESSION_BUS_ADDRESS={bus_path}",
                "DISPLAY=:0"
            ] + cmd
            subprocess.run(sudo_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        sys.stderr.write(f"[!] Ошибка отправки уведомления: {e}\n")


def notify_throttled(key, title, message, icon=None, cooldown=600, max_cache_age=3600):
    global _LAST_CACHE_CLEANUP
    now = time.time()
    with _NOTIFY_LOCK:
        if now - _LAST_CACHE_CLEANUP > 60 or len(_NOTIFY_CACHE) > 500:
            stale = [k for k, t in _NOTIFY_CACHE.items() if now - t > max_cache_age]
            for k in stale:
                del _NOTIFY_CACHE[k]
            if len(_NOTIFY_CACHE) > 1000:
                oldest_keys = list(islice(_NOTIFY_CACHE.keys(), 500))
                for k in oldest_keys:
                    del _NOTIFY_CACHE[k]
            _LAST_CACHE_CLEANUP = now

        last_time = _NOTIFY_CACHE.get(key, 0)
        if now - last_time < cooldown:
            return
        _NOTIFY_CACHE.pop(key, None)
        _NOTIFY_CACHE[key] = now
    send_desktop_notification(title, message, icon=icon)


def is_subpath(path, parent):
    try:
        real_path = os.path.realpath(path)
        real_parent = os.path.realpath(parent)
        return os.path.commonpath([real_path, real_parent]) == real_parent
    except ValueError:
        return False


def is_interpreter_binary(exe_name):
    clean_name = os.path.basename(exe_name).replace(" (deleted)", "")
    return bool(INTERPRETER_REGEX.match(clean_name))


class CacheDB:
    def __init__(self, db_path):
        self.db_path = os.path.abspath(db_path)
        db_dir = os.path.dirname(self.db_path)
        self.intel_db_path = os.path.join(db_dir or ".", "threat_intel.db")
        self._local = threading.local()
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.secret_key = self._load_or_create_hmac_key(db_dir or ".")
        if self.secret_key:
            mlock_bytes(self.secret_key)
        self._init_db()

    def _load_or_create_hmac_key(self, base_dir):
        key_path = os.path.join(base_dir, "secret.key")
        try:
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read()
                if len(key) >= 32:
                    return key
            key = secrets.token_bytes(32)
            with open(key_path, "wb") as f:
                f.write(key)
            os.chmod(key_path, 0o600)
            sudo_uid = os.environ.get("SUDO_UID")
            sudo_gid = os.environ.get("SUDO_GID")
            if os.geteuid() == 0 and sudo_uid and sudo_gid and base_dir.startswith("/home/"):
                os.chown(key_path, int(sudo_uid), int(sudo_gid))
            return key
        except OSError as e:
            sys.stderr.write(f"[!] ВНИМАНИЕ: Нет доступа к {key_path} ({e}). Проверка HMAC пропущена.\n")
            return None

    def compute_hmac(self, binary_path, sha256_hash):
        if not self.secret_key:
            return None
        msg = f"{binary_path}:{sha256_hash}".encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_cache (
                file_path TEXT PRIMARY KEY,
                mtime REAL,
                size INTEGER,
                sha256 TEXT,
                verdict TEXT,
                alerts TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS integrity_baseline (
                binary_path TEXT PRIMARY KEY,
                sha256 TEXT,
                hmac_sig TEXT,
                recorded_at TEXT
            )
        """)
        try:
            conn.execute("ALTER TABLE integrity_baseline ADD COLUMN hmac_sig TEXT;")
        except sqlite3.OperationalError:
            pass

            conn.commit()
        with sqlite3.connect(self.intel_db_path, timeout=10.0) as iconn:
            iconn.execute("PRAGMA journal_mode=WAL;")
            iconn.execute("CREATE TABLE IF NOT EXISTS known_threats (sha256 TEXT PRIMARY KEY, malware_family TEXT)")
            iconn.commit()

        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if os.geteuid() == 0 and sudo_uid and sudo_gid and self.db_path.startswith("/home/"):
            for suffix in ("", "-wal", "-shm"):
                p = self.db_path + suffix
                if os.path.exists(p):
                    try:
                        os.chown(p, int(sudo_uid), int(sudo_gid))
                    except OSError:
                        pass

    def check_known_threat(self, sha256_hash, timeout=10.0):
        try:
            with sqlite3.connect(f'file:{self.intel_db_path}?mode=ro', uri=True, timeout=timeout) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT malware_family FROM known_threats WHERE sha256 = ?", (sha256_hash,))
                row = cursor.fetchone()
                if row:
                    return row[0]
        except sqlite3.Error:
            pass
        return None

    def get(self, file_path, current_mtime, current_size, timeout=10.0):
        try:
            with sqlite3.connect(self.db_path, timeout=timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT sha256, verdict, alerts FROM file_cache WHERE file_path = ? AND mtime = ? AND size = ?",
                    (file_path, current_mtime, current_size)
                )
                row = cursor.fetchone()
                if row:
                    return {"sha256": row[0], "verdict": row[1], "alerts": json.loads(row[2])}
        except (sqlite3.Error, json.JSONDecodeError, TypeError):
            return None
        return None

    def set(self, file_path, mtime, size, sha256, verdict, alerts, timeout=10.0):
        try:
            with sqlite3.connect(self.db_path, timeout=timeout) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO file_cache (file_path, mtime, size, sha256, verdict, alerts) VALUES (?, ?, ?, ?, ?, ?)",
                    (file_path, mtime, size, sha256, verdict, json.dumps(alerts, ensure_ascii=False))
                )
                conn.commit()
        except sqlite3.Error:
            pass

    def update_baseline(self, binary_path, sha256_hash, timeout=10.0):
        sig = self.compute_hmac(binary_path, sha256_hash) or ""
        with sqlite3.connect(self.db_path, timeout=timeout) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO integrity_baseline (binary_path, sha256, hmac_sig, recorded_at) VALUES (?, ?, ?, ?)",
                (binary_path, sha256_hash, sig, time.strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()

    def get_baseline(self, timeout=10.0):
        try:
            with sqlite3.connect(self.db_path, timeout=timeout) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT binary_path, sha256, hmac_sig FROM integrity_baseline")
                return {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
        except sqlite3.Error:
            return {}


def get_lineage(pid, max_depth=6):
    chain, curr, seen = [], int(pid), set()
    for _ in range(max_depth):
        if curr <= 1 or curr in seen: break
        seen.add(curr)
        try:
            ppid = next(int(l.split()[1]) for l in open(f"/proc/{curr}/status") if l.startswith("PPid:"))
            st = os.stat(f"/proc/{curr}/exe")
            exe = os.path.realpath(f"/proc/{curr}/exe")
            chain.append({"pid": curr, "ppid": ppid, "name": os.path.basename(exe), "exe": exe, "ino": st.st_ino, "dev": st.st_dev})
            curr = ppid
        except Exception: break
    return chain

def log_timeline(ev):
    import json
    b = os.environ.get("ORLITUM_HOME") or os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    fp = os.path.join(b, "orlitum_timeline.jsonl")
    fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")

def is_dga_or_c2(cmd):
    import math, re
    if ".onion" in cmd or "/dev/tcp/" in cmd: return True, "Tor/RawTCP C2"
    for d in re.findall(r"([a-z0-9]{11,})\.(?:ru|cn|xyz|top|cc|pw|biz|onion)\b", cmd.lower()):
        L = len(d)
        e = -sum((d.count(c)/L)*math.log2(d.count(c)/L) for c in set(d))
        if e > 3.3 or sum(c.isdigit() for c in d)/L > 0.35: return True, f"DGA:{d}"
    return False, ""

class SigmaEngine:
    RULES = [
        {"id": "SIG-LNX-01", "p": {"nginx", "httpd", "apache2", "php-fpm"}, "c": {"sh", "bash", "dash", "zsh", "nc", "socat"}, "d": "Web spawns shell"},
        {"id": "SIG-LNX-02", "p": {"mysqld", "postgres", "redis-server"}, "c": {"sh", "bash", "curl", "wget", "nc", "python3"}, "d": "DB spawns shell/tool"},
    ]
    _YML = None
    @classmethod
    def _load(cls):
        if cls._YML is None:
            cls._YML = []
            for f in __import__("glob").glob(f"{get_default_base_dir()}/rules/sigma/*.yml"):
                for b in open(f).read().split("- id:")[1:]:
                    cls._YML.append({k.strip(): v.strip() for l in ("id:"+b).splitlines() if ":" in l for k, v in [l.split(":", 1)]})
        return cls._YML
    @classmethod
    def match(cls, chain, cmd=""):
        nms = [x["name"] for x in chain]
        for r in cls.RULES:
            for p in nms[1:]:
                if p in r["p"] and nms[0] in r["c"]:
                    return True, r["id"], r["d"]
        for r in cls._load():
            co = not r.get("child") or (nms and nms[0] in r["child"].split(","))
            po = not r.get("parent") or any(x in r["parent"].split(",") for x in nms[1:])
            mo = not r.get("cmd") or any(k in cmd.lower() for k in r["cmd"].split(","))
            if co and po and mo: return True, r["id"], r.get("msg", "")
        return False, "", ""

class ProcessHunter:
    @staticmethod
    def audit_lineage(pid):
        c = get_lineage(pid)
        hit, rid, d = SigmaEngine.match(c) if c else (False, "", "")
        if hit:
            import time
            log_timeline({"ts": int(time.time()), "pid": pid, "rule": rid, "desc": d, "chain": [x["name"] for x in c], "verdict": "KILL"})
            ProcessHunter._safe_kill(pid)
            return True
        return False

    @staticmethod
    def _safe_kill(pid):
        try:
            try: log_timeline({"ts": int(time.time()), "pid": pid, "ppid_chain": [x["name"] for x in get_lineage(pid)], "event": "PROCESS_KILL", "verdict": "KILLED"})
            except Exception: pass
            pfd = os.pidfd_open(pid, 0)
            try:
                signal.pidfd_send_signal(pfd, signal.SIGKILL, None, 0)
            finally:
                os.close(pfd)
        except Exception:
            os.kill(pid, signal.SIGKILL)

    @staticmethod
    def terminate_associated_processes(file_path):
        real_target = os.path.realpath(file_path)
        deleted_target = f"{real_target} (deleted)"
        killed_pids = []
        current_pid = os.getpid()

        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid == current_pid:
                    continue

                proc_dir = f"/proc/{pid}"
                try:
                    raw_exe = os.readlink(os.path.join(proc_dir, "exe"))
                    exe_link = os.path.realpath(os.path.join(proc_dir, "exe"))
                    if exe_link == real_target or raw_exe in (real_target, deleted_target):
                        ProcessHunter._safe_kill(pid)
                        killed_pids.append(pid)
                        continue
                except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                    continue

                try:
                    if is_interpreter_binary(exe_link):
                        killed = False
                        fd_dir = os.path.join(proc_dir, "fd")
                        if os.path.exists(fd_dir):
                            for fd in os.listdir(fd_dir):
                                fd_target = os.path.realpath(os.path.join(fd_dir, fd))
                                if fd_target == real_target:
                                    ProcessHunter._safe_kill(pid)
                                    killed_pids.append(pid)
                                    killed = True
                                    break
                        maps_path = os.path.join(proc_dir, "maps")
                        if os.path.exists(maps_path):
                            with open(maps_path, "r", encoding="utf-8", errors="ignore") as mf:
                                for line in mf:
                                    parts = line.split()
                                    if len(parts) >= 6 and parts[-1] == real_target:
                                        ProcessHunter._safe_kill(pid)
                                        killed_pids.append(pid)
                                        break
                except (FileNotFoundError, PermissionError):
                    pass
        except Exception:
            pass

        return killed_pids


class BehavioralAnalyzer:
    NETWORK_INTERPRETERS = {"nc", "ncat", "socat", "netcat", "curl", "wget"}
    SHELL_BINARIES = {"sh", "bash", "dash", "zsh"}

    _PROC_CACHE = {}
    _CACHE_LOCK = threading.Lock()

    @classmethod
    def evaluate_process_event(cls, proc_info):
        alerts = []
        comm = proc_info.get("comm", "")
        parent_comm = proc_info.get("parent_comm", "")
        exe = proc_info.get("exe", "")
        cmdline = proc_info.get("cmdline", "")
        open_files = proc_info.get("open_files", [])

        if comm in cls.SHELL_BINARIES and (parent_comm in cls.NETWORK_INTERPRETERS or any('socket:[' in f for f in open_files[:3])):
            alerts.append(f"[CRITICAL] Поведенческий детект Reverse Shell: {parent_comm} -> {comm}")

        if any(p in cmdline for p in ["| sh", "| bash", "|sh", "|bash"]) and any(u in cmdline for u in ["curl ", "wget ", "base64"]):
            alerts.append("[HIGH] Инлайн-выполнение загруженного кода (пайп в командную оболочку)")
        if any(w in cmdline for w in ("timeshift --delete", "btrfs subvolume delete", "lvremove", "rm -rf /var/backups", "chattr -i")):
            alerts.append(f"[CRITICAL] Anti-Ransomware: Попытка уничтожения теневых копий/бэкапов ({cmdline})")

        legit_auth = {"sshd", "sudo", "su", "login", "passwd", "unix_chkpwd", "chage", "useradd", "usermod", "lightdm", "polkitd"}
        if not (comm in legit_auth and exe.startswith(('/usr/', '/bin/', '/sbin/', '/lib/')) and '(deleted)' not in exe):
            if "/etc/shadow" in open_files or "/etc/shadow" in cmdline:
                alerts.append(f"[HIGH] Несанкционированный доступ процесса {comm} к /etc/shadow")
            if any(re.match(r"^/proc/\d+/mem$", f) for f in open_files):
                alerts.append(f"[CRITICAL] Попытка чтения памяти чужого процесса (/proc/*/mem) процессом {comm}")

        if "memfd:" in exe or (exe.endswith("(deleted)") and any(exe.startswith(t) for t in ("/tmp/", "/var/tmp/", "/dev/shm/"))):
            alerts.append(f"[CRITICAL] Fileless-выполнение в памяти или запуск удаленного бинарника: {exe}")

        if any(f in cmdline for f in (" -c ", " -e ")) and any(k in cmdline for k in ("pty.spawn", "socket", "ctypes", "base64", "os.system")):
            alerts.append(f"[CRITICAL] Fileless Script: {cmdline[:60]}")
        c2_hit, c2_msg = is_dga_or_c2(cmdline)
        if c2_hit:
            alerts.append(f"[CRITICAL] Скрытый канал C2/DGA ({c2_msg}): {cmdline[:60]}")
        ch = proc_info.get("lineage") or get_lineage(proc_info.get("pid", 0))
        hit, rid, d = SigmaEngine.match(ch, cmdline)
        if hit:
            alerts.append(f"[CRITICAL] Sigma {rid} ({d}): {'<-'.join(x['name'] for x in ch)}")
        return alerts

    @classmethod
    def scan_running_processes(cls):
        findings = []
        current_pid = os.getpid()
        active_pids = set()

        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == current_pid:
                continue
            active_pids.add(pid)

            proc_dir = f"/proc/{pid}"
            try:
                starttime = 0
                try:
                    with open(os.path.join(proc_dir, "stat"), "r", encoding="utf-8", errors="ignore") as f:
                        stat_content = f.read()
                        rparen = stat_content.rfind(")")
                        if rparen != -1:
                            fields = stat_content[rparen + 2:].split()
                            if len(fields) >= 20:
                                starttime = int(fields[19])
                except Exception:
                    pass

                exe_target = ""
                try: exe_target = os.readlink(os.path.join(proc_dir, "exe"))
                except OSError: pass
                with cls._CACHE_LOCK:
                    if pid in cls._PROC_CACHE:
                        cached_key, cached_alerts, cached_comm = cls._PROC_CACHE[pid]
                        if cached_key == (starttime, exe_target) and starttime > 0:
                            if cached_alerts:
                                findings.append(({"pid": pid, "comm": cached_comm,
                                                  "parent_comm": "", "cmdline": ""},
                                                 cached_alerts))
                            continue

                with open(os.path.join(proc_dir, "comm"), "r", encoding="utf-8", errors="ignore") as f:
                    comm = f.read().strip()

                ppid = 0
                parent_comm = ""
                with open(os.path.join(proc_dir, "status"), "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                            break
                if ppid > 0 and os.path.exists(f"/proc/{ppid}/comm"):
                    with open(f"/proc/{ppid}/comm", "r", encoding="utf-8", errors="ignore") as f:
                        parent_comm = f.read().strip()

                exe = ""
                try:
                    exe = os.readlink(os.path.join(proc_dir, "exe"))
                except OSError:
                    pass

                cmdline = ""
                try:
                    with open(os.path.join(proc_dir, "cmdline"), "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                except OSError:
                    pass

                open_files = []
                fd_dir = os.path.join(proc_dir, "fd")
                if os.path.exists(fd_dir):
                    try:
                        for fd in islice(os.listdir(fd_dir), 64):
                            open_files.append(os.path.realpath(os.path.join(fd_dir, fd)))
                    except OSError:
                        pass

                info = {"pid": pid, "ppid": ppid, "comm": comm,
                        "parent_comm": parent_comm, "exe": exe,
                        "cmdline": cmdline, "open_files": open_files}
                proc_alerts = cls.evaluate_process_event(info)

                with cls._CACHE_LOCK:
                    cls._PROC_CACHE[pid] = ((starttime, exe), proc_alerts, comm)

                if proc_alerts:
                    findings.append((info, proc_alerts))
                    log_timeline({"ts": int(time.time()), "pid": pid, "ppid_chain": [x["name"] for x in get_lineage(pid)], "exe": exe, "event": "BEHAVIORAL_ALERT", "alerts": proc_alerts})
            except (FileNotFoundError, PermissionError):
                continue

        with cls._CACHE_LOCK:
            dead_pids = [q for q in cls._PROC_CACHE if q not in active_pids]
            for q in dead_pids:
                del cls._PROC_CACHE[q]

        return findings

class ScannerCore:
    def __init__(self, quarantine_dir, rules_dir=None, output_log=None, auto_quarantine=True, max_size_mb=100, notify=True, max_log_bytes=10 * 1024 * 1024):
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self.db_path = os.path.join(os.path.dirname(self.quarantine_dir), "cache.db")
        self.cache = CacheDB(self.db_path)
        self.output_log = os.path.abspath(output_log) if output_log else None
        self.auto_quarantine = auto_quarantine
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_log_bytes = max_log_bytes
        self.notify = notify
        self.log_lock = threading.Lock()

        os.makedirs(self.quarantine_dir, exist_ok=True)
        if self.output_log:
            log_dir = os.path.dirname(self.output_log)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

        self.yara_rules = None
        if YARA_AVAILABLE and rules_dir and os.path.exists(rules_dir):
            self.load_yara_rules(rules_dir)

    def load_yara_rules(self, rules_dir):
        rule_files = {}
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if f.endswith(('.yar', '.yara')):
                    full_p = os.path.join(root, f)
                    ns = os.path.relpath(full_p, rules_dir)
                    rule_files[ns] = full_p

        if rule_files:
            try:
                self.yara_rules = yara.compile(filepaths=rule_files)
                print(f"{CLR_GREEN}[*] Загружено файлов YARA-правил: {len(rule_files)}{CLR_RESET}")
            except Exception as e:
                print(f"{CLR_RED}[!] Ошибка компиляции YARA-правил: {e}{CLR_RESET}")

    def is_whitelisted(self, file_path):
        if file_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            return False
        parts = [p.lower() for p in file_path.split(os.sep)]
        return any(d in parts for d in WHITELIST_DIRS)

    @staticmethod
    def _sample_seek(fp, sz):
        import hashlib, math
        h, me = hashlib.sha256(), 0.0
        nw = max(32, (max(2, int((sz / (1024**3)) * 2)) * 1024 * 1024) // 65536)
        st = sz // nw
        with open(fp, "rb") as f:
            for i in range(nw):
                f.seek(i * st); c = f.read(65536)
                if not c: break
                h.update(c); inv = 1.0 / len(c)
                we = -sum((x * inv) * math.log2(x * inv) for b in range(256) if (x := c.count(b)) > 0)
                if we > me: me = we
        return h.hexdigest(), me

    def scan_file(self, file_path):
        file_path = os.path.abspath(file_path)

        if os.path.realpath(file_path) == os.path.realpath(__file__):
            return False, "Ignored Internal File", []
        if is_subpath(file_path, self.quarantine_dir):
            return False, "Ignored", []
        if file_path.startswith(self.db_path) or (self.output_log and file_path == self.output_log):
            return False, "Ignored Internal File", []
        if file_path.endswith(('secret.key', 'pin.vault', 'agent_self.sha256')) or (file_path.endswith(('.crdownload', '.part')) and not os.access(file_path, os.X_OK)):
            return False, "Ignored Internal File", []
        if self.is_whitelisted(file_path) and not os.access(file_path, os.X_OK):
            return False, "Whitelisted Directory", []
        if os.path.islink(file_path) or not os.path.isfile(file_path):
            return False, "Skipped (Not a regular file)", []

        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0 or file_size > self.max_size_bytes:
                return False, "Skipped (Size)", []

            file_mtime = os.path.getmtime(file_path)
            cached = self.cache.get(file_path, file_mtime, file_size)
            ti_match_cached = None
            if cached and cached["verdict"] == "Clean":
                ti_match_cached = self.cache.check_known_threat(cached["sha256"])
                if not ti_match_cached:
                    return False, "Clean (Cached)", []

            st = os.stat(file_path)
            is_exec = bool(st.st_mode & 0o111) or os.access(file_path, os.X_OK)
            with open(file_path, "rb") as f: m16 = f.read(16)
            is_code = m16.startswith((b"\x7fELF", b"MZ", b"#!", b"PK\x03\x04", b"\x1f\x8b", b"7z"))
            sha256_hash = hashlib.sha256()
            total_read, win_idx, max_entropy = 0, 0, 0.0
            magic_bytes = b""
            target_windows = max(32, min(512, (file_size // (1024 * 1024 * 64)) + 32))
            step = max(1, (file_size // 65536) // target_windows)
            magic_bytes = m16[:4]
            if file_size > 100 * 1024 * 1024 and not (is_exec or is_code):
                digest, max_entropy = self._sample_seek(file_path, file_size)

            else:
                with open(file_path, "rb") as f:
                    while chunk := f.read(65536):
                        if total_read == 0:
                            magic_bytes = chunk[:4]
                        sha256_hash.update(chunk)
                        total_read += len(chunk)
                        win_idx += 1
                        if win_idx <= 8 or win_idx % step == 0:
                            inv = 1.0 / len(chunk)
                            we = -sum((c * inv) * math.log2(c * inv) for b in range(256) if (c := chunk.count(b)) > 0)
                            if we > max_entropy:
                                max_entropy = we

            digest = sha256_hash.hexdigest()

            file_format = "Unknown"
            if magic_bytes.startswith(b"\x7fELF"):
                file_format = "ELF (Linux Binary)"
            elif magic_bytes.startswith(b"MZ"):
                file_format = "PE (Windows Binary)"
            elif magic_bytes.startswith(b"%PDF"):
                file_format = "PDF"
            elif magic_bytes.startswith(b"PK\x03\x04"):
                file_format = "ZIP/Archive"

            is_executable, suid_bit, sgid_bit = self.check_permissions(file_path)
            entropy = max_entropy

            alerts = []
            matched_rules = []

            ti_match = ti_match_cached if (cached and cached.get("sha256") == digest) else self.cache.check_known_threat(digest)
            if ti_match:
                alerts.append(f"ThreatIntel: {ti_match}")
                matched_rules.append(f"ThreatIntel: {ti_match}")

            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(file_path)
                    for m in matches:
                        matched_rules.append(m.rule)
                        alerts.append(f"YARA: {m.rule}")
                except Exception:
                    pass

            untrusted_suid = suid_bit and not file_path.startswith(TRUSTED_SYSTEM_PREFIXES)
            if untrusted_suid:
                alerts.append("Критический SUID-бит в несистемном каталоге (угроза Privilege Escalation)")
            elif suid_bit:
                alerts.append("Системный SUID-бит")

            if sgid_bit:
                alerts.append("SGID-бит установлен")
            if os.path.basename(file_path) == ".orlitum_canary.dat" and entropy > 6.5:
                alerts.append("[CRITICAL] RANSOMWARE CANARY: Шифрование файла-ловушки!")
                matched_rules.append("Ransomware_Canary")
            if "ELF" in file_format and entropy > 7.3:
                alerts.append(f"Высокая энтропия ({entropy:.2f})")
            if self.check_double_extension(file_path):
                alerts.append("Подозрительное двойное расширение")

            is_malicious = len(matched_rules) > 0 or untrusted_suid
            verdict = "Clean"
            killed_pids = []

            if is_malicious and self.auto_quarantine:
                killed_pids = ProcessHunter.terminate_associated_processes(file_path)
                if killed_pids:
                    time.sleep(0.05)
                verdict = self.isolate_file(file_path, alerts, killed_pids)
            elif is_malicious:
                verdict = "Malicious (Audit Mode)"
            elif alerts:
                verdict = "Suspicious"

            self.print_verdict(file_path, file_format, digest, entropy, alerts, verdict, killed_pids)

            if self.output_log:
                self.log_event({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "file_path": file_path,
                    "sha256": digest,
                    "format": file_format,
                    "is_executable": is_executable,
                    "entropy": round(entropy, 4),
                    "alerts": alerts,
                    "verdict": verdict,
                    "killed_pids": killed_pids
                })

            if verdict in ("Clean", "Suspicious"):
                self.cache.set(file_path, file_mtime, file_size, digest, verdict, alerts)

            return is_malicious, verdict, alerts

        except (FileNotFoundError, PermissionError):
            return False, "Access Denied", []
        except Exception as e:
            return False, f"Error: {e}", []

    def isolate_file(self, file_path, reasons, killed_pids):
        try:
            fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                st = os.fstat(fd)
                if (st.st_mode & 0o170000) != 0o100000: return "Skipped (Not Regular)"
                original_mode = format(st.st_mode & 0o777, "o")
                base_name = os.path.basename(file_path)
                ts = int(time.time() * 1000)
                target_path = os.path.join(self.quarantine_dir, f"{base_name}_{ts}.quarantined")
                meta_path = f"{target_path}.meta.json"
                dfd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    while c := os.read(fd, 65536): os.write(dfd, c)
                    os.fchmod(dfd, 0o000)
                finally: os.close(dfd)
                os.unlink(file_path)
            finally: os.close(fd)

            meta_data = {
                "original_path": file_path,
                "original_mode": original_mode,
                "quarantine_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reasons": reasons,
                "killed_pids": killed_pids
            }

            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_data, f, ensure_ascii=False, indent=2)

            set_immutable_flag(target_path, enable=True)
            set_immutable_flag(meta_path, enable=True)

            if self.notify:
                msg = f"Изолирован файл:\n{base_name}"
                if killed_pids:
                    msg += f"\nЗавершены PID: {killed_pids}"
                send_desktop_notification("⚠️ Orlitum EDR Community", msg)

            return "Quarantined"
        except Exception as e:
            return f"Quarantine Failed ({e})"

    def print_verdict(self, path, fmt, sha, entropy, alerts, verdict, killed_pids=None):
        if verdict == "Quarantined":
            badge = f"{CLR_RED}{CLR_BOLD}[✖ В КАРАНТИНЕ]{CLR_RESET}"
        elif verdict.startswith("Malicious"):
            badge = f"{CLR_RED}{CLR_BOLD}[✖ УГРОЗА (АУДИТ)]{CLR_RESET}"
        elif alerts:
            badge = f"{CLR_YELLOW}{CLR_BOLD}[▲ ПОДОЗРИТЕЛЬНЫЙ]{CLR_RESET}"
        else:
            badge = f"{CLR_GREEN}[✔ ЧИСТЫЙ]{CLR_RESET}"

        print(f"{badge} {path}")
        print(f"    Формат: {fmt} | Энтропия: {entropy:.2f} | Хэш: {sha[:16]}...")
        for alert in alerts:
            print(f"    {CLR_RED}↳ Сигнал:{CLR_RESET} {alert}")
        if killed_pids:
            print(f"    {CLR_RED}↳ Убит процесс:{CLR_RESET} PID {killed_pids}")
        if verdict == "Quarantined":
            print(f"    {CLR_BLUE}↳ Изолирован в:{CLR_RESET} {self.quarantine_dir}")

    def check_permissions(self, file_path):
        try:
            st = os.stat(file_path)
            return bool(st.st_mode & 0o111), bool(st.st_mode & 0o4000), bool(st.st_mode & 0o2000)
        except Exception:
            return False, False, False

    def calculate_entropy(self, size, counter):
        if size == 0:
            return 0.0
        entropy = 0.0
        for count in counter.values():
            p = count / size
            entropy -= p * math.log2(p)
        return entropy

    def check_double_extension(self, file_path):
        exec_exts = {"exe", "sh", "bat", "elf", "ps1", "py", "php", "pl", "bin"}
        decoy_exts = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "jpeg", "txt", "zip", "tar"}

        parts = [p for p in os.path.basename(file_path).lower().split(".") if p]
        if len(parts) >= 3:
            last_ext = parts[-1]
            second_last = parts[-2]
            if last_ext in exec_exts and second_last in decoy_exts:
                return True
        return False

    def _rotate_logs(self):
        max_backups = 3
        oldest = f"{self.output_log}.{max_backups}.gz"
        if os.path.exists(oldest):
            os.remove(oldest)

        for i in range(max_backups - 1, 0, -1):
            src = f"{self.output_log}.{i}.gz"
            dst = f"{self.output_log}.{i + 1}.gz"
            if os.path.exists(src):
                shutil.move(src, dst)

        dst_first = f"{self.output_log}.1.gz"
        with open(self.output_log, "rb") as f_in, gzip.open(dst_first, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(self.output_log)

    def log_event(self, record):
        with self.log_lock:
            try:
                if os.path.exists(self.output_log) and os.path.getsize(self.output_log) >= self.max_log_bytes:
                    self._rotate_logs()
                with open(self.output_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception:
                pass


class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, scanner_core):

        super().__init__()

        self.scanner = scanner_core

        self.executor = ThreadPoolExecutor(max_workers=8)

        self.in_progress = set()

        self.lock = threading.Lock()
        self.burst_ts = []


    def _enqueue(self, file_path):

        real_p = os.path.abspath(file_path)

        with self.lock:

            if real_p in self.in_progress:

                return
            self.in_progress.add(real_p)
            now = time.time()
            self.burst_ts = [x for x in self.burst_ts if now - x < 5.0] + [now]
            if len(self.burst_ts) > 20 or real_p.endswith((".locked", ".encrypted", ".lockbit")):
                log_timeline({"ts": int(now), "file": real_p, "event": "RANSOMWARE_BURST"})
                ProcessHunter.terminate_associated_processes(real_p)
            self.executor.submit(self.handle_event, real_p)


    def on_created(self, event):

        if not event.is_directory:

            self._enqueue(event.src_path)


    def on_moved(self, event):

        if not event.is_directory:

            self._enqueue(event.dest_path)


    def on_modified(self, event):

        if not event.is_directory:

            self._enqueue(event.src_path)


    def handle_event(self, file_path):
        try:
            last_size = -1
            stable_count = 0
            start = time.time()
            while time.time() - start < 5:
                try:
                    curr = os.path.getsize(file_path)
                    if curr == last_size and curr > 0:
                        stable_count += 1
                        if stable_count >= 3:
                            break
                    else:
                        stable_count = 0
                        last_size = curr
                    time.sleep(0.15)
                except (FileNotFoundError, PermissionError):
                    return
            self.scanner.scan_file(file_path)
        finally:
            with self.lock:
                self.in_progress.discard(file_path)


def list_quarantine(quarantine_dir):
    if not os.path.exists(quarantine_dir):
        print(f"{CLR_YELLOW}[*] Папка карантина пуста.{CLR_RESET}")
        return
    meta_files = [f for f in os.listdir(quarantine_dir) if f.endswith(".meta.json")]
    if not meta_files:
        print(f"{CLR_GREEN}[*] В карантине нет файлов.{CLR_RESET}")
        return
    print(f"\n{CLR_BOLD}{'Имя в карантине':<38} | {'Дата изоляции':<20} | {'Причина детекции'}{CLR_RESET}")
    print("─" * 95)
    for mf in sorted(meta_files):
        base = mf.replace(".meta.json", "")
        with open(os.path.join(quarantine_dir, mf), "r", encoding="utf-8") as f:
            data = json.load(f)
            reasons = ", ".join(data.get("reasons", ["-"]))
            t = data.get("quarantine_time", "-")
            print(f"{base:<38} | {t:<20} | {reasons}")
    print()


def is_safe_restore_path(orig_path):
    if not orig_path:
        return False
    normalized_orig = os.path.abspath(orig_path)
    if os.path.islink(normalized_orig):
        return False
    real_dest_dir = os.path.realpath(os.path.dirname(normalized_orig))
    real_full = os.path.realpath(os.path.join(real_dest_dir, os.path.basename(normalized_orig)))
    if real_full.startswith(TRUSTED_SYSTEM_PREFIXES):
        return False
    allowed_roots = (get_real_user_home(), "/tmp", "/var/tmp", "/media", "/mnt")
    return any(is_subpath(real_full, root) for root in allowed_roots)


def restore_quarantine_file(quarantine_dir, target_identifier):
    if not os.path.exists(quarantine_dir):
        print(f"{CLR_RED}[!] Карантин пуст.{CLR_RESET}")
        return False
    all_meta = [f for f in os.listdir(quarantine_dir) if f.endswith(".meta.json")]
    exact = [f for f in all_meta if f.replace(".meta.json", "") == target_identifier]
    candidates = exact if exact else [f for f in all_meta if target_identifier in f]
    if not candidates:
        print(f"{CLR_RED}[!] Файл '{target_identifier}' не найден в карантине.{CLR_RESET}")
        return False
    if len(candidates) > 1 and not exact:
        print(f"{CLR_YELLOW}[!] Найдено несколько файлов. Укажите точное имя из --quarantine-list:{CLR_RESET}")
        for c in candidates:
            print(f"  - {c.replace('.meta.json', '')}")
        return False
    meta_filename = candidates[0]
    meta_path = os.path.join(quarantine_dir, meta_filename)
    quarantined_file = os.path.join(quarantine_dir, meta_filename.replace(".meta.json", ""))
    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    orig_path = data.get("original_path")
    raw_mode = str(data.get("original_mode", "644")).strip().lstrip("0o") or "0"
    orig_mode = int(raw_mode, 8) & 0o0777
    if not is_safe_restore_path(orig_path):
        print(f"{CLR_RED}[!] БЛОКИРОВКА БЕЗОПАСНОСТИ: Восстановление по пути '{orig_path}' запрещено.{CLR_RESET}")
        return False
    set_immutable_flag(quarantined_file, enable=False)
    set_immutable_flag(meta_path, enable=False)
    try:
        os.chmod(quarantined_file, orig_mode)
        os.makedirs(os.path.dirname(orig_path), exist_ok=True)
        shutil.move(quarantined_file, orig_path)
        os.chmod(orig_path, orig_mode)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        print(f"{CLR_GREEN}[✔] Файл успешно восстановлен на исходное место:{CLR_RESET} {orig_path}")
        return True
    except Exception as e:
        print(f"{CLR_RED}[!] Ошибка при восстановлении: {e}{CLR_RESET}")
        return False


def delete_quarantine_file(quarantine_dir, target_identifier):
    if not os.path.exists(quarantine_dir):
        print(f"{CLR_RED}[!] Карантин пуст.{CLR_RESET}")
        return False
    all_meta = [f for f in os.listdir(quarantine_dir) if f.endswith(".meta.json")]
    exact = [f for f in all_meta if f.replace(".meta.json", "") == target_identifier]
    candidates = exact if exact else [f for f in all_meta if target_identifier in f]
    if not candidates:
        print(f"{CLR_RED}[!] Файл '{target_identifier}' не найден в карантине.{CLR_RESET}")
        return False
    for meta_filename in candidates:
        meta_path = os.path.join(quarantine_dir, meta_filename)
        quarantined_file = os.path.join(quarantine_dir, meta_filename.replace(".meta.json", ""))
        set_immutable_flag(quarantined_file, enable=False)
        set_immutable_flag(meta_path, enable=False)
        try:
            if os.path.exists(quarantined_file):
                os.chmod(quarantined_file, 0o600)
                os.remove(quarantined_file)
            if os.path.exists(meta_path):
                os.remove(meta_path)
            print(f"{CLR_GREEN}[✔] Удален из карантина:{CLR_RESET} {os.path.basename(quarantined_file)}")
        except OSError as e:
            print(f"{CLR_RED}[!] Ошибка удаления {quarantined_file}: {e}{CLR_RESET}")
    return True


def run_on_demand_scan(target_path, scanner):
    print(f"\n{CLR_BOLD}=== ЗАПУСК СКАНИРОВАНИЯ: {target_path} ==={CLR_RESET}")
    stats = {"scanned": 0, "skipped": 0, "threats": 0}
    def _process(fp):
        is_mal, verdict, _ = scanner.scan_file(fp)
        if verdict in SKIPPED_VERDICTS:
            stats["skipped"] += 1
        else:
            stats["scanned"] += 1
            if is_mal:
                stats["threats"] += 1
    if os.path.isfile(target_path):
        _process(target_path)
    else:
        for root, _, files in os.walk(target_path, onerror=lambda _: None):
            for file in files:
                _process(os.path.join(root, file))
    print("─" * 65)
    print(f"{CLR_BOLD}Итоги сканирования:{CLR_RESET}")
    print(f"  Проверено файлов: {stats['scanned']} (пропущено фильтром: {stats['skipped']})")
    if stats["threats"] > 0:
        print(f"  {CLR_RED}Угроз обнаружено/изолировано: {stats['threats']}{CLR_RESET}")
    else:
        print(f"  {CLR_GREEN}Угроз не обнаружено.{CLR_RESET}")


def get_default_downloads_dir():
    home = get_real_user_home()
    xdg = os.path.join(home, ".config/user-dirs.dirs")
    if os.path.isfile(xdg):
        m = re.search(r'XDG_DOWNLOAD_DIR="\$HOME/([^"]+)"', open(xdg, errors="ignore").read())
        if m and os.path.exists(os.path.join(home, m.group(1))):
            return os.path.join(home, m.group(1))
    for name in ["Загрузки", "Downloads"]:
        candidate = os.path.join(home, name)
        if os.path.exists(candidate):
            return candidate
    return home
CRITICAL_BINARIES = sorted({
    os.path.realpath(p) for cmd in ("ls", "ps", "netstat", "ss", "top", "sudo", "login", "sh", "bash", "sshd")
    if (p := shutil.which(cmd)) and os.path.exists(p)
})


def hash_file_sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
            ram_hex = h.hexdigest()
            if filepath in CRITICAL_BINARIES and hasattr(os, "posix_fadvise"):
                try:
                    os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                    f.seek(0)
                    h_disk = hashlib.sha256()
                    while chunk := f.read(65536):
                        h_disk.update(chunk)
                    if h_disk.hexdigest() != ram_hex:
                        return "DIRTY_PIPE_POISONED_" + ram_hex
                except OSError:
                    pass
        return ram_hex
    except (FileNotFoundError, PermissionError):
        return None


def manage_self_integrity(base_dir, init_mode=False):
    self_path = os.path.realpath(__file__)
    sig_file = os.path.join(base_dir, "agent_self.sha256")
    cur_hash = hash_file_sha256(self_path)
    if not cur_hash:
        return True
    if init_mode:
        os.makedirs(base_dir, exist_ok=True)
        gp = os.path.join(base_dir, "guard.py")
        gh = hash_file_sha256(gp) if os.path.exists(gp) else ""
        with open(sig_file, "w", encoding="utf-8") as f:
            f.write(f"{gh}\n{cur_hash}\n")
        try:
            os.chmod(sig_file, 0o600)
        except OSError:
            pass
        print(f"{CLR_GREEN}[✔] Эталонный хэш самозащиты сохранен:{CLR_RESET} {cur_hash[:16]}... ({sig_file})")
        return True
    if os.path.exists(sig_file):
        try:
            with open(sig_file, "r", encoding="utf-8") as f:
                expected = f.read().strip()
            if expected and not any(hmac.compare_digest(cur_hash, x.strip()) for x in expected.splitlines() if x.strip()):
                msg = f"КРИТИЧЕСКАЯ ТРЕВОГА: Код агента {self_path} был изменен (выполните --init-self-hash)!"
                print(f"{CLR_RED}{CLR_BOLD}[✖] {msg}{CLR_RESET}")
                send_desktop_notification("🚨 EDR Anti-Tamper", msg)
                return False
        except OSError:
            pass
    return True


def run_integrity_check(cache_db, init_mode=False):
    print(f"\n{CLR_BOLD}=== МОДУЛЬ КОНТРОЛЯ ЦЕЛОСТНОСТИ СИСТЕМЫ (FIM + HMAC) ==={CLR_RESET}")
    baseline = cache_db.get_baseline()
    if init_mode or not baseline:
        print("[*] Создание подписанного (HMAC-SHA256) эталонного снимка системных утилит...")
        for b in CRITICAL_BINARIES:
            real_p = os.path.realpath(b)
            if os.path.exists(real_p):
                h = hash_file_sha256(real_p)
                if h:
                    cache_db.update_baseline(real_p, h)
                    print(f"  [+] Зафиксирован и подписан: {real_p} -> {h[:16]}...")
        print(f"{CLR_GREEN}[✔] Эталонный снимок успешно сформирован.{CLR_RESET}\n")
        return
    print("[*] Сканирование системных утилит и проверка HMAC-подписей БД...")
    tampered = False
    for b in CRITICAL_BINARIES:
        real_p = os.path.realpath(b)
        if not os.path.exists(real_p):
            continue
        cur_hash = hash_file_sha256(real_p)
        if not cur_hash:
            continue
        record = baseline.get(real_p)
        if not record:
            print(f"  {CLR_YELLOW}[?] Новый бинарник (нет в базе): {real_p}{CLR_RESET}")
            continue
        base_hash, stored_hmac = record
        expected_hmac = cache_db.compute_hmac(real_p, base_hash)
        if expected_hmac and (not stored_hmac or not hmac.compare_digest(stored_hmac, expected_hmac)):
            tampered = True
            print(f"  {CLR_RED}[✖ НАРУШЕНИЕ HMAC БД!]{CLR_RESET} Несовпадение ключа подписи для {real_p}")
        elif cur_hash != base_hash:
            tampered = True
            print(f"  {CLR_RED}[✖ ВНИМАНИЕ: ПОДМЕНА БИНАРНИКА!]{CLR_RESET} {real_p}")
            print(f"      Ожидался хэш: {base_hash}")
            print(f"      Текущий хэш:  {cur_hash}")
        else:
            print(f"  {CLR_GREEN}[✔ ЦЕЛ + HMAC OK]{CLR_RESET} {real_p}")
    if not tampered:
        print(f"\n{CLR_GREEN}[✔] Все критические системные утилиты и подписи БД аутентичны.{CLR_RESET}\n")
    else:
        print(f"\n{CLR_RED}[!] Обнаружены расхождения! Если вы обновляли систему, выполните: python3 orlitum.py --init-integrity{CLR_RESET}\n")


def block_ip_nftables(ip_addr, timeout_str="1h"):
    if os.geteuid() != 0:
        print(f"{CLR_RED}[!] Управление nftables требует прав root (sudo).{CLR_RESET}")
        return False
    clean_ip = ip_addr.strip("[]")
    if not re.match(r"^[0-9a-fA-F:.]+$", clean_ip) or clean_ip in ("127.0.0.1", "::1", "0.0.0.0", "*"):
        print(f"{CLR_YELLOW}[!] Некорректный или локальный адрес для блокировки: {ip_addr}{CLR_RESET}")
        return False
    try:
        # Базовая таблица и цепочки
        subprocess.run(["nft", "add", "table", "inet", "edr_guard"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(
        ["nft", "add", "chain", "inet", "edr_guard", "input", "{ type filter hook input priority -10 ; }"],
        check=False, stderr=subprocess.DEVNULL
        )
        subprocess.run(
        ["nft", "add", "chain", "inet", "edr_guard", "output", "{ type filter hook output priority -10 ; }"],
        check=False, stderr=subprocess.DEVNULL
        )
        is_ipv6 = ":" in clean_ip
        set_name = "blacklist_v6" if is_ipv6 else "blacklist_v4"
        addr_type = "ipv6_addr" if is_ipv6 else "ipv4_addr"
        proto_field = "ip6" if is_ipv6 else "ip"
        # Создаем динамический сет с поддержкой таймеров ядра
        subprocess.run(
        ["nft", "add", "set", "inet", "edr_guard", set_name, f"{{ type {addr_type}; flags timeout; }}"],
        check=False, stderr=subprocess.DEVNULL
        )
        # Однократные правила привязки к сету
        subprocess.run(
        ["nft", "add", "rule", "inet", "edr_guard", "input", proto_field, "saddr", f"@{set_name}", "drop"],
        check=False, stderr=subprocess.DEVNULL
        )
        subprocess.run(
        ["nft", "add", "rule", "inet", "edr_guard", "output", proto_field, "daddr", f"@{set_name}", "drop"],
        check=False, stderr=subprocess.DEVNULL
        )
        # Добавление элемента с таймером или перманентно
        if timeout_str and timeout_str.lower() != "permanent":
            elem_spec = f"{{ {clean_ip} timeout {timeout_str} }}"
            mode_desc = f"на {timeout_str} (авторазблокировка ядром)"
        else:
            elem_spec = f"{{ {clean_ip} }}"
            mode_desc = "навсегда (permanent)"
        subprocess.run(["nft", "add", "element", "inet", "edr_guard", set_name, elem_spec], check=True)
        print(f"{CLR_GREEN}[✔] IP-адрес {clean_ip} заблокирован {mode_desc} в таблице inet edr_guard.{CLR_RESET}")
        return True
    except Exception as e:
        print(f"{CLR_RED}[!] Ошибка применения правил nftables: {e}{CLR_RESET}")
        return False


def flush_nftables_rules():
    if os.geteuid() != 0:
        print(f"{CLR_RED}[!] Сброс правил nftables требует прав root (sudo).{CLR_RESET}")
        return False
    try:
        subprocess.run(["nft", "delete", "table", "inet", "edr_guard"], check=True, stderr=subprocess.PIPE)
        print(f"{CLR_GREEN}[✔] Все блокировки IP в таблице inet edr_guard успешно сняты.{CLR_RESET}")
        return True
    except subprocess.CalledProcessError:
        print(f"{CLR_YELLOW}[*] Таблица блокировок inet edr_guard уже пуста или не существует.{CLR_RESET}")
        return True


def audit_network_connections(auto_kill=False):
    print(f"\n{CLR_BOLD}=== МОДУЛЬ СЕТЕВОГО МОНИТОРИНГА И ДЕТЕКЦИИ RAT ==={CLR_RESET}")
    if os.geteuid() != 0:
        print(f"{CLR_YELLOW}[i] Совет: запустите с sudo для видимости системных процессов других пользователей.{CLR_RESET}")
    print(f"{'PID':<8} | {'ПРОЦЕСС':<15} | {'СТАТУС':<12} | {'АДРЕС':<25} | {'АРГУМЕНТЫ / ПУТЬ'}")
    print("─" * 95)
    alerts_found = 0
    try:
        res = subprocess.run(
        ["ss", "-H", "-tunap"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
        )
        lines = res.stdout.strip().splitlines()
    except Exception as e:
        print(f"{CLR_RED}[!] Ошибка запуска сетевого сканера: {e}{CLR_RESET}")
        return 0
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[1]
        local = parts[4]
        peer = parts[5] if len(parts) > 5 else "*:*"
        pid = None
        pname = "-"
        match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if match:
            pname = match.group(1)
            pid = int(match.group(2))
        exe_path = "-"
        cmdline = ""
        is_suspicious = False
        reasons = []
        if pid:
            try:
                exe_path = os.path.realpath(f"/proc/{pid}/exe")
                try:
                    with open(f"/proc/{pid}/cmdline", "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
                except Exception:
                    cmdline = ""
                cwd = ""
                try:
                    cwd = os.path.realpath(f"/proc/{pid}/cwd")
                except Exception:
                    pass
                temp_dirs = ("/tmp", "/var/tmp", "/dev/shm")
                if (any(exe_path.startswith(d) for d in temp_dirs) or
                any(d in cmdline for d in temp_dirs) or
                any(cwd.startswith(d) for d in temp_dirs)):
                    is_suspicious = True
                    reasons.append("Запуск из временного каталога")
                is_flatpak = exe_path.startswith("/app/")
                if "(deleted)" in exe_path or (not is_flatpak and not os.path.exists(exe_path)):
                    is_suspicious = True
                    reasons.append("Удален исполняемый файл")
                if pname in {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat"}:
                    is_suspicious = True
                    reasons.append("Командная оболочка с сетевым сокетом")
                if pname.startswith("python") and ("-c " in cmdline or not cmdline.endswith(".py")):
                    is_suspicious = True
                    reasons.append("Инлайн-скрипт Python слушает сокет")
            except (FileNotFoundError, PermissionError):
                pass
        addr_str = f"{local} -> {peer}" if state == "ESTAB" else local
        display_info = cmdline[:45] if cmdline else exe_path
        if is_suspicious:
            alerts_found += 1
            print(f"{CLR_RED}{str(pid or '-'):<8} | {pname:<15} | {state:<12} | {addr_str:<25} | {display_info}{CLR_RESET}")
            print(f"   {CLR_YELLOW}↳ ТРЕВОГА: {', '.join(reasons)}{CLR_RESET}")
            if auto_kill and pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                    print(f"   {CLR_GREEN}↳ [ЛИКВИДИРОВАН] Процесс PID {pid} принудительно завершен (SIGKILL).{CLR_RESET}")
                except Exception as ex:
                    print(f"   {CLR_RED}↳ [ОШИБКА ЛИКВИДАЦИИ] Не удалось убить PID {pid}: {ex}{CLR_RESET}")
        else:
            print(f"{str(pid or '-'):<8} | {pname:<15} | {state:<12} | {addr_str:<25} | {display_info}")
    print("─" * 95)
    if alerts_found == 0:
        print(f"{CLR_GREEN}[✔] Аномальных и скрытых сетевых соединений не обнаружено.{CLR_RESET}\n")
    else:
        print(f"{CLR_RED}[✖ ВНИМАНИЕ] Обнаружено подозрительных сокетов: {alerts_found}!{CLR_RESET}\n")
    return alerts_found


def run_behavioral_audit():
    print(f"\n{CLR_BOLD}=== ПОВЕДЕНЧЕСКИЙ АНАЛИЗ АКТИВНЫХ ПРОЦЕССОВ (BEHAVIORAL EDR) ==={CLR_RESET}")
    findings = BehavioralAnalyzer.scan_running_processes()
    if not findings:
        print(f"{CLR_GREEN}[✔] Подозрительных цепочек процессов и поведенческих аномалий не обнаружено.{CLR_RESET}\n")
        return 0
    for info, alerts in findings:
        print(f"{CLR_RED}[✖ PID {info['pid']}] {info['comm']} (родитель: {info['parent_comm']} [PPID {info['ppid']}]){CLR_RESET}")
        if info["cmdline"]:
            print(f"    Команда: {info['cmdline'][:80]}")
        for a in alerts:
            print(f"    {CLR_YELLOW}↳ {a}{CLR_RESET}")
        print()
    return len(findings)


def update_threat_intel(cache_db, gpg_verify_file=None, quiet=False):
    if not quiet:
        print(f"\n{CLR_BOLD}=== ОБНОВЛЕНИЕ БАЗЫ THREAT INTELLIGENCE (IoC / Global Feeds) ==={CLR_RESET}")
    url = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"
    try:
        system_ca = "/etc/ssl/certs/ca-certificates.crt"
        ctx = ssl.create_default_context(cafile=system_ca) if os.path.exists(system_ca) else ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "Orlitum-EDR-Community/1.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            content = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        if not quiet:
            print(f"{CLR_RED}[✖] Ошибка загрузки базы: {e}{CLR_RESET}\n")
        return 0
    batch = [(l.strip().lower(), "ThreatFeed_SHA256") for l in content.splitlines()[:15000] if len(l.strip()) == 64]
    sys_h = {v[0] for v in cache_db.get_baseline().values()} | {hash_file_sha256(b) for b in CRITICAL_BINARIES}
    batch = [x for x in batch if x[0] not in sys_h]
    if not batch:
        return 0
    try:
        with sqlite3.connect(getattr(cache_db, 'intel_db_path', cache_db.db_path), timeout=15.0) as conn:
            conn.executemany("INSERT OR IGNORE INTO known_threats (sha256, malware_family) VALUES (?, ?)", batch)
            conn.commit()
            total_count = conn.execute("SELECT COUNT(*) FROM known_threats").fetchone()[0]
        if not quiet:
            print(f"{CLR_GREEN}[✔] База обновлена. Активных сигнатур угроз: {total_count}{CLR_RESET}\n")
        return total_count
    except sqlite3.Error:
        return 0


def background_periodic_auditor(cache_db, stop_event, interval=60, hb_interval=300):
    bad_procs = {"sh", "bash", "dash", "zsh", "nc", "ncat", "socat"}
    temp_dirs = ("/tmp/", "/var/tmp/", "/dev/shm/")
    last_hb = time.time()
    last_intel_update = time.time()
    send_heartbeat()
    while not stop_event.wait(interval):
        try:
            now = time.time()
            if hb_interval > 0 and now - last_hb >= hb_interval:
                send_heartbeat()
                last_hb = now
            if now - last_intel_update >= 86400:
                update_threat_intel(cache_db, quiet=True)
                last_intel_update = now
            seen_pids = set()
            res = subprocess.run(["ss", "-H", "-tunap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in res.stdout.strip().splitlines():
                match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if match:
                    pname, pid = match.group(1), int(match.group(2))
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                    exe_path = ""
                    try:
                        exe_path = os.path.realpath(f"/proc/{pid}/exe")
                    except (FileNotFoundError, PermissionError):
                        pass
                    if pname in bad_procs or exe_path.startswith(temp_dirs):
                        notify_throttled(
                        key=f"net_{pname}_{pid}",
                        title="EDR Сетевая Тревога",
                        message=f"Подозрительный процесс в сети: {pname} (PID {pid})",
                        icon="dialog-warning"
                        )
            baseline = cache_db.get_baseline()
            for b in CRITICAL_BINARIES:
                real_p = os.path.realpath(b)
                if os.path.exists(real_p) and real_p in baseline:
                    base_hash, stored_hmac = baseline[real_p]
                    expected_hmac = cache_db.compute_hmac(real_p, base_hash)
                    h = hash_file_sha256(real_p)
                    if h and h != base_hash:
                        notify_throttled(
                        key=f"fim_{real_p}",
                        title="EDR FIM Тревога",
                        message=f"Изменен системный файл: {real_p}!",
                        icon="security-low",
                        cooldown=1800
                        )
                    elif h == base_hash and expected_hmac and stored_hmac != expected_hmac:
                        cache_db.update_baseline(real_p, base_hash)
            for info, alerts in BehavioralAnalyzer.scan_running_processes():
                notify_throttled(
                key=f"beh_{info['pid']}_{info['comm']}",
                title="EDR Поведенческая Тревога",
                message=f"{info['comm']} (PID {info['pid']}): {alerts[0]}",
                icon="security-low"
                )
        except Exception:
            pass


def audit_persistence():
    print(f"\n{CLR_BOLD}=== РАСШИРЕННЫЙ АУДИТ ТОЧЕК ЗАКРЕПЛЕНИЯ (PERSISTENCE v3.2) ==={CLR_RESET}")
    threats = []
    suspicious_tokens = [
    "curl ", "wget ", "python -c", "python3 -c",
    "nc -", "ncat ", "socat ", "sh -i", "bash -i",
    "/dev/tcp/", "| sh", "| bash", "base64 -d"
    ]
    import errno, stat
    ld_preload = "/etc/ld.so.preload"
    try:
        fd = os.open(ld_preload, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload} (not_reg)")
            else:
                raw = os.read(fd, 4097)
                if len(raw) > 4096:
                    threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload} (truncated)")
                else:
                    content = raw.decode("utf-8", errors="ignore").strip()
                    if content:
                        threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload}: {content}")
        finally:
            os.close(fd)
    except FileNotFoundError:
        pass
    except OSError as e:
        if e.errno == errno.ELOOP:
            threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload} (symlink)")
        elif e.errno in (errno.EACCES, errno.EPERM):
            threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload} (denied)")
        else:
            threats.append(f"КРИТИЧЕСКИЙ РУТКИТ: {ld_preload} (other)")
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs", "/etc/apt/apt.conf.d", "/etc/dnf/plugins", "/etc/pacman.d/hooks", "/etc/udev/rules.d"]
    for cp in cron_paths:
        if os.path.exists(cp):
            targets = []
            if os.path.isdir(cp):
                try:
                    targets = [os.path.join(cp, e) for e in os.listdir(cp)]
                except PermissionError:
                    continue
            else:
                targets = [cp]
            for fp in targets:
                if os.path.isfile(fp):
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            c = f.read()
                        if any(x in c for x in suspicious_tokens) or SUSPICIOUS_TMP_EXEC_REGEX.search(c):
                            threats.append(f"Подозрительное задание cron: {fp}")
                    except Exception:
                        pass
    home_dirs = {get_real_user_home()}
    if os.geteuid() == 0:
        home_dirs.add("/root")
        if os.path.exists("/home"):
            for u in os.listdir("/home"):
                home_dirs.add(os.path.join("/home", u))
    shell_files = ["/etc/rc.local"]
    if os.path.exists("/etc/profile.d"):
        try:
            shell_files.extend(os.path.join("/etc/profile.d", f) for f in os.listdir("/etc/profile.d") if f.endswith(".sh"))
        except PermissionError:
            pass
    for hd in home_dirs:
        for rc_name in (".bashrc", ".profile", ".bash_profile", ".zshrc", ".config/fish/config.fish"):
            shell_files.append(os.path.join(hd, rc_name))
    for sf in sorted(set(shell_files)):
        if os.path.isfile(sf):
            try:
                with open(sf, "r", encoding="utf-8", errors="ignore") as f:
                    for idx, line in enumerate(f, 1):
                        s_line = line.strip()
                        if s_line.startswith("#"):
                            continue
                        if (any(p in s_line for p in ["base64 -d", "/dev/tcp/", "| sh", "| bash"]) or
                        SUSPICIOUS_TMP_EXEC_REGEX.search(s_line)):
                            threats.append(f"Подозрительная команда в {sf}:{idx}")
            except Exception:
                pass
    systemd_dirs = ["/etc/systemd/system"]
    for hd in home_dirs:
        systemd_dirs.append(os.path.join(hd, ".config/systemd/user"))
    for sd in systemd_dirs:
        if os.path.isdir(sd):
            try:
                for entry in os.listdir(sd):
                    if entry.endswith((".service", ".timer")):
                        fp = os.path.join(sd, entry)
                        if os.path.isfile(fp):
                            try:
                                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                if any(t in content for t in suspicious_tokens) or SUSPICIOUS_TMP_EXEC_REGEX.search(content):
                                    threats.append(f"Подозрительный systemd unit: {fp}")
                            except Exception:
                                pass
            except Exception:
                pass
    for hd in home_dirs:
        ak = os.path.join(hd, ".ssh/authorized_keys")
        if os.path.isfile(ak) and "command=" in open(ak, errors="ignore").read():
            threats.append(f"Подозрительный триггер command= в {ak}")
        ad = os.path.join(hd, ".config/autostart")
        if os.path.isdir(ad):
            for e in os.listdir(ad):
                fp = os.path.join(ad, e)
                if e.endswith(".desktop") and os.path.isfile(fp):
                    c = open(fp, errors="ignore").read()
                    if any(x in c for x in suspicious_tokens):
                        threats.append(f"Подозрительный XDG автозапуск: {fp}")
    if os.path.isdir("/etc/pam.d"):
        for e in os.listdir("/etc/pam.d"):
            fp = os.path.join("/etc/pam.d", e)
            if os.path.isfile(fp) and "pam_exec.so" in open(fp, errors="ignore").read():
                threats.append(f"Подозрительный модуль PAM (pam_exec): {fp}")

    if not threats:
        print(f"{CLR_GREEN}[✔] Все 10 векторов автозапуска чисты.{CLR_RESET}\n")
    else:
        for t in threats:
            print(f"{CLR_RED}[✖ ВНИМАНИЕ] {t}{CLR_RESET}")
        print()
    return threats


def _check(condition, message):
    if not condition:
        raise AssertionError(message)


def run_self_tests():
    print(f"\n{CLR_BOLD}=== ЗАПУСК ВСТРОЕННЫХ АВТОТЕСТОВ (SELF-TEST v3.2) ==={CLR_RESET}")
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        q_dir = os.path.join(tmpdir, "quarantine")
        log_file = os.path.join(tmpdir, "audit.jsonl")
        s = ScannerCore(quarantine_dir=q_dir, output_log=log_file, notify=False, max_log_bytes=200)
        _check(is_subpath("/home/user/antivirus/x", "/home/user/antivirus"), "Ошибка is_subpath")
        _check(s.check_double_extension("invoice_2026.pdf.sh"), "Пропуск двойного расширения")
        _check(is_interpreter_binary("/usr/bin/python3.12 (deleted)"), "Не распознан python (deleted)")
        _check(not s.is_whitelisted("/tmp/target/malware.elf"), "Белый список пропустил /tmp")
        _check(not is_safe_restore_path("/etc/passwd"), "Пропущен /etc/passwd")
        test_file = os.path.join(tmpdir, "evil.sh")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\necho test\n")
        os.chmod(test_file, 0o755)
        verdict = s.isolate_file(test_file, ["SelfTest"], [])
        _check(verdict == "Quarantined", "Файл не изолирован")
        restored = restore_quarantine_file(q_dir, "evil.sh")
        _check(restored and os.path.exists(test_file), "Файл не восстановлен")
        fake_proc = {
        "pid": 99999, "ppid": 99998, "comm": "bash", "parent_comm": "nc",
        "exe": "/bin/bash", "cmdline": "bash -i", "open_files": []
        }
        _check(len(BehavioralAnalyzer.evaluate_process_event(fake_proc)) > 0, "Детект Reverse Shell не сработал")
        _check(len(get_lineage(os.getpid())) > 0, "Ошибка get_lineage")
        _check(SigmaEngine.match([{"name": "sh"}, {"name": "nginx"}])[0], "Ошибка SigmaEngine")
        _check(is_dga_or_c2("curl http://x8k9m2p1q7z4v.xyz/a")[0], "Ошибка DGA")
        _check(len(BehavioralAnalyzer.evaluate_process_event({"cmdline": "python3 -c 'import pty; pty.spawn()'"})) > 0, "Ошибка Fileless")
        secret_msg = b"PayloadPinTest"
        enc = PinCryptoVault.encrypt_blob(secret_msg, "TestPIN123")
        _check(PinCryptoVault.decrypt_blob(enc, "Wrong") is None, "Сейф расшифрован с неверным PIN")
        _check(PinCryptoVault.decrypt_blob(enc, "TestPIN123") == secret_msg, "Сейф не восстановил исходный текст")
        print(f"{CLR_GREEN}{CLR_BOLD}[✔] ВСЕ СИСТЕМНЫЕ ТЕСТЫ БЕЗОПАСНОСТИ УСПЕШНО ПРОЙДЕНЫ!{CLR_RESET}\n")


def main():
    harden_process_memory()
    base_dir = get_default_base_dir()
    default_dl = get_default_downloads_dir()
    rules_path = os.path.join(base_dir, "rules")
    quarantine_path = os.path.join(base_dir, "quarantine")
    parser = argparse.ArgumentParser(description="EDR-агент Linux Mint (v3.2 Core Module)")
    parser.add_argument("--scan", type=str, default=None, help="Разовое сканирование папки или файла")
    parser.add_argument("--quarantine-list", action="store_true", help="Вывести список файлов в карантине")
    parser.add_argument("--restore", type=str, default=None, help="Восстановить файл из карантина (требует PIN)")
    parser.add_argument("--delete-quarantine", type=str, default=None, help="Удалить файл из карантина (требует PIN)")
    parser.add_argument("--setup-pin", action="store_true", help="Установить или изменить защитный PIN-код")
    parser.add_argument("--protect-agent", action="store_true", help="Заблокировать файлы агента через chattr +i")
    parser.add_argument("--unprotect-agent", action="store_true", help="Снять защиту chattr +i (требует PIN)")
    parser.add_argument("--disable", action="store_true", help="Остановить службу антивируса (требует PIN)")
    parser.add_argument("-w", "--watch", nargs="+", default=["/tmp", "/var/tmp", "/dev/shm", default_dl])
    parser.add_argument("-q", "--quarantine", default=quarantine_path)
    parser.add_argument("-r", "--rules", default=rules_path)
    parser.add_argument("-l", "--log", default=os.path.join(base_dir, "audit.jsonl"))
    parser.add_argument("--no-action", action="store_true")
    parser.add_argument("--init-integrity", action="store_true")
    parser.add_argument("--check-integrity", action="store_true")
    parser.add_argument("--init-self-hash", action="store_true")
    parser.add_argument("--audit-net", action="store_true")
    parser.add_argument("--kill-net", action="store_true")
    parser.add_argument("--yes-kill-net", action="store_true")
    parser.add_argument("--block-ip", type=str, default=None)
    parser.add_argument("--unblock-ip", action="store_true")
    parser.add_argument("--flush-nftables", action="store_true")
    parser.add_argument("--audit-behavior", action="store_true")
    parser.add_argument("--audit-persist", action="store_true")
    parser.add_argument("--update-intel", action="store_true")
    parser.add_argument("--tg-token", type=str, default=None)
    parser.add_argument("--tg-chat", type=str, default=None)
    parser.add_argument("--heartbeat-interval", type=int, default=300)
    parser.add_argument("--heartbeat-now", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.tg_token:
        _TG_CONFIG["token"] = args.tg_token
    if args.tg_chat:
        _TG_CONFIG["chat_id"] = args.tg_chat
    if args.self_test:
        run_self_tests()
        return
    if args.heartbeat_now:
        send_heartbeat()
        time.sleep(1.5)
        print(f"{CLR_GREEN}[✔] Сигнал Heartbeat отправлен.{CLR_RESET}")
        return
    db_dir = os.path.dirname(os.path.abspath(args.quarantine))
    db_path = os.path.join(db_dir, "cache.db")
    if args.setup_pin:
        PinCryptoVault.setup_pin(base_dir)
        return
    if args.protect_agent:
        manage_agent_immutable_protection(base_dir, enable=True)
        return
    if args.unprotect_agent:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        manage_agent_immutable_protection(base_dir, enable=False)
        return
    if args.disable:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        subprocess.run(["systemctl", "stop", "orlitum.service"] if os.geteuid() == 0 else ["systemctl", "--user", "stop", "orlitum.service"], check=False)
        print(f"{CLR_YELLOW}[*] Служба остановлена с подтверждением PIN.{CLR_RESET}")
        return
    if args.init_self_hash:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        manage_self_integrity(base_dir, init_mode=True)
        return
    if not manage_self_integrity(base_dir, init_mode=False):
        sys.exit(1)
    if args.block_ip:
        block_ip_nftables(args.block_ip)
        return
    if args.unblock_ip or args.flush_nftables:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        flush_nftables_rules()
        return
    if args.audit_behavior:
        run_behavioral_audit()
        return
    if args.audit_persist:
        audit_persistence()
        return
    if args.update_intel:
        cache = CacheDB(db_path)
        update_threat_intel(cache)
        return
    if args.init_integrity:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        cache = CacheDB(db_path)
        run_integrity_check(cache, init_mode=True)
        return
    if args.check_integrity:
        cache = CacheDB(db_path)
        run_integrity_check(cache, init_mode=False)
        return
    if args.audit_net:
        allow_kill = False
        if args.kill_net:
            if args.yes_kill_net and PinCryptoVault.verify_pin(base_dir):
                allow_kill = True
        audit_network_connections(auto_kill=allow_kill)
        return
    if args.quarantine_list:
        list_quarantine(args.quarantine)
        return
    if args.restore:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        restore_quarantine_file(args.quarantine, args.restore)
        return
    if args.delete_quarantine:
        if not PinCryptoVault.verify_pin(base_dir):
            sys.exit(1)
        delete_quarantine_file(args.quarantine, args.delete_quarantine)
        return
    scanner = ScannerCore(
    quarantine_dir=args.quarantine,
    rules_dir=args.rules,
    output_log=args.log,
    auto_quarantine=not args.no_action
    )
    if args.scan:
        scan_target = os.path.abspath(os.path.expanduser(args.scan))
        run_on_demand_scan(scan_target, scanner)
        return
    watch_dirs = [os.path.abspath(os.path.expanduser(d)) for d in args.watch if os.path.exists(os.path.expanduser(d))]
    handler = FileMonitorHandler(scanner)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
    stop_event = threading.Event()
    def handle_sig(signum, frame):
        stop_event.set()
    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGHUP, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)
    print(f"{CLR_GREEN}{CLR_BOLD}=== EDR СТРАЖ ЗАПУЩЕН (v3.2 Core Module) ==={CLR_RESET}")
    print(f"[*] Behavioral EDR: Кэширование процессов активно")
    print(f"[*] Threat Intelligence: Фоновое автообновление активно (каждые 24 часа)")
    print(f"[*] Карантин: Автоматическая защита chattr +i активна")
    print("Наблюдение активно...\n")
    cache = CacheDB(db_path)
    t = threading.Thread(
    target=background_periodic_auditor,
    args=(cache, stop_event, 60, args.heartbeat_interval),
    daemon=True
    )
    t.start()
    try:
        observer.start()
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        stop_event.set()
        observer.stop()
        observer.join()
        handler.executor.shutdown(wait=True)


if __name__ == "__main__":
    main()
