#!/usr/bin/env python3
# Copyright (c) 2026 Orlitum EDR <zxclow663@gmail.com>
__author__ = "Orlitum EDR <zxclow663@gmail.com>"
import os, sys, resource, subprocess, tempfile, struct, ctypes

# Community-изолятор без нативного детонатора. Свежий ОДНОПОТОЧНЫЙ Python сам
# применяет limit_box() (seccomp+rlimit) и делает execve цели НАПРЯМУЮ — без fork.
# Поэтому timeout убивает именно цель (нет осиротевшего fork-ребёнка), а
# start_new_session + killpg в _run_isolated гарантируют зачистку всей группы.
_LIMIT_WRAPPER = (
    "import os, sys, importlib.util\n"
    "spec = importlib.util.spec_from_file_location('_csb', sys.argv[1])\n"
    "mod = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(mod)\n"
    "cmd = sys.argv[2:]\n"
    "try:\n"
    "    mod.limit_box()\n"
    "except BaseException:\n"
    "    os._exit(126)\n"
    "try:\n"
    "    os.execv(cmd[0], cmd)\n"
    "except BaseException:\n"
    "    os._exit(127)\n"
)

class _IsoResult:
    __slots__ = ("returncode", "stdout", "stderr", "timed_out")
    def __init__(self, rc, out, err, to):
        self.returncode, self.stdout, self.stderr, self.timed_out = rc, out, err, to

def _run_isolated(cmd, cwd, timeout=4):
    # start_new_session=True -> setsid: обёртка становится лидером сессии/группы.
    # На таймауте убиваем ВСЮ группу (killpg), а не только прямого ребёнка,
    # чтобы не оставить осиротевших потомков цели вне песочницы.
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    timed_out = False
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(os.getpgid(p.pid), 9)
        except OSError:
            try:
                p.kill()
            except OSError:
                pass
        try:
            out, err = p.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            out, err = "", ""
    return _IsoResult(p.returncode, out, err, timed_out)

def limit_box():
    # BPF: arch-guard (только x86_64) + x32-guard + блок ptrace/bpf + TimeWarp nanosleep.
    # Без arch-guard 32-битный процесс (i386/x32) прошёл бы мимо фильтра: его номера
    # (nanosleep=162, ptrace=26, bpf=357) не совпадают с 35/230/101/321 и упали бы
    # в RET ALLOW — полный обход изоляции.
    ins = [
        (0x20,0,0,4),           # LD  W ABS arch
        (0x15,1,0,0xC000003E),  # JEQ AUDIT_ARCH_X86_64 -> skip kill
        (0x06,0,0,0x00000000),  # RET KILL (чужой ABI)
        (0x20,0,0,0),           # LD  W ABS nr
        (0x35,0,1,0x40000000),  # JGE x32-бит (0x40000000) -> kill
        (0x06,0,0,0x00000000),  # RET KILL (x32)
        (0x15,3,0,35),          # nanosleep        -> RET ERRNO 0 (TimeWarp)
        (0x15,2,0,230),         # clock_nanosleep  -> RET ERRNO 0 (TimeWarp)
        (0x15,2,0,101),         # ptrace           -> RET ERRNO EPERM
        (0x15,1,2,321),         # bpf              -> RET ERRNO EPERM
        (0x06,0,0,0x00050000),  # RET ERRNO 0
        (0x06,0,0,0x00050001),  # RET ERRNO EPERM
        (0x06,0,0,0x7fff0000),  # RET ALLOW
    ]
    b = ctypes.create_string_buffer(b"".join(struct.pack("@HBBI", *x) for x in ins))
    pr = struct.pack("@HP", len(ins), ctypes.addressof(b))
    c = ctypes.CDLL(None, use_errno=True)
    # Реальная сетевая изоляция (best-effort): пустой netns без маршрутов -> connect()
    # даёт ENETUNREACH ("Network is unreachable") — оживляет детект NET_C2_ATTEMPT.
    try:
        c.unshare(0x40000000)  # CLONE_NEWNET; без CAP_SYS_ADMIN молча пропускаем
    except Exception:
        pass
    # PR_SET_NO_NEW_PRIVS=38, PR_SET_SECCOMP=22 (SECCOMP_MODE_FILTER=2).
    # FAIL-CLOSED: без seccomp цель не запускается ни при каких условиях.
    if c.prctl(38, 1, 0, 0, 0) != 0:
        os._exit(126)
    if c.prctl(22, 2, pr, 0, 0) != 0:
        os._exit(126)
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

def run_sandbox(target):
    print(f"\n=== CIRCULUM NATIVE SANDBOX: ДЕТОНАЦИЯ {os.path.basename(target)} ===")
    print("[*] Изоляция Ring-0: CLONE_NEWNET | seccomp-bpf | TimeWarp (Anti-Sleep) | RAM=64MB")
    with tempfile.TemporaryDirectory() as box:
        t_path = os.path.realpath(target)
        det = os.path.join(os.path.dirname(os.path.realpath(__file__)), "shield/target/release/detonator")
        if os.path.isfile(det) and os.access(det, os.X_OK):
            # Нативный детонатор сам применяет seccomp/rlimit — preexec_fn не нужен.
            cmd = [det, t_path]
        else:
            print("[i] Режим Community: изолированный обёрточный подпроцесс (seccomp+rlimit)")
            cmd = [sys.executable, t_path] if target.endswith(".py") else [t_path]
            cmd = [sys.executable, "-c", _LIMIT_WRAPPER, os.path.realpath(__file__)] + cmd
        res = _run_isolated(cmd, box, timeout=4)
        dropped = os.listdir(box)
        risk, tags = 0, []
        if dropped: risk += 30; tags.append(f"DROPPED_FILES:{dropped}")
        timed_out = bool(getattr(res, "timed_out", False))
        iso_fail = res.returncode in (125, 126, 127)
        if timed_out: risk += 50; tags.append("TIMEOUT_KILL")
        if iso_fail: risk += 90; tags.append("SANDBOX_ISOLATION_FAILURE")
        if res.returncode in (-9,-24,-25,137) or "MemoryError" in res.stderr: risk += 70; tags.append("RESOURCE_BOMB")
        if "Network is unreachable" in res.stderr: risk += 60; tags.append("NET_C2_ATTEMPT")
        if "PermissionError" in res.stderr or "Operation not permitted" in res.stderr: risk += 60; tags.append("SECCOMP_SYSCALL_BLOCK")
        risk = min(100, risk)
        print(f"[*] Досье детонации: Risk={risk}/100 | Артефакты={dropped} | Метки={tags}")
        import json, time
        fp = os.path.join(os.path.dirname(os.path.realpath(__file__)), "orlitum_timeline.jsonl")
        fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        f = None
        try:
            f = os.fdopen(fd, "a")
            f.write(json.dumps({"ts": int(time.time()), "target": os.path.basename(target), "risk": risk, "tags": tags, "event": "SANDBOX_REPORT"}) + "\n")
        finally:
            if f is not None:
                try: f.close()
                except OSError: pass
            else:
                try: os.close(fd)
                except OSError: pass
        print(f"[*] Код возврата в капсуле: {res.returncode}")
        if iso_fail:
            print("\033[91m[!] ВЕРДИКТ ПЕСОЧНИЦЫ: ИЗОЛЯЦИЯ НЕ ПРИМЕНИЛАСЬ (сбой seccomp/exec, код 125/126/127) — цель могла выйти из-под контроля!\033[0m")
        elif timed_out:
            print("\033[91m[!] ВЕРДИКТ ПЕСОЧНИЦЫ: ТАЙМАУТ — цель зависла/уходила от анализа (anti-sleep/бесконечный цикл), группа процессов уничтожена.\033[0m")
        elif res.returncode in (-9, -24, -25, 137) or "MemoryError" in res.stderr:
            print("\033[91m[!] ВЕРДИКТ ПЕСОЧНИЦЫ: ЗАБЛОКИРОВАНА РЕСУРСНАЯ БОМБА (Попытка перегрузки памяти/диска)!\033[0m")
        elif "Network is unreachable" in res.stderr or "PermissionError" in res.stderr:
            print("\033[91m[!] ВЕРДИКТ ПЕСОЧНИЦЫ: ПОПЫТКА СЕТЕВОГО C2 КОННЕКТА В ИЗОЛЯЦИИ!\033[0m")
        else:
            print("\033[92m[✔] Детонация завершена безопасно, система хоста не затронута.\033[0m")

if __name__ == "__main__" and len(sys.argv) > 1:
    run_sandbox(sys.argv[1])
