#!/usr/bin/env bash
set -euo pipefail

EDR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_USER="${SUDO_USER:-$(whoami)}"
[ "$REAL_USER" = "root" ] && REAL_USER=""

echo "=== ORLITUM EDR UNIVERSAL INSTALLER ==="
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[*] Дистрибутив : ${PRETTY_NAME:-$ID}"
else
    ID="unknown"
    echo "[*] Дистрибутив : Unknown Linux"
fi
echo "[*] Папка EDR   : $EDR_DIR (Пользователь: ${REAL_USER:-root})"

# Определение активного LSM (SELinux / AppArmor)
LSM="none"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    LSM="selinux"
elif [ -d /sys/kernel/security/apparmor ]; then
    LSM="apparmor"
fi
echo "[*] Активный LSM: $LSM"

if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "[✔] Ядро BTF    : Поддерживается"
else
    echo "[!] Ядро BTF    : Не обнаружено (работа в режиме User-Space)"
fi

# Установка системных зависимостей по семейству дистрибутива
case "${ID:-}" in
    fedora|rhel|centos|rocky|almalinux)
        sudo dnf install -y -q python3 python3-yara python3-watchdog yara nftables iproute policycoreutils-python-utils
        ;;
    ubuntu|debian|kali|linuxmint|pop)
        export DEBIAN_FRONTEND=noninteractive
        sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-yara python3-watchdog python3-yaml nftables iproute2
        ;;
    arch|manjaro|endeavouros)
        sudo pacman -Sy --noconfirm --needed python python-yara python-watchdog nftables iproute2
        ;;
    opensuse*|sles)
        sudo zypper --non-interactive install -y python3 python3-yara python3-watchdog nftables iproute2
        ;;
    *)
        echo "[!] Неизвестный пакетный менеджер (${ID:-unknown}). Убедитесь, что установлены: python3, yara-python, watchdog, nftables, iproute2."
        ;;
esac

chmod +x "$EDR_DIR/orlitum.py" "$EDR_DIR/orlitum_sandbox.py" "$EDR_DIR/orlitum_menu.sh" "$EDR_DIR/install.sh"

# Настройка службы systemd (если systemd доступен и каталог /etc/systemd/system существует)
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    sudo tee /etc/systemd/system/orlitum.service >/dev/null << UNIT
[Unit]
Description=Orlitum EDR Autonomous Host Defense Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=$EDR_DIR
Environment=ORLITUM_HOME=$EDR_DIR
ExecStart=/usr/bin/python3 $EDR_DIR/orlitum.py --monitor
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
    if [ -d /run/systemd/system ]; then
        sudo systemctl daemon-reload
        sudo systemctl enable --now orlitum.service
        echo "[✔] Служба orlitum.service активирована и запущена."
    else
        echo "[!] systemd не является PID 1 (контейнер/chroot) — юнит создан, но запуск пропущен."
    fi
else
    echo "[!] systemd не обнаружен — установка завершена в standalone-режиме."
fi

echo "[✔] Установка Orlitum EDR завершена! Запуск меню: ./orlitum_menu.sh"
