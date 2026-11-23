#!/bin/bash
# Copyright (c) 2026 Orlitum EDR <zxclow663@gmail.com>
clear() { command clear 2>/dev/null || printf "\033c"; }
sudo -v || exit 1
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[1;32m"
CLR_RED="\033[31m"
CLR_CYAN="\033[36m"
CLR_WHITE_NUM="\033[1;37m"
CLR_YELLOW="\033[33m"

while true; do
    CUR_L=$(python3 "$DIR/orlitum_tuning.py" --get-lang 2>/dev/null || echo "ru")
    clear
    [ -f "$DIR/ouroboros_art.txt" ] && echo -e "${CLR_GREEN}" && cat "$DIR/ouroboros_art.txt" && echo -e "${CLR_RESET}"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "                 ${CLR_GREEN}🛡 ORLITUM EDR CONTROL PANEL${CLR_RESET}"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    echo -e "${CLR_WHITE_NUM} 1.${CLR_RESET} Запустить полный аудит (--audit-all)"
    echo -e "${CLR_WHITE_NUM} 2.${CLR_RESET} Обновить базы Threat Intelligence / IoC (--update-intel)"
    echo -e "${CLR_WHITE_NUM} 3.${CLR_RESET} Установить/сменить PIN-код (--setup-pin)"
    echo -e "${CLR_WHITE_NUM} 4.${CLR_RESET} Проверить статус службы EDR"
    echo -e "${CLR_WHITE_NUM} 5.${CLR_RESET} Перезапустить службу EDR"
    echo -e "${CLR_WHITE_NUM} 6.${CLR_RESET} Посмотреть файлы в карантине"
    echo -e "${CLR_WHITE_NUM} 7.${CLR_RESET} Восстановить файл из карантина"
    echo -e "${CLR_WHITE_NUM} 8.${CLR_RESET} Добавить путь/имя в Whitelist"
    echo -e "${CLR_WHITE_NUM} 9.${CLR_RESET} Отправить тестовый Telegram Heartbeat"
    echo -e "${CLR_WHITE_NUM} 10.${CLR_RESET} Активные внешние сетевые соединения (ESTABLISHED)"
    echo -e "${CLR_WHITE_NUM} 11.${CLR_RESET} Открытые прослушиваемые порты и службы (LISTEN)"
    echo -e "${CLR_WHITE_NUM} 12.${CLR_RESET} ${CLR_GREEN}[LIVE]${CLR_RESET} Журнал событий и логи EDR в реальном времени"
    echo -e "${CLR_WHITE_NUM} 13.${CLR_RESET} [93m[SANDBOX][0m Запустить файл в изолированной капсуле ядра"
    echo -e "${CLR_WHITE_NUM} 14.${CLR_RESET} Карта каталогов и файлов EDR"
echo -e "${CLR_WHITE_NUM} 15.${CLR_RESET} ${CLR_CYAN}[TREE]${CLR_RESET} Граф атак и инцидентов"
echo -e "${CLR_WHITE_NUM} 16.${CLR_RESET} ${CLR_RED}[ROOTKIT]${CLR_RESET} Сканер скрытых процессов"
echo -e "${CLR_WHITE_NUM} 17.${CLR_RESET} [FIREWALL] Сетевой карантин хоста"
echo -e "${CLR_WHITE_NUM} 18.${CLR_RESET} [LSM] Статус модуля безопасности"
echo -e "${CLR_WHITE_NUM} 19.${CLR_RESET} [TUNING] Матрица: Стационар <-> Сервер"
echo -e "${CLR_WHITE_NUM} 20.${CLR_RESET} ${CLR_RED}[STOP]${CLR_RESET} Остановить EDR (PIN)"
echo -e "${CLR_WHITE_NUM}  L.${CLR_RESET} [LANG] Язык / Language [${CLR_GREEN}${CUR_L^^}${CLR_RESET}]"
echo -e "${CLR_WHITE_NUM} 0.${CLR_RESET} Выход"
    echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
    read -p "Выберите действие [0-20/L]: " choice

    case "$choice" in
        1) python3 "$DIR/orlitum.py" --check-integrity
        python3 "$DIR/orlitum.py" --audit-net
        python3 "$DIR/orlitum.py" --audit-behavior
        python3 "$DIR/orlitum.py" --audit-persist ;;
        2) python3 "$DIR/orlitum.py" --update-intel ;;
        3) python3 "$DIR/orlitum.py" --setup-pin ;;
        4) python3 "$DIR/orlitum_tuning.py" --status ;;
        5) (sudo systemctl restart orlitum.service 2>/dev/null || (pkill -f "orlitum.py" 2>/dev/null; nohup python3 "$DIR/orlitum.py" >> "$DIR/daemon.log" 2>&1 &)) && echo -e "${CLR_GREEN}[✔] Служба перезапущена.${CLR_RESET}" ;;
        6) python3 "$DIR/orlitum.py" --quarantine-list ;;
        7) read -p "Имя файла в карантине: " qfile; [ -n "$qfile" ] && python3 "$DIR/orlitum.py" --restore "$qfile" || echo "Отменено." ;;
        8) python3 "$DIR/orlitum_tuning.py" --whitelist-banner; read -p "Путь/имя для Whitelist: " wpath; [ -n "$wpath" ] && echo "$wpath" >> "$DIR/whitelist.txt" && echo -e "${CLR_GREEN}[✔] Добавлено в whitelist.txt${CLR_RESET}" || echo "Отменено." ;;
        9) python3 "$DIR/orlitum.py" --heartbeat-now ;;
        10)
            while true; do
                clear
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                echo -e "     ${CLR_BOLD}${CLR_CYAN}=== ВНЕШНИЕ СЕТЕВЫЕ СОЕДИНЕНИЯ (ESTABLISHED) ===${CLR_RESET}"
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                ss -tunap state established
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                echo -e "${CLR_WHITE_NUM} [1]${CLR_RESET} Принудительно завершить процесс (Kill PID)"
                echo -e "${CLR_WHITE_NUM} [2]${CLR_RESET} ${CLR_RED}Заблокировать IP (Firewall Ban)${CLR_RESET}"
                echo -e "${CLR_WHITE_NUM} [0]${CLR_RESET} Вернуться в главное меню"
                echo -e "${CLR_CYAN}----------------------------------------------------------------------${CLR_RESET}"
                read -p "Действие [0-2]: " net_act
                case "$net_act" in
                    1)
                        read -p "Введите PID процесса: " kpid
                        if [ -n "$kpid" ]; then
                            kill -9 "$kpid" 2>/dev/null || sudo kill -9 "$kpid" 2>/dev/null
                            echo -e "${CLR_GREEN}[✔] Процесс $kpid завершен.${CLR_RESET}"
                            sleep 1.2
                        fi
                        ;;
                    2)
                        read -p "Введите IP адрес для блокировки: " ban_ip
                        if [ -n "$ban_ip" ]; then
                            sudo python3 "$DIR/orlitum.py" --block-ip "$ban_ip"
                            echo -e "${CLR_RED}[✔] IP $ban_ip заблокирован.${CLR_RESET}"
                            sleep 1.5
                        fi
                        ;;
                    *) break ;;
                esac
            done
            continue ;;
        11)
            while true; do
                clear
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                echo -e "         ${CLR_BOLD}${CLR_CYAN}=== ПРОСЛУШИВАЕМЫЕ ПОРТЫ И СЛУЖБЫ (LISTEN) ===${CLR_RESET}"
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                sudo ss -tulnp
                echo -e "${CLR_CYAN}======================================================================${CLR_RESET}"
                echo -e "${CLR_WHITE_NUM} [1]${CLR_RESET} Принудительно завершить службу по PID (Kill PID)"
                echo -e "${CLR_WHITE_NUM} [0]${CLR_RESET} Вернуться в главное меню"
                echo -e "${CLR_CYAN}----------------------------------------------------------------------${CLR_RESET}"
                read -p "Действие [0-1]: " l_act
                case "$l_act" in
                    1)
                        read -p "Введите PID службы для завершения: " lpid
                        if [ -n "$lpid" ]; then
                            sudo kill -9 "$lpid" 2>/dev/null || kill -9 "$lpid" 2>/dev/null
                            echo -e "${CLR_GREEN}[✔] Процесс $lpid остановлен.${CLR_RESET}"
                            sleep 1.2
                        fi
                        ;;
                    *) break ;;
                esac
            done
            continue ;;
        12)
            clear
            echo -e "${CLR_BOLD}${CLR_GREEN}=== ORLITUM EDR: МОНИТОРИНГ ЛОГОВ (PRO) ===${CLR_RESET}"
            echo " 1) Полный системный поток службы"
            echo " 2) Только боевые алерты ядра (eBPF, FAN_DENY, W^X, YARA)"
            echo " 3) Структурированный лог аудита (audit.jsonl)"
            echo ""
            read -p "Режим [1-3]: " lch
            clear
            echo -e "${CLR_YELLOW}Для возврата нажмите [Ctrl+C]${CLR_RESET}\n"
            trap 'echo -e "\n${CLR_GREEN}[✔] Возврат...${CLR_RESET}"; sleep 0.8' INT
            case "$lch" in
                1) sudo journalctl -u orlitum.service -f -n 30 || true ;;
                2) sudo journalctl -u orlitum.service -f -n 100 | grep --line-buffered -E "ALERT|Fileless|BLOCK|БЛОКИРОВКА|САМОЗАЩИТА|HUNTER|RWX|YARA|FAN_DENY" || true ;;
                3) [ -f "$DIR/audit.jsonl" ] && tail -f -n 20 "$DIR/audit.jsonl" || echo "[!] Файл audit.jsonl пока пуст" ;;
                *) echo "Неверный выбор" ;;
            esac
            trap - INT ;;
        13) read -p "Путь к файлу для детонации: " sbf; [ -n "$sbf" ] && python3 "$DIR/orlitum_sandbox.py" "$sbf"; read -p "Enter..." ;;
        14) echo "DIR: $DIR | Rules: $DIR/rules | Quarantine: $DIR/quarantine" ;;
        15) tail -n 25 "$DIR/orlitum_timeline.jsonl" 2>/dev/null || echo "Журнал пуст" ;;
        16) python3 "$DIR/orlitum.py" --audit-persist && python3 "$DIR/orlitum.py" --audit-behavior ;;
        17) read -p "[1] Включить [2] Снять: " na; [ "$na" = "1" ] && read -p "IP: " bip; sudo python3 "$DIR/orlitum.py" --block-ip "$bip"; [ "$na" = "2" ] && sudo python3 "$DIR/orlitum.py" --flush-nftables ;;
        18) cat /sys/kernel/security/lsm 2>/dev/null; echo ""; read -p "[1] Включить BPF-LSM (GRUB)  [2] Отключить BPF-LSM  [Enter] Назад: " l_op; [ "$l_op" = "1" ] && sudo "$DIR/shield/target/release/admin_ctl" --enable-lsm; [ "$l_op" = "2" ] && sudo "$DIR/shield/target/release/admin_ctl" --disable-lsm ;;
        19) python3 "$DIR/orlitum_tuning.py" --matrix ;;
        20) python3 "$DIR/orlitum.py" --disable ;;
        l|L) python3 "$DIR/orlitum_tuning.py" --toggle-lang >/dev/null ;;
        0) exit 0 ;;
        *) echo "Неверный ввод" ;;
    esac
    echo ""
    read -p "Нажмите Enter для возврата..." dummy
done
