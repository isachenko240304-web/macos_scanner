#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import os
import plistlib
import datetime
import sys
from collections import Counter
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def run_cmd(cmd: str, timeout: int = 10, use_sudo: bool = False) -> str:
    """Безопасный запуск shell-команды с таймаутом и без sudo по умолчанию."""
    try:
        if use_sudo and os.geteuid() != 0:
            # Если нужен sudo, но нет прав, возвращаем ошибку
            return "ERROR: требуются права root"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"ERROR: команда не завершилась за {timeout} секунд"
    except Exception as e:
        return f"ERROR: {str(e)}"

class MacOSSecurityScanner:
    def __init__(self):
        self.results = {}

    def run_all_checks(self):
        print(Colors.BOLD + "\n    СКАНИРОВАНИЕ БЕЗОПАСНОСТИ macOS\n" + Colors.ENDC)
        self.check_os_version()
        self.check_hostname_workgroup()
        self.check_security_updates()
        self.check_admin_accounts()
        self.check_password_policy()
        self.check_audit_system()
        self.check_network_settings()
        self.check_shared_resources()
        self.check_running_services()
        self.check_filesystem()
        self.check_registry_macos()
        self.check_group_policies()
        self.check_additional_params()
        self.check_logs()
        self.check_port_scan()
        self.print_summary()

    # 1. Вид ОС
    def check_os_version(self):
        print(Colors.OKCYAN + "[1] Вид ОС" + Colors.ENDC)
        product_name = run_cmd("sw_vers -productName")
        product_version = run_cmd("sw_vers -productVersion")
        build = run_cmd("sw_vers -buildVersion")
        kernel = run_cmd("uname -r")
        details = {
            "OS": f"{product_name} {product_version} ({build})",
            "Kernel": kernel
        }
        status = "OK" if product_version.startswith("15.") else "WARN"
        recs = [] if status == "OK" else ["Рекомендуется обновить macOS до версии Sequoia 15.x"]
        self.results[1] = {"name": "Вид ОС", "status": status, "details": details, "recommendations": recs}
        print(f"  {product_name} {product_version}, ядро {kernel}")

    # 2. Имя узла, рабочая группа/домен
    def check_hostname_workgroup(self):
        print(Colors.OKCYAN + "[2] Имя узла, рабочая группа / домен" + Colors.ENDC)
        hostname = run_cmd("scutil --get ComputerName")
        local_hostname = run_cmd("scutil --get LocalHostName")
        workgroup = "WORKGROUP"
        smb_conf = Path("/etc/smb.conf")
        if smb_conf.exists():
            try:
                with open(smb_conf) as f:
                    content = f.read()
                    m = re.search(r'workgroup\s*=\s*(\S+)', content, re.I)
                    if m:
                        workgroup = m.group(1)
            except:
                pass
        ad_info = run_cmd("dsconfigad -show 2>/dev/null | grep 'Active Directory Domain'")
        domain = ad_info.split(":")[-1].strip() if ad_info else "Не присоединён к AD"
        details = {
            "Имя компьютера": hostname,
            "Локальное имя": local_hostname,
            "Рабочая группа (SMB)": workgroup,
            "Домен": domain
        }
        status = "OK"
        recs = []
        if "Не присоединён" in domain and workgroup == "WORKGROUP":
            recs.append("Для корпоративной среды рассмотрите присоединение к домену AD.")
        self.results[2] = {"name": "Имя узла, рабочая группа/домен", "status": status, "details": details, "recommendations": recs}
        print(f"  Имя: {hostname}, Рабочая группа: {workgroup}, Домен: {domain}")

    # 3. Обновления безопасности
    def check_security_updates(self):
        print(Colors.OKCYAN + "[3] Обновления безопасности" + Colors.ENDC)
        history_file = "/Library/Receipts/InstallHistory.plist"
        updates = []
        if os.path.exists(history_file):
            try:
                with open(history_file, 'rb') as f:
                    data = plistlib.load(f)
                    for item in data:
                        if 'displayName' in item and ('Security' in item['displayName'] or 'Update' in item['displayName']):
                            updates.append(item['displayName'])
            except:
                pass
        pending = run_cmd("softwareupdate --list 2>&1")
        has_pending = "No new software" not in pending and "Software Update Tool" in pending
        details = {
            "Установленные обновления безопасности": updates[:10],
            "Ожидающие обновления": "Да" if has_pending else "Нет"
        }
        status = "WARN" if has_pending else "OK"
        recs = []
        if has_pending:
            recs.append("Установите доступные обновления: sudo softwareupdate -i -a")
        self.results[3] = {"name": "Обновления безопасности", "status": status, "details": details, "recommendations": recs}
        print(f"  Ожидающих обновлений: {'есть' if has_pending else 'нет'}")

    # 4. Учетные записи администраторов (без sudo, без зависаний)
    def check_admin_accounts(self):
        print(Colors.OKCYAN + "[4] Учетные записи администраторов" + Colors.ENDC)
        # Получаем список обычных пользователей (UID >= 500) без системных
        output = run_cmd("dscl . list /Users | grep -v '^_'")
        users = output.splitlines()
        admin_users = []
        for user in users:
            # Проверяем членство в группе admin (не требует sudo)
            check = run_cmd(f"dseditgroup -o checkmember -m {user} admin 2>/dev/null")
            if "yes" in check.lower():
                admin_users.append(user)
        # Оценка наличия пароля – пропустим, так как требует sudo, просто отметим
        details = {
            "Администраторы": admin_users,
            "Примечание": "Проверка наличия паролей требует прав root"
        }
        status = "OK"  # без sudo не можем проверить слабые пароли, считаем OK
        recs = []
        if len(admin_users) > 3:
            recs.append("Много администраторов – сократите их число до необходимого минимума.")
        self.results[4] = {"name": "Учетные записи администраторов", "status": status, "details": details, "recommendations": recs}
        print(f"  Администраторы: {', '.join(admin_users)}")

    # 5. Политика паролей
    def check_password_policy(self):
        print(Colors.OKCYAN + "[5] Политика паролей" + Colors.ENDC)
        policy_output = run_cmd("pwpolicy -getaccountpolicies 2>/dev/null")
        details = {}
        recs = []
        if not policy_output or policy_output.startswith("ERROR"):
            details["Политика"] = "Не задана или не удалось прочитать"
            recs.append("Настройте политику паролей через pwpolicy или профиль конфигурации.")
            status = "WARN"
        else:
            min_len = re.search(r'minChars\D*(\d+)', policy_output)
            max_age = re.search(r'maxPwdAge\D*(\d+)', policy_output)
            history = re.search(r'history\D*(\d+)', policy_output)
            details = {
                "Минимальная длина": min_len.group(1) if min_len else "не задана",
                "Максимальный возраст (сек)": max_age.group(1) if max_age else "не ограничен",
                "История паролей": history.group(1) if history else "не задана"
            }
            status = "OK"
            if min_len and int(min_len.group(1)) < 8:
                recs.append("Увеличьте минимальную длину пароля до 8 символов.")
                status = "WARN"
            if max_age and int(max_age.group(1)) > 7776000:
                recs.append("Установите срок действия пароля не более 90 дней.")
                status = "WARN"
        self.results[5] = {"name": "Политика паролей", "status": status, "details": details, "recommendations": recs}
        print(f"  {details}")

    # 6. Аудит системы
    def check_audit_system(self):
        print(Colors.OKCYAN + "[6] Аудит системы" + Colors.ENDC)
        auditd_running = run_cmd("pgrep -q auditd && echo yes || echo no")
        audit_control = "/etc/security/audit_control"
        flags = []
        if os.path.exists(audit_control):
            try:
                with open(audit_control) as f:
                    flags = [line for line in f if line.startswith("flags:")]
            except:
                pass
        details = {
            "Служба аудита активна": "Да" if auditd_running == "yes" else "Нет",
            "Файл конфигурации": "Существует" if os.path.exists(audit_control) else "Отсутствует",
            "Настройки flags": flags[0].strip() if flags else "Не заданы"
        }
        status = "WARN" if auditd_running != "yes" else "OK"
        recs = []
        if auditd_running != "yes":
            recs.append("Включите аудит: sudo audit -s")
        if not flags or "lo" not in str(flags):
            recs.append("Настройте аудит для логирования событий входа/выхода (lo).")
        self.results[6] = {"name": "Аудит системы", "status": status, "details": details, "recommendations": recs}
        print(f"  Аудит активен: {details['Служба аудита активна']}")

    # 7. Сетевые настройки (исправлен pfctl)
    def check_network_settings(self):
        print(Colors.OKCYAN + "[7] Сетевые настройки" + Colors.ENDC)
        listening = run_cmd("netstat -an | grep LISTEN | wc -l")
        # pfctl без sudo, с коротким таймаутом
        try:
            result = subprocess.run(
                "pfctl -s info 2>/dev/null | grep Status",
                shell=True, capture_output=True, text=True, timeout=5
            )
            pf_status = result.stdout.strip()
            if not pf_status:
                pf_status = "Не включён (или недостаточно прав)"
        except subprocess.TimeoutExpired:
            pf_status = "Таймаут (команда pfctl не ответила)"
        except Exception:
            pf_status = "Ошибка получения статуса PF"
        details = {
            "Количество слушающих портов": listening,
            "Статус файрвола (pf)": pf_status
        }
        status = "WARN" if ("Disabled" in pf_status or "не включён" in pf_status.lower() or "Таймаут" in pf_status) else "OK"
        recs = []
        if "Disabled" in pf_status or "не включён" in pf_status.lower():
            recs.append("Включите файрвол: sudo pfctl -e")
        elif "Таймаут" in pf_status:
            recs.append("Проверьте работу pfctl. Возможно, файрвол не настроен.")
        self.results[7] = {"name": "Сетевые настройки", "status": status, "details": details, "recommendations": recs}
        print(f"  Слушающих портов: {listening}, pf: {pf_status}")

    # 8. Открытые ресурсы
    def check_shared_resources(self):
        print(Colors.OKCYAN + "[8] Открытые ресурсы (общие папки)" + Colors.ENDC)
        shares = run_cmd("sharing -l 2>/dev/null | grep -E 'name:|path:'")
        nfs_exports = "/etc/exports"
        nfs_shares = []
        if os.path.exists(nfs_exports):
            try:
                with open(nfs_exports) as f:
                    nfs_shares = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except:
                pass
        details = {
            "Общие папки SMB/AFP": shares.splitlines()[:5] if shares else "Нет",
            "NFS экспорты": nfs_shares[:5] if nfs_shares else "Нет"
        }
        status = "OK"
        recs = []
        if shares and "guest" in shares.lower():
            recs.append("Проверьте общие папки, возможно разрешён гостевой доступ.")
            status = "WARN"
        self.results[8] = {"name": "Открытые ресурсы", "status": status, "details": details, "recommendations": recs}
        print(f"  SMB/AFP ресурсы: {len(shares.splitlines()) if shares else 0}")

    # 9. Запущенные сервисы
    def check_running_services(self):
        print(Colors.OKCYAN + "[9] Запущенные сервисы" + Colors.ENDC)
        loaded = run_cmd("launchctl list | grep -v 'com.apple' | head -30")
        net_services = run_cmd("lsof -i -P | grep LISTEN | awk '{print $1}' | sort | uniq -c | sort -nr")
        details = {
            "Загруженные сторонние сервисы (пример)": loaded.splitlines()[:10],
            "Сетевые сервисы (PID, имя)": net_services.splitlines()[:10]
        }
        dangerous = ["httpd", "nginx", "ftp", "telnet", "vnc"]
        found_danger = [s for s in dangerous if s in net_services.lower()]
        status = "WARN" if found_danger else "OK"
        recs = []
        if found_danger:
            recs.append(f"Обнаружены потенциально небезопасные сервисы: {found_danger}. Отключите их, если не нужны.")
        self.results[9] = {"name": "Запущенные сервисы", "status": status, "details": details, "recommendations": recs}
        print(f"  Сетевых сервисов: {len(net_services.splitlines())}")

    # 10. Файловая система
    def check_filesystem(self):
        print(Colors.OKCYAN + "[10] Файловая система" + Colors.ENDC)
        fs_type = run_cmd("diskutil info / | grep 'File System' | awk -F: '{print $2}'")
        critical_files = [
            "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/Library/Preferences/SystemConfiguration/com.apple.Boot.plist"
        ]
        permissions = {}
        for f in critical_files:
            if os.path.exists(f):
                try:
                    stat_info = os.stat(f)
                    perms = oct(stat_info.st_mode)[-3:]
                    permissions[f] = perms
                except:
                    permissions[f] = "недоступно"
        suid_files = run_cmd("find /usr/bin /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l")
        details = {
            "Тип ФС": fs_type.strip(),
            "Права на критичные файлы": permissions,
            "Количество SUID-файлов (в /usr/bin,/bin,/sbin)": suid_files
        }
        status = "OK"
        recs = []
        for f, perm in permissions.items():
            if perm not in ["444", "440", "644"] and "sudoers" not in f:
                recs.append(f"Файл {f} имеет права {perm}, рекомендуются более строгие.")
                status = "WARN"
        self.results[10] = {"name": "Файловая система", "status": status, "details": details, "recommendations": recs}
        print(f"  Тип ФС: {fs_type}, SUID-файлов: {suid_files}")

    # 11. Реестр (plist)
    def check_registry_macos(self):
        print(Colors.OKCYAN + "[11] Реестр (plist / defaults)" + Colors.ENDC)
        important_keys = {
            "com.apple.security": ["SessionKey"],
            "com.apple.loginwindow": ["GuestEnabled", "SHOWFULLNAME"],
            "com.apple.AppleFileServer": ["guestAccess"]
        }
        results = {}
        for domain, keys in important_keys.items():
            for key in keys:
                value = run_cmd(f"defaults read /Library/Preferences/{domain} {key} 2>/dev/null")
                if value and not value.startswith("ERROR"):
                    results[f"{domain}:{key}"] = value
        plist_perms = {}
        plist_files = ["/Library/Preferences/com.apple.security.plist", "/Library/Preferences/com.apple.loginwindow.plist"]
        for pf in plist_files:
            if os.path.exists(pf):
                try:
                    plist_perms[pf] = oct(os.stat(pf).st_mode)[-3:]
                except:
                    plist_perms[pf] = "недоступно"
        details = {
            "Значения ключей (нестандартные)": results,
            "Права на plist-файлы": plist_perms
        }
        status = "OK"
        recs = []
        if "GuestEnabled" in str(results) and "=1" in str(results):
            recs.append("Гостевой вход включён в loginwindow. Отключите его.")
            status = "WARN"
        self.results[11] = {"name": "Реестр (plist)", "status": status, "details": details, "recommendations": recs}
        print(f"  Найдено нестандартных ключей: {len(results)}")

    # 12. Групповые политики
    def check_group_policies(self):
        print(Colors.OKCYAN + "[12] Групповые политики (профили)" + Colors.ENDC)
        profiles = run_cmd("profiles list -C 2>/dev/null")
        has_profiles = bool(profiles and "There are no configuration profiles" not in profiles and not profiles.startswith("ERROR"))
        details = {
            "Установленные профили": "Да" if has_profiles else "Нет",
            "Содержимое": profiles.splitlines()[:10] if has_profiles else []
        }
        status = "WARN" if not has_profiles else "OK"
        recs = []
        if not has_profiles:
            recs.append("Для усиления безопасности рекомендуется установить профили конфигурации (CIS benchmark).")
        self.results[12] = {"name": "Групповые политики", "status": status, "details": details, "recommendations": recs}
        print(f"  Профили конфигурации: {'установлены' if has_profiles else 'отсутствуют'}")

    # 13. Дополнительные параметры (исправлен вывод)
    def check_additional_params(self):
        print(Colors.OKCYAN + "[13] Дополнительные параметры" + Colors.ENDC)
        fv_status = run_cmd("fdesetup status")
        is_fv_on = "On" in fv_status
        guest_enabled = run_cmd("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
        auth_cache = run_cmd("dsconfigad -show 2>/dev/null | grep 'Cache'")
        details = {
            "FileVault (шифрование диска)": "Включён" if is_fv_on else "Выключен",
            "Гостевой вход": "Включён" if "1" in guest_enabled else "Выключен",
            "Кэширование паролей (AD)": auth_cache if auth_cache and not auth_cache.startswith("ERROR") else "Не задано"
        }
        status = "OK"
        recs = []
        if not is_fv_on:
            recs.append("Включите FileVault для шифрования загрузочного диска.")
            status = "WARN"
        if "1" in guest_enabled:
            recs.append("Отключите гостевой вход: sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO")
            status = "WARN"
        self.results[13] = {"name": "Дополнительные параметры", "status": status, "details": details, "recommendations": recs}
        print(f"  FileVault: {details['FileVault (шифрование диска)']}, Гость: {details['Гостевой вход']}")

    # 14. Анализ журналов
    def check_logs(self):
        print(Colors.OKCYAN + "[14] Анализ журналов" + Colors.ENDC)
        log_output = run_cmd('log show --predicate \'eventMessage contains "failed" OR eventMessage contains "error" OR eventMessage contains "authentication"\' --info --last 1h 2>/dev/null', timeout=30)
        lines = log_output.splitlines()
        # Если произошла ошибка, lines будет содержать строку с "ERROR"
        if log_output.startswith("ERROR"):
            lines = []
        counter = Counter()
        for line in lines[:500]:
            parts = line.split()
            if len(parts) > 5:
                msg = ' '.join(parts[5:])
                counter[msg] += 1
        top_repeated = counter.most_common(5)
        details = {
            "Всего строк с ошибками/аутентификацией за час": len(lines),
            "Наиболее повторяющиеся события": top_repeated,
            "Пример записей (первые 5)": lines[:5]
        }
        status = "WARN" if len(lines) > 100 else "OK"
        recs = []
        if len(lines) > 100:
            recs.append("Обнаружено большое количество ошибок в логах. Проверьте систему на наличие проблем.")
        self.results[14] = {"name": "Анализ журналов", "status": status, "details": details, "recommendations": recs}
        print(f"  За час зафиксировано {len(lines)} событий типа error/failed")

    # 15. Обнаружение сканирования портов (исправлено преобразование int)
    def check_port_scan(self):
        print(Colors.OKCYAN + "[15] Обнаружение сканирования портов" + Colors.ENDC)
        pf_log = run_cmd("cat /var/log/pf.log 2>/dev/null | tail -200")
        ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', pf_log)
        ip_counts = Counter(ips)
        suspicious_ips = [ip for ip, cnt in ip_counts.items() if cnt > 10]
        system_log_scan_raw = run_cmd("log show --predicate 'eventMessage contains \"scan\"' --last 1d 2>/dev/null | grep -i 'port' | wc -l")
        # Преобразуем в число, обрабатывая ошибки
        try:
            system_log_scan = int(system_log_scan_raw.strip())
        except ValueError:
            system_log_scan = 0
        details = {
            "Подозрительные IP (более 10 обращений в PF логах)": suspicious_ips[:5],
            "Упоминаний сканирования в системных логах за сутки": system_log_scan
        }
        status = "WARN" if suspicious_ips or system_log_scan > 0 else "OK"
        recs = []
        if suspicious_ips:
            recs.append(f"Обнаружены потенциальные сканеры портов: {suspicious_ips}. Рассмотрите блокировку через PF.")
        self.results[15] = {"name": "Обнаружение сканирования портов", "status": status, "details": details, "recommendations": recs}
        print(f"  Подозрительных IP: {len(suspicious_ips)}, упоминаний сканирования: {system_log_scan}")

    # Вывод итогового отчёта
    def print_summary(self):
        print("\n" + Colors.BOLD + "    СВОДНЫЙ ОТЧЁТ ПО БЕЗОПАСНОСТИ" + Colors.ENDC)
        for idx, data in self.results.items():
            status_color = Colors.OKGREEN if data["status"] == "OK" else Colors.FAIL
            print(f"\n{idx}. {data['name']} - {status_color}{data['status']}{Colors.ENDC}")
            for key, val in data["details"].items():
                print(f"    {key}: {val}")
            if data["recommendations"]:
                print(Colors.WARNING + "    Рекомендации:" + Colors.ENDC)
                for rec in data["recommendations"]:
                    print(f"      • {rec}")

if __name__ == "__main__":
    if sys.platform != "darwin":
        print("Ошибка: программа предназначена только для macOS")
        sys.exit(1)
    if os.geteuid() != 0:
        print(Colors.WARNING + "Предупреждение: некоторые проверки требуют прав root. Запустите с sudo для полного отчёта." + Colors.ENDC)
    scanner = MacOSSecurityScanner()
    scanner.run_all_checks()