"""База знаний: оценка опасности открытых сервисов и рекомендации по устранению."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceRisk:
    severity: str
    title: str
    recommendation: str


_REC_RESTRICT = "Закройте порт на межсетевом экране или ограничьте доступ списком доверенных адресов / VPN."

# Ключ: (протокол, порт). Для сервисов, которые не должны быть доступны из интернета.
RISKY_PORTS: dict[tuple[str, int], ServiceRisk] = {
    ("tcp", 21): ServiceRisk("medium", "FTP доступен из интернета", "FTP передаёт учётные данные открытым текстом. Замените на SFTP/FTPS. " + _REC_RESTRICT),
    ("tcp", 23): ServiceRisk("high", "Telnet доступен из интернета", "Telnet передаёт данные без шифрования. Отключите Telnet и используйте SSH. " + _REC_RESTRICT),
    ("tcp", 25): ServiceRisk("info", "SMTP доступен из интернета", "Убедитесь, что сервер не является открытым релеем и поддерживает STARTTLS."),
    ("tcp", 53): ServiceRisk("low", "DNS (TCP) доступен из интернета", "Убедитесь, что запрещены рекурсия для внешних клиентов и передача зоны (AXFR)."),
    ("udp", 53): ServiceRisk("low", "DNS доступен из интернета", "Убедитесь, что запрещена рекурсия для внешних клиентов (открытый резолвер используется в DDoS-атаках)."),
    ("tcp", 110): ServiceRisk("low", "POP3 без шифрования", "Используйте POP3S (995) и отключите незашифрованный доступ."),
    ("tcp", 111): ServiceRisk("high", "RPCbind доступен из интернета", _REC_RESTRICT),
    ("udp", 111): ServiceRisk("high", "RPCbind доступен из интернета", _REC_RESTRICT),
    ("udp", 123): ServiceRisk("low", "NTP доступен из интернета", "Отключите команды monlist/mode 6 для внешних клиентов, обновите ntpd."),
    ("tcp", 135): ServiceRisk("high", "Microsoft RPC доступен из интернета", _REC_RESTRICT),
    ("tcp", 137): ServiceRisk("high", "NetBIOS доступен из интернета", _REC_RESTRICT),
    ("udp", 137): ServiceRisk("high", "NetBIOS доступен из интернета", _REC_RESTRICT),
    ("tcp", 139): ServiceRisk("high", "NetBIOS/SMB доступен из интернета", _REC_RESTRICT),
    ("tcp", 143): ServiceRisk("low", "IMAP без шифрования", "Используйте IMAPS (993) и отключите незашифрованный доступ."),
    ("udp", 161): ServiceRisk("high", "SNMP доступен из интернета", "Запретите SNMP извне, используйте SNMPv3 с аутентификацией и шифрованием, смените community-строки."),
    ("tcp", 389): ServiceRisk("high", "LDAP доступен из интернета", "Каталог не должен быть доступен из интернета. " + _REC_RESTRICT),
    ("udp", 389): ServiceRisk("high", "CLDAP доступен из интернета", "CLDAP используется для DDoS-амплификации. " + _REC_RESTRICT),
    ("tcp", 445): ServiceRisk("critical", "SMB доступен из интернета", "SMB никогда не должен быть доступен из интернета. Немедленно закройте порт на межсетевом экране."),
    ("udp", 500): ServiceRisk("info", "IKE (VPN) доступен из интернета", "Используйте IKEv2 и стойкие алгоритмы, отключите aggressive mode."),
    ("tcp", 512): ServiceRisk("high", "rexec доступен из интернета", "Отключите r-сервисы. " + _REC_RESTRICT),
    ("tcp", 513): ServiceRisk("high", "rlogin доступен из интернета", "Отключите r-сервисы. " + _REC_RESTRICT),
    ("tcp", 514): ServiceRisk("high", "rsh доступен из интернета", "Отключите r-сервисы. " + _REC_RESTRICT),
    ("udp", 514): ServiceRisk("medium", "Syslog доступен из интернета", _REC_RESTRICT),
    ("tcp", 636): ServiceRisk("medium", "LDAPS доступен из интернета", _REC_RESTRICT),
    ("tcp", 873): ServiceRisk("high", "rsync доступен из интернета", "Проверьте, не доступны ли модули без аутентификации. " + _REC_RESTRICT),
    ("udp", 1900): ServiceRisk("medium", "SSDP/UPnP доступен из интернета", "Отключите UPnP на пограничных устройствах."),
    ("tcp", 1433): ServiceRisk("high", "Microsoft SQL Server доступен из интернета", "СУБД не должна быть доступна из интернета. " + _REC_RESTRICT),
    ("udp", 1434): ServiceRisk("medium", "MS SQL Browser доступен из интернета", _REC_RESTRICT),
    ("tcp", 1521): ServiceRisk("high", "Oracle DB доступна из интернета", "СУБД не должна быть доступна из интернета. " + _REC_RESTRICT),
    ("tcp", 1723): ServiceRisk("medium", "PPTP VPN", "PPTP криптографически устарел. Перейдите на IPsec/IKEv2, OpenVPN или WireGuard."),
    ("tcp", 2049): ServiceRisk("high", "NFS доступен из интернета", _REC_RESTRICT),
    ("tcp", 2375): ServiceRisk("critical", "Docker API без TLS доступен из интернета", "Немедленно закройте порт: Docker API без TLS даёт полный контроль над хостом."),
    ("tcp", 2376): ServiceRisk("high", "Docker API доступен из интернета", _REC_RESTRICT),
    ("tcp", 2379): ServiceRisk("critical", "etcd доступен из интернета", "etcd хранит секреты кластера. Закройте порт и включите mTLS."),
    ("tcp", 3306): ServiceRisk("high", "MySQL/MariaDB доступна из интернета", "СУБД не должна быть доступна из интернета. " + _REC_RESTRICT),
    ("tcp", 3389): ServiceRisk("high", "RDP доступен из интернета", "Опубликуйте RDP через VPN или RD Gateway с MFA, включите NLA. " + _REC_RESTRICT),
    ("tcp", 4369): ServiceRisk("medium", "Erlang Port Mapper доступен из интернета", _REC_RESTRICT),
    ("tcp", 5000): ServiceRisk("low", "Сервис на порту 5000", "Проверьте назначение сервиса (часто — панели управления, Docker Registry, UPnP)."),
    ("tcp", 5432): ServiceRisk("high", "PostgreSQL доступна из интернета", "СУБД не должна быть доступна из интернета. " + _REC_RESTRICT),
    ("tcp", 5601): ServiceRisk("high", "Kibana доступна из интернета", "Закройте доступ или включите аутентификацию. " + _REC_RESTRICT),
    ("tcp", 5672): ServiceRisk("medium", "AMQP (RabbitMQ) доступен из интернета", _REC_RESTRICT),
    ("tcp", 5900): ServiceRisk("high", "VNC доступен из интернета", "VNC часто использует слабую аутентификацию. " + _REC_RESTRICT),
    ("tcp", 5985): ServiceRisk("high", "WinRM (HTTP) доступен из интернета", _REC_RESTRICT),
    ("tcp", 5986): ServiceRisk("high", "WinRM (HTTPS) доступен из интернета", _REC_RESTRICT),
    ("tcp", 6379): ServiceRisk("critical", "Redis доступен из интернета", "Redis по умолчанию без аутентификации. Закройте порт, включите requirepass/ACL и bind на внутренний адрес."),
    ("tcp", 6443): ServiceRisk("high", "Kubernetes API доступен из интернета", "Ограничьте доступ к API-серверу списком адресов/VPN."),
    ("tcp", 7001): ServiceRisk("medium", "Oracle WebLogic доступен из интернета", "Проверьте актуальность патчей WebLogic, закройте консоль администрирования."),
    ("tcp", 8009): ServiceRisk("high", "AJP (Tomcat) доступен из интернета", "Отключите AJP-коннектор или ограничьте его localhost (уязвимость Ghostcat, CVE-2020-1938)."),
    ("tcp", 8086): ServiceRisk("high", "InfluxDB доступна из интернета", _REC_RESTRICT),
    ("tcp", 9000): ServiceRisk("low", "Сервис на порту 9000", "Проверьте назначение сервиса (часто — Portainer, SonarQube, PHP-FPM, MinIO)."),
    ("tcp", 9042): ServiceRisk("high", "Cassandra доступна из интернета", _REC_RESTRICT),
    ("tcp", 9090): ServiceRisk("medium", "Prometheus/панель на 9090 доступна из интернета", "Метрики раскрывают внутреннюю инфраструктуру. " + _REC_RESTRICT),
    ("tcp", 9100): ServiceRisk("medium", "Node exporter / принтер JetDirect доступен из интернета", _REC_RESTRICT),
    ("tcp", 9200): ServiceRisk("critical", "Elasticsearch доступен из интернета", "Закройте порт и включите аутентификацию (xpack.security)."),
    ("tcp", 9300): ServiceRisk("high", "Elasticsearch transport доступен из интернета", _REC_RESTRICT),
    ("tcp", 10250): ServiceRisk("critical", "Kubelet API доступен из интернета", "Закройте порт, отключите анонимный доступ к kubelet."),
    ("tcp", 11211): ServiceRisk("critical", "Memcached доступен из интернета", "Memcached используется для DDoS-амплификации и не имеет аутентификации. Закройте порт."),
    ("udp", 11211): ServiceRisk("critical", "Memcached (UDP) доступен из интернета", "Отключите UDP в memcached (-U 0) и закройте порт."),
    ("tcp", 15672): ServiceRisk("high", "Консоль RabbitMQ доступна из интернета", _REC_RESTRICT),
    ("tcp", 27017): ServiceRisk("critical", "MongoDB доступна из интернета", "Закройте порт, включите авторизацию (security.authorization) и bind на внутренний адрес."),
    ("tcp", 50000): ServiceRisk("medium", "SAP / Jenkins agent доступен из интернета", _REC_RESTRICT),
}

# Сервисы, опасность которых определяется по имени (если порт нестандартный).
RISKY_SERVICE_NAMES: dict[str, tuple[str, int]] = {
    "telnet": ("tcp", 23),
    "microsoft-ds": ("tcp", 445),
    "netbios-ssn": ("tcp", 139),
    "ms-wbt-server": ("tcp", 3389),
    "vnc": ("tcp", 5900),
    "mysql": ("tcp", 3306),
    "postgresql": ("tcp", 5432),
    "ms-sql-s": ("tcp", 1433),
    "oracle-tns": ("tcp", 1521),
    "redis": ("tcp", 6379),
    "mongodb": ("tcp", 27017),
    "memcached": ("tcp", 11211),
    "elasticsearch": ("tcp", 9200),
    "ldap": ("tcp", 389),
    "snmp": ("udp", 161),
    "rpcbind": ("tcp", 111),
    "nfs": ("tcp", 2049),
    "docker": ("tcp", 2375),
    "ajp13": ("tcp", 8009),
    "rsync": ("tcp", 873),
    "ftp": ("tcp", 21),
}

ADMIN_PANEL_TECH = {
    "phpMyAdmin": ("high", "Панель phpMyAdmin доступна из интернета"),
    "Jenkins": ("high", "Jenkins доступен из интернета"),
    "Grafana": ("medium", "Grafana доступна из интернета"),
    "Kibana": ("high", "Kibana доступна из интернета"),
    "GitLab": ("low", "GitLab доступен из интернета"),
    "Portainer": ("high", "Portainer доступен из интернета"),
    "Webmin": ("high", "Webmin доступен из интернета"),
    "cPanel": ("medium", "cPanel доступен из интернета"),
    "Apache Tomcat Manager": ("high", "Tomcat Manager доступен из интернета"),
    "Microsoft Exchange (OWA)": ("low", "Outlook Web Access опубликован"),
    "RabbitMQ Management": ("high", "Консоль RabbitMQ доступна из интернета"),
    "Zabbix": ("medium", "Zabbix доступен из интернета"),
    "1С-Битрикс (админ-панель)": ("medium", "Административная панель Битрикс доступна из интернета"),
    "WordPress (админ-панель)": ("low", "Страница входа WordPress доступна из интернета"),
}


def service_risk(protocol: str, port: int, service_name: str) -> ServiceRisk | None:
    risk = RISKY_PORTS.get((protocol, port))
    if risk:
        return risk
    mapped = RISKY_SERVICE_NAMES.get(service_name)
    if mapped:
        return RISKY_PORTS.get(mapped)
    return None


def cve_recommendation(product: str, version: str, cve: str) -> str:
    target = " ".join(p for p in (product, version) if p) or "ПО сервиса"
    return (
        f"Обновите {target} до версии, в которой устранена {cve}, или примените исправление производителя. "
        f"Если обновление невозможно — ограничьте доступ к сервису и примените компенсирующие меры. "
        f"Подробнее: https://nvd.nist.gov/vuln/detail/{cve}"
    )


# Правила для отдельных скриптов NSE: (id скрипта, подстрока в выводе или None, уровень, заголовок, рекомендация)
SCRIPT_RULES: list[tuple[str, str | None, str, str, str]] = [
    ("ftp-anon", "Anonymous FTP login allowed", "high", "Разрешён анонимный вход на FTP",
     "Отключите анонимный доступ к FTP, если он не требуется; проверьте содержимое доступных каталогов."),
    ("smb-security-mode", "message_signing: disabled", "medium", "SMB: подпись сообщений отключена",
     "Включите обязательную подпись SMB (RequireSecuritySignature)."),
    ("smb2-security-mode", "not required", "medium", "SMBv2: подпись сообщений не обязательна",
     "Включите обязательную подпись SMB."),
    ("smb-protocols", "NT LM 0.12 (SMBv1)", "high", "Поддерживается SMBv1",
     "Отключите протокол SMBv1 (уязвим к EternalBlue и др.)."),
    ("http-open-proxy", "Potentially OPEN proxy", "high", "Открытый HTTP-прокси",
     "Запретите проксирование для внешних клиентов."),
    ("dns-recursion", "Recursion appears to be enabled", "medium", "Открытый рекурсивный DNS-резолвер",
     "Запретите рекурсивные запросы от внешних клиентов (allow-recursion)."),
    ("ntp-monlist", None, "high", "NTP monlist включён (DDoS-амплификация)",
     "Обновите ntpd и отключите monlist (disable monitor)."),
    ("snmp-sysdescr", None, "high", "SNMP отвечает на стандартную community-строку",
     "Смените community-строки, перейдите на SNMPv3 и закройте SNMP извне."),
    ("snmp-info", None, "medium", "SNMP раскрывает информацию об устройстве",
     "Ограничьте доступ к SNMP и используйте SNMPv3."),
    ("redis-info", "Version", "critical", "Redis доступен без аутентификации",
     "Включите аутентификацию (requirepass/ACL) и закройте порт."),
    ("mongodb-databases", None, "critical", "MongoDB доступна без аутентификации",
     "Включите авторизацию и закройте порт."),
    ("memcached-info", None, "high", "Memcached отвечает без аутентификации",
     "Закройте порт memcached и включите SASL."),
    ("http-git", "Git repository found", "high", "Доступен каталог .git на веб-сервере",
     "Удалите каталог .git из корня сайта или запретите к нему доступ."),
    ("http-methods", "Potentially risky methods", "low", "Разрешены потенциально опасные HTTP-методы",
     "Отключите неиспользуемые методы (PUT, DELETE, TRACE и др.)."),
    ("http-trace", "TRACE is enabled", "low", "Включён HTTP TRACE",
     "Отключите метод TRACE (TraceEnable off)."),
    ("ssh-auth-methods", "password", "low", "SSH допускает вход по паролю",
     "Используйте аутентификацию по ключам, отключите PasswordAuthentication, ограничьте доступ к SSH."),
    ("sslv2", "SSLv2 supported", "high", "Поддерживается SSLv2", "Отключите SSLv2 и SSLv3, оставьте TLS 1.2/1.3."),
    ("http-cookie-flags", "httponly flag not set", "low", "Cookie без флага HttpOnly",
     "Установите флаги HttpOnly и Secure для cookie сессий."),
    ("ms-sql-empty-password", "Login Success", "critical", "MS SQL: вход с пустым паролем",
     "Задайте надёжный пароль учётной записи и закройте порт."),
    ("mysql-empty-password", "account has empty password", "critical", "MySQL: учётная запись с пустым паролем",
     "Задайте пароли всем учётным записям и закройте порт."),
    ("rdp-enum-encryption", "Native RDP", "medium", "RDP допускает подключение без NLA",
     "Включите Network Level Authentication (NLA)."),
    ("ike-version", "Aggressive", "medium", "IKE Aggressive Mode",
     "Отключите aggressive mode в настройках VPN."),
    ("vnc-info", "None", "critical", "VNC без аутентификации", "Включите аутентификацию VNC и закройте порт."),
]
