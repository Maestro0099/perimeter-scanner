"""Определение технологий веб-сервиса по заголовкам, cookie и содержимому страницы."""

from __future__ import annotations

import re

# (название, где искать, регулярное выражение). Где: header:<имя>, cookie, body.
RULES: list[tuple[str, str, str]] = [
    ("nginx", "header:server", r"nginx"),
    ("Apache HTTP Server", "header:server", r"apache"),
    ("Microsoft IIS", "header:server", r"microsoft-iis"),
    ("LiteSpeed", "header:server", r"litespeed"),
    ("OpenResty", "header:server", r"openresty"),
    ("Caddy", "header:server", r"caddy"),
    ("Envoy", "header:server", r"envoy"),
    ("Apache Tomcat", "header:server", r"tomcat|coyote"),
    ("Jetty", "header:server", r"jetty"),
    ("Kestrel", "header:server", r"kestrel"),
    ("Cloudflare", "header:server", r"cloudflare"),
    ("DDoS-Guard", "header:server", r"ddos-guard"),
    ("QRATOR", "header:server", r"qrator"),
    ("Varnish", "header:via", r"varnish"),
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("ASP.NET", "header:x-aspnet-version", r"."),
    ("Express", "header:x-powered-by", r"express"),
    ("Next.js", "header:x-powered-by", r"next\.js"),
    ("PHP", "cookie", r"PHPSESSID"),
    ("Java (Servlet)", "cookie", r"JSESSIONID"),
    ("ASP.NET", "cookie", r"ASP\.NET_SessionId"),
    ("1С-Битрикс", "cookie", r"BITRIX_SM|PHPSESSID.*BX"),
    ("1С-Битрикс", "header:x-powered-cms", r"bitrix"),
    ("1С-Битрикс", "body", r"/bitrix/(?:js|templates|cache)/"),
    ("1С-Битрикс (админ-панель)", "body", r"bitrix/admin|<title>Авторизация</title>.*bitrix"),
    ("WordPress", "body", r"/wp-content/|/wp-includes/"),
    ("WordPress (админ-панель)", "body", r"wp-login\.php"),
    ("Joomla", "body", r"/media/jui/|content=\"Joomla"),
    ("Drupal", "body", r"Drupal\.settings|/sites/default/files/"),
    ("Drupal", "header:x-generator", r"drupal"),
    ("Tilda", "body", r"tilda\.ws|tildacdn"),
    ("jQuery", "body", r"jquery[.-]?[\d.]*(?:\.min)?\.js"),
    ("React", "body", r"data-reactroot|__NEXT_DATA__|react(?:\.production)?\.min\.js"),
    ("Vue.js", "body", r"data-v-[0-9a-f]{6,}|vue(?:\.runtime)?(?:\.min)?\.js"),
    ("Angular", "body", r"ng-version=|ng-app"),
    ("Bootstrap", "body", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Grafana", "body", r"<title>Grafana</title>|grafana-app"),
    ("Kibana", "body", r"<title>Kibana</title>|kbn-name"),
    ("Kibana", "header:kbn-name", r"."),
    ("Jenkins", "header:x-jenkins", r"."),
    ("GitLab", "body", r"gitlab-logo|<meta content=\"GitLab\""),
    ("Portainer", "body", r"<title>Portainer</title>"),
    ("phpMyAdmin", "body", r"phpMyAdmin|pma_navigation"),
    ("Webmin", "body", r"<title>Login to Webmin</title>"),
    ("cPanel", "body", r"cPanel"),
    ("Zabbix", "body", r"<title>[^<]*Zabbix"),
    ("RabbitMQ Management", "body", r"<title>RabbitMQ Management</title>"),
    ("Microsoft Exchange (OWA)", "body", r"/owa/auth/|OutlookSession"),
    ("Microsoft Exchange (OWA)", "header:x-owa-version", r"."),
    ("Apache Tomcat Manager", "body", r"/manager/html"),
    ("Confluence", "body", r"confluence-base-url|ajs-confluence"),
    ("Jira", "body", r"jira-frontend|ajs-jira"),
    ("Nextcloud", "body", r"nextcloud"),
    ("Roundcube", "body", r"roundcube"),
    ("Fortinet FortiGate", "body", r"fortinet|/remote/login\?lang="),
    ("Cisco ASA / AnyConnect", "body", r"/\+CSCOE\+/"),
    ("Citrix Gateway", "body", r"/vpn/index\.html|citrix"),
    ("Palo Alto GlobalProtect", "body", r"global-protect|GlobalProtect"),
    ("MikroTik RouterOS", "body", r"<title>RouterOS|mikrotik"),
]


def detect(headers: dict[str, str], cookies: list[str], body: str) -> list[str]:
    found: list[str] = []
    h = {k.lower(): v for k, v in headers.items()}
    cookie_text = " ".join(cookies)
    body = body[:300_000]
    for name, where, pattern in RULES:
        if name in found:
            continue
        if where.startswith("header:"):
            text = h.get(where.split(":", 1)[1], "")
        elif where == "cookie":
            text = cookie_text
        else:
            text = body
        if text and re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            found.append(name)
    return found


_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def discloses_version(value: str) -> bool:
    return bool(_VERSION_RE.search(value or ""))
