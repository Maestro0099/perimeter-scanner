#!/usr/bin/env bash
# Установка и запуск «Контроля периметра» на Ubuntu Server.
#
#   git clone <репозиторий> /opt/perimeter-scanner && cd /opt/perimeter-scanner
#   ./install.sh
#
# Скрипт можно запускать повторно: существующие .env и targets.yaml не перезаписываются.
# По умолчанию скрипт также ставит nginx и публикует интерфейс во внутренней сети по HTTPS
# (https://<адрес ВМ>) с самоподписанным сертификатом. Отключить: ./install.sh --no-https
#
# Необязательные переменные окружения:
#   PS_ADMIN_PASSWORD — пароль первого администратора (иначе будет сгенерирован)
#   PS_ADMIN_USERNAME — логин первого администратора (по умолчанию admin)
#   PS_SERVER_NAME    — DNS-имя интерфейса, например perimeter.corp.local (иначе — IP-адрес ВМ)
#   PS_TLS_CERT, PS_TLS_KEY — пути к своему сертификату (цепочка) и ключу вместо самоподписанного
#   PS_ALLOWED_NETS   — сети, которым разрешён доступ (через пробел);
#                       по умолчанию — частные диапазоны 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
set -euo pipefail

HTTPS=1
for arg in "$@"; do
  case "$arg" in
    --no-https) HTTPS=0 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Неизвестный параметр: $arg" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$(readlink -f "$0")")"

info() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "Нужны права root или sudo."
  SUDO="sudo"
fi

# --------------------------------------------------------------------------- Docker
install_docker() {
  [ -r /etc/os-release ] || die "Не удалось определить дистрибутив. Установите Docker вручную."
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = "ubuntu" ] || die "Автоустановка Docker поддерживается только на Ubuntu. Установите Docker Engine и плагин compose вручную."
  info "Устанавливаю Docker Engine из официального репозитория…"
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl
  $SUDO install -m 0755 -d /etc/apt/keyrings
  $SUDO curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  $SUDO chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

if ! command -v docker >/dev/null 2>&1; then
  install_docker
fi

DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  if $SUDO docker info >/dev/null 2>&1; then
    DOCKER="$SUDO docker"
  else
    die "Docker установлен, но служба недоступна. Проверьте: systemctl status docker"
  fi
fi
$DOCKER compose version >/dev/null 2>&1 || die "Не найден плагин docker compose (пакет docker-compose-plugin)."

# --------------------------------------------------------------------------- .env
rand_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

set_env() {  # set_env КЛЮЧ ЗНАЧЕНИЕ — заменяет строку «КЛЮЧ=…» в .env
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="} $1==k {print k "=" v; done=1; next} {print} END{if(!done) print k "=" v}' .env >"$tmp"
  cat "$tmp" > .env
  rm -f "$tmp"
}

GENERATED_PASSWORD=""
if [ ! -f .env ]; then
  info "Создаю .env из .env.example"
  ( umask 077; cp .env.example .env )
  chmod 600 .env
  set_env SECRET_KEY "$(rand_hex 32)"
  set_env ADMIN_USERNAME "${PS_ADMIN_USERNAME:-admin}"
  if [ -n "${PS_ADMIN_PASSWORD:-}" ]; then
    set_env ADMIN_PASSWORD "$PS_ADMIN_PASSWORD"
  else
    GENERATED_PASSWORD="Ps-$(rand_hex 6)-$(rand_hex 4 | tr 'a-f' 'A-F')"
    set_env ADMIN_PASSWORD "$GENERATED_PASSWORD"
  fi
else
  info ".env уже существует — не изменяю"
  grep -q '^SECRET_KEY=.\+' .env || warn "В .env не задан SECRET_KEY — ключ будет создан в томе данных."
fi

# --------------------------------------------------------------------------- targets.yaml
if [ -d targets.yaml ]; then
  die "targets.yaml — каталог (его создал docker при запуске без файла). Удалите его: rmdir targets.yaml — и запустите скрипт снова."
fi
if [ ! -f targets.yaml ]; then
  info "Создаю пустой targets.yaml (цели можно добавить в интерфейсе или вписать в файл по образцу targets.example.yaml)"
  printf '# Цели организации. Формат — см. targets.example.yaml\ngroups: []\ntargets: []\n' > targets.yaml
fi

# --------------------------------------------------------------------------- nginx + HTTPS
TLS_DIR=/etc/ssl/perimeter-scanner
NGINX_SITE=/etc/nginx/sites-available/perimeter-scanner
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_NAME="${PS_SERVER_NAME:-${PRIMARY_IP:-localhost}}"
ALLOWED_NETS="${PS_ALLOWED_NETS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16}"
HTTPS_DONE=""
SELF_SIGNED=""

valid_name() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9.:-]+$'; }
valid_net()  { printf '%s' "$1" | grep -Eq '^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$'; }

make_cert() {
  $SUDO install -d -m 0755 "$TLS_DIR"
  if [ -n "${PS_TLS_CERT:-}" ] || [ -n "${PS_TLS_KEY:-}" ]; then
    [ -r "${PS_TLS_CERT:-}" ] && [ -r "${PS_TLS_KEY:-}" ] || die "PS_TLS_CERT и PS_TLS_KEY должны указывать на читаемые файлы."
    info "Устанавливаю указанный сертификат"
    $SUDO install -m 0644 "$PS_TLS_CERT" "$TLS_DIR/fullchain.pem"
    $SUDO install -m 0600 "$PS_TLS_KEY" "$TLS_DIR/privkey.pem"
    return
  fi
  if $SUDO test -s "$TLS_DIR/fullchain.pem" && $SUDO test -s "$TLS_DIR/privkey.pem"; then
    info "Сертификат уже есть в $TLS_DIR — не изменяю"
    $SUDO test -e "$TLS_DIR/.self-signed" && SELF_SIGNED=1
    return
  fi
  info "Выпускаю самоподписанный сертификат для ${SERVER_NAME}"
  local san="DNS:localhost,IP:127.0.0.1" ip host
  for ip in $(hostname -I 2>/dev/null); do san="$san,IP:$ip"; done
  for host in "$(hostname)" "$(hostname -f 2>/dev/null || true)"; do
    if [ -n "$host" ] && valid_name "$host"; then san="$san,DNS:$host"; fi
  done
  if printf '%s' "$SERVER_NAME" | grep -Eq '^[0-9.]+$|:'; then san="$san,IP:$SERVER_NAME"; else san="$san,DNS:$SERVER_NAME"; fi
  $SUDO openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj "/CN=${SERVER_NAME}/O=Perimeter Scanner" -addext "subjectAltName=${san}" \
    -keyout "$TLS_DIR/privkey.pem" -out "$TLS_DIR/fullchain.pem" >/dev/null 2>&1 \
    || die "Не удалось выпустить сертификат (openssl)."
  $SUDO chmod 600 "$TLS_DIR/privkey.pem"
  $SUDO touch "$TLS_DIR/.self-signed"
  SELF_SIGNED=1
}

write_nginx_site() {
  local port="$1" net allow="" tmp v6_80="" v6_443=""
  # строки для IPv6 добавляются, только если IPv6 включён в системе — иначе nginx не запустится
  if [ -e /proc/net/if_inet6 ]; then
    v6_80="    listen [::]:80 default_server;"
    v6_443="    listen [::]:443 ssl http2 default_server;"
  fi
  for net in $ALLOWED_NETS; do
    valid_net "$net" || die "Некорректная сеть в PS_ALLOWED_NETS: $net"
    allow="${allow}    allow ${net};
"
  done
  tmp="$(mktemp)"
  cat >"$tmp" <<NGINX
# Создано install.sh («Контроль периметра»). При повторном запуске скрипта файл перезаписывается.
server {
    listen 80 default_server;
${v6_80}
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2 default_server;
${v6_443}
    server_name ${SERVER_NAME};

    ssl_certificate     ${TLS_DIR}/fullchain.pem;
    ssl_certificate_key ${TLS_DIR}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:perimeter:10m;
    ssl_session_timeout 1d;
    server_tokens off;

    # Доступ только из внутренних сетей
    allow 127.0.0.1;
    allow ::1;
${allow}    deny all;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-For   \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }
}
NGINX
  $SUDO install -m 0644 "$tmp" "$NGINX_SITE"
  rm -f "$tmp"
}

reload_nginx() {
  $SUDO nginx -t >/dev/null 2>&1 || { $SUDO nginx -t || true; die "Конфигурация nginx не прошла проверку."; }
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    $SUDO systemctl enable nginx >/dev/null 2>&1 || true
    $SUDO systemctl reload nginx 2>/dev/null || $SUDO systemctl restart nginx
  else
    $SUDO nginx -s reload 2>/dev/null || $SUDO nginx
  fi
}

setup_https() {
  valid_name "$SERVER_NAME" || die "Некорректное имя в PS_SERVER_NAME: $SERVER_NAME"
  if ! command -v nginx >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || { warn "Автоустановка nginx поддерживается только на Ubuntu/Debian — HTTPS не настроен."; return; }
    info "Устанавливаю nginx…"
    $SUDO apt-get update -y
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl
  fi
  [ -d /etc/nginx/sites-available ] || { warn "Нестандартная раскладка nginx — HTTPS не настроен, см. README."; return; }

  # Приложение остаётся на 127.0.0.1; наружу его публикует только nginx.
  set_env BIND_ADDRESS 127.0.0.1
  set_env COOKIE_SECURE true
  set_env FORWARDED_ALLOW_IPS '*'
  grep -q '^PUBLIC_URL=.\+' .env || set_env PUBLIC_URL "https://${SERVER_NAME}"
  local port
  port="$(grep -E '^BIND_PORT=' .env | tail -1 | cut -d= -f2-)"; port="${port:-8000}"
  printf '%s' "$port" | grep -Eq '^[0-9]{1,5}$' || die "Некорректный BIND_PORT в .env"

  make_cert
  write_nginx_site "$port"
  $SUDO ln -sfn "$NGINX_SITE" /etc/nginx/sites-enabled/perimeter-scanner
  # стандартная страница nginx занимает те же порты как сервер по умолчанию
  if [ -L /etc/nginx/sites-enabled/default ]; then $SUDO rm -f /etc/nginx/sites-enabled/default; fi
  reload_nginx

  if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q '^Status: active'; then
    info "Открываю 80/443 в ufw для разрешённых сетей"
    local net
    for net in $ALLOWED_NETS; do
      $SUDO ufw allow from "$net" to any port 443 proto tcp >/dev/null
      $SUDO ufw allow from "$net" to any port 80 proto tcp >/dev/null
    done
  fi
  HTTPS_DONE=1
}

if [ "$HTTPS" = "1" ]; then
  setup_https
fi

# --------------------------------------------------------------------------- запуск
info "Собираю образ и запускаю контейнер…"
$DOCKER compose up -d --build

BIND_ADDRESS="$(grep -E '^BIND_ADDRESS=' .env | tail -1 | cut -d= -f2-)"; BIND_ADDRESS="${BIND_ADDRESS:-127.0.0.1}"
BIND_PORT="$(grep -E '^BIND_PORT=' .env | tail -1 | cut -d= -f2-)"; BIND_PORT="${BIND_PORT:-8000}"
CHECK_HOST="$BIND_ADDRESS"; [ "$CHECK_HOST" = "0.0.0.0" ] && CHECK_HOST="127.0.0.1"

info "Жду готовности приложения…"
ok=""
for _ in $(seq 1 60); do
  if $DOCKER compose exec -T app python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)" >/dev/null 2>&1; then
    ok=1; break
  fi
  sleep 2
done
if [ -z "$ok" ]; then
  $DOCKER compose logs --no-color --tail 60 app || true
  die "Приложение не запустилось. Журнал выше; полный журнал: docker compose logs app"
fi

if [ -n "$HTTPS_DONE" ]; then
  ok=""
  for _ in $(seq 1 15); do
    if curl -ksS -o /dev/null --max-time 5 "https://127.0.0.1/healthz" 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [ -n "$ok" ] || warn "nginx не отвечает по https://127.0.0.1 — проверьте: sudo nginx -t; sudo systemctl status nginx"
fi

echo
if [ -n "$HTTPS_DONE" ]; then
  echo "Готово. Интерфейс доступен во внутренней сети:  https://${SERVER_NAME}"
  if [ -n "$SELF_SIGNED" ]; then
    cat <<MSG
  Сертификат самоподписанный: при первом открытии браузер покажет предупреждение —
  это ожидаемо, подтвердите переход. Чтобы предупреждения не было, установите сертификат
  своего удостоверяющего центра: PS_TLS_CERT=... PS_TLS_KEY=... ./install.sh
MSG
  fi
  echo "  Доступ разрешён из сетей: ${ALLOWED_NETS} (изменить: PS_ALLOWED_NETS='...' ./install.sh)"
else
  echo "Готово. Приложение слушает http://${CHECK_HOST}:${BIND_PORT} (только на этой ВМ)."
fi
echo
echo "Логин администратора: $(grep -E '^ADMIN_USERNAME=' .env | cut -d= -f2-)"
if [ -n "$GENERATED_PASSWORD" ]; then
  cat <<MSG
Пароль администратора: ${GENERATED_PASSWORD}
  (показан один раз; после первого входа смените его в разделе «Учётная запись»
   и удалите строку ADMIN_PASSWORD из .env)
MSG
fi
if [ -z "$HTTPS_DONE" ]; then
  cat <<MSG

HTTPS не настроен. Доступ с рабочего места — через SSH-туннель:
    ssh -L ${BIND_PORT}:127.0.0.1:${BIND_PORT} <пользователь>@<адрес ВМ>
и откройте http://127.0.0.1:${BIND_PORT} (для входа по http поставьте COOKIE_SECURE=false
в .env и выполните: docker compose up -d). Настройка nginx вручную — в README.
MSG
fi
cat <<MSG

Что дальше: добавьте цели (IP, подсети, домены) и запустите первый скан.

Журнал:      docker compose logs -f app
Остановка:   docker compose down
Обновление:  git pull && ./install.sh
MSG
