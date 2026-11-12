#!/usr/bin/env bash
# Установка и запуск «Контроля периметра» на Ubuntu Server.
#
#   git clone <репозиторий> /opt/perimeter-scanner && cd /opt/perimeter-scanner
#   ./install.sh
#
# Скрипт можно запускать повторно: существующие .env и targets.yaml не перезаписываются.
# Необязательные переменные окружения:
#   PS_ADMIN_PASSWORD — пароль первого администратора (иначе будет сгенерирован)
#   PS_ADMIN_USERNAME — логин первого администратора (по умолчанию admin)
set -euo pipefail

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

cat <<MSG

Готово. Приложение запущено и слушает http://${CHECK_HOST}:${BIND_PORT} (только на этой ВМ).

Логин администратора: $(grep -E '^ADMIN_USERNAME=' .env | cut -d= -f2-)
MSG
if [ -n "$GENERATED_PASSWORD" ]; then
  cat <<MSG
Пароль администратора: ${GENERATED_PASSWORD}
  (показан один раз; после первого входа смените его в разделе «Учётная запись»
   и удалите строку ADMIN_PASSWORD из .env)
MSG
fi
cat <<MSG

Что дальше:
  1. Доступ с рабочего места до настройки HTTPS — через SSH-туннель:
       ssh -L ${BIND_PORT}:127.0.0.1:${BIND_PORT} <пользователь>@<адрес ВМ>
     и откройте http://127.0.0.1:${BIND_PORT}. Для входа по http временно поставьте
     COOKIE_SECURE=false в .env и выполните: docker compose up -d
  2. Публикация во внутренней сети через nginx с HTTPS — раздел README
     «Публикация во внутренней сети».
  3. Добавьте цели (IP, подсети, домены) и запустите первый скан.

Журнал:      docker compose logs -f app
Остановка:   docker compose down
Обновление:  git pull && docker compose up -d --build
MSG
