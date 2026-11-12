# Контроль внешнего периметра

Внутренний веб-инструмент для контроля внешнего периметра организации.
Подробная инструкция по установке будет дополнена по мере реализации этапов.

Быстрый старт (локально):

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env   # заполните SECRET_KEY и ADMIN_PASSWORD, COOKIE_SECURE=false для http
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```
