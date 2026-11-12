"""Отправка сообщений через Telegram Bot API."""

from __future__ import annotations

import httpx

from app.config import get_settings

API = "https://api.telegram.org"
MAX_LEN = 4000


class NotifyError(RuntimeError):
    pass


def telegram_configured() -> bool:
    s = get_settings()
    return bool(s.telegram_bot_token and s.telegram_chat_id)


def send_telegram(html_text: str) -> None:
    s = get_settings()
    if not telegram_configured():
        raise NotifyError("Не заданы TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID в .env")
    if len(html_text) > MAX_LEN:
        html_text = html_text[: MAX_LEN - 20] + "\n…"
    try:
        r = httpx.post(
            f"{API}/bot{s.telegram_bot_token}/sendMessage",
            json={
                "chat_id": s.telegram_chat_id,
                "text": html_text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
    except httpx.HTTPError as exc:
        # не включаем текст исключения целиком: в URL содержится токен бота
        raise NotifyError(f"Telegram недоступен: {type(exc).__name__}") from None
    if r.status_code != 200:
        try:
            desc = r.json().get("description", "")
        except ValueError:
            desc = ""
        raise NotifyError(f"Telegram вернул ошибку {r.status_code}: {desc[:200]}")
