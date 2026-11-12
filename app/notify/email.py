"""Отправка уведомлений по электронной почте (SMTP)."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from app.config import get_settings
from app.notify.telegram import NotifyError


def email_configured() -> bool:
    s = get_settings()
    return bool(s.smtp_host and s.smtp_from and s.smtp_to)


def send_email(subject: str, text: str, html: str | None = None) -> None:
    s = get_settings()
    if not email_configured():
        raise NotifyError("Не заданы SMTP_HOST, SMTP_FROM и SMTP_TO в .env")
    recipients = [r.strip() for r in s.smtp_to.split(",") if r.strip()]
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\n", " ")[:200]
    msg["From"] = s.smtp_from
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=s.smtp_from.split("@")[-1] if "@" in s.smtp_from else None)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    ctx = ssl.create_default_context()
    try:
        if s.smtp_ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=30, context=ctx)
        else:
            server = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30)
        with server:
            server.ehlo()
            if s.smtp_starttls and not s.smtp_ssl:
                server.starttls(context=ctx)
                server.ehlo()
            if s.smtp_user:
                server.login(s.smtp_user, s.smtp_password)
            server.send_message(msg, to_addrs=recipients)
    except (smtplib.SMTPException, OSError) as exc:
        raise NotifyError(f"Ошибка SMTP: {type(exc).__name__}: {str(exc)[:200]}") from None
