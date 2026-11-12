"""Командная строка: управление пользователями и импорт целей.

    python -m app.cli create-user --admin <логин>
    python -m app.cli reset-password <логин>
    python -m app.cli import-targets targets.yaml
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from sqlalchemy import select

from app.db import create_all, session_scope
from app.models import Role, User
from app.security.passwords import hash_password
from app.validation import ValidationError, validate_password, validate_username


def _ask_password() -> str:
    pw = getpass.getpass("Пароль: ")
    if pw != getpass.getpass("Повторите пароль: "):
        raise ValidationError("Пароли не совпадают")
    return validate_password(pw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user", help="создать пользователя")
    cu.add_argument("username")
    cu.add_argument("--admin", action="store_true", help="роль «администратор»")
    rp = sub.add_parser("reset-password", help="сменить пароль пользователя")
    rp.add_argument("username")
    it = sub.add_parser("import-targets", help="импортировать цели из YAML")
    it.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    create_all()
    try:
        with session_scope() as db:
            if args.cmd == "create-user":
                username = validate_username(args.username)
                if db.scalar(select(User).where(User.username == username)):
                    raise ValidationError("Пользователь уже существует")
                db.add(
                    User(
                        username=username,
                        password_hash=hash_password(_ask_password()),
                        role=Role.ADMIN.value if args.admin else Role.VIEWER.value,
                    )
                )
                print(f"Пользователь {username} создан")
            elif args.cmd == "reset-password":
                user = db.scalar(select(User).where(User.username == args.username))
                if not user:
                    raise ValidationError("Пользователь не найден")
                user.password_hash = hash_password(_ask_password())
                user.is_active = True
                print("Пароль изменён")
            elif args.cmd == "import-targets":
                from app.targets_service import import_targets_yaml

                res = import_targets_yaml(db, args.path.read_text(encoding="utf-8"), created_by="cli")
                print(f"Создано: {res.created}, обновлено: {res.updated}")
                for e in res.errors:
                    print("Ошибка:", e, file=sys.stderr)
    except ValidationError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
