"""Тонкий клиент Metasploit RPC (msgpack поверх HTTP).

Приложение не вызывает msfconsole и не исполняет shell — оно общается с демоном
msfrpcd по RPC (msgpack). Демон поднимается отдельным контейнером во внутренней
сети Docker и не публикуется наружу. См. README, раздел про Metasploit.

Клиент намеренно минимальный: один метод call() кодирует запрос в msgpack,
отправляет POST и декодирует ответ; поверх него — несколько удобных обёрток.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import msgpack

from app.config import get_settings

log = logging.getLogger("msf")


class MsfError(RuntimeError):
    pass


class MsfAuthError(MsfError):
    pass


def _to_native(obj: Any) -> Any:
    """Рекурсивно приводит bytes → str (msf иногда отдаёт бинарные строки)."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    if isinstance(obj, dict):
        return {_to_native(k): _to_native(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_native(v) for v in obj]
    return obj


class MsfRpcClient:
    def __init__(
        self,
        host: str,
        port: int,
        password: str,
        *,
        username: str = "msf",
        ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        if not password:
            raise MsfError("Не задан пароль RPC Metasploit (MSF_RPC_PASSWORD)")
        scheme = "https" if ssl else "http"
        self._url = f"{scheme}://{host}:{port}/api/"
        self._username = username
        self._password = password
        self._timeout = timeout
        self._token: str | None = None
        # демон во внутренней сети с самоподписанным сертификатом — проверку TLS не делаем
        self._client = httpx.Client(timeout=timeout, verify=False)

    # ---- низкий уровень
    def call(self, method: str, *args: Any, with_token: bool = True) -> Any:
        payload: list[Any] = [method]
        if with_token:
            if self._token is None:
                self.login()
            payload.append(self._token)
        payload.extend(args)
        try:
            resp = self._client.post(
                self._url,
                content=msgpack.packb(payload, use_bin_type=True),
                headers={"Content-Type": "binary/message-pack"},
            )
        except httpx.HTTPError as exc:
            raise MsfError(f"Metasploit RPC недоступен: {type(exc).__name__}") from None
        if resp.status_code != 200:
            raise MsfError(f"Metasploit RPC вернул HTTP {resp.status_code}")
        try:
            data = _to_native(msgpack.unpackb(resp.content, raw=False, strict_map_key=False))
        except (msgpack.UnpackException, ValueError) as exc:
            raise MsfError(f"Не удалось разобрать ответ Metasploit RPC: {exc}") from None
        if isinstance(data, dict) and data.get("error"):
            msg = data.get("error_message") or data.get("error_string") or "ошибка RPC"
            if "token" in str(msg).lower() or data.get("error_code") == 401:
                self._token = None
                raise MsfAuthError(str(msg))
            raise MsfError(str(msg))
        return data

    def login(self) -> None:
        data = self.call("auth.login", self._username, self._password, with_token=False)
        if not isinstance(data, dict) or data.get("result") != "success" or not data.get("token"):
            raise MsfAuthError("Не удалось авторизоваться в Metasploit RPC (проверьте MSF_RPC_PASSWORD)")
        self._token = str(data["token"])

    def logout(self) -> None:
        if self._token:
            try:
                self.call("auth.logout", self._token)
            except MsfError:
                pass
            self._token = None

    def close(self) -> None:
        self.logout()
        self._client.close()

    def __enter__(self) -> MsfRpcClient:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- удобные обёртки
    def version(self) -> dict[str, Any]:
        data = self.call("core.version")
        return data if isinstance(data, dict) else {}

    def module_names(self, module_type: str) -> list[str]:
        data = self.call(f"module.{module_type}s")
        if isinstance(data, dict):
            return [str(m) for m in data.get("modules", [])]
        if isinstance(data, list):
            return [str(m) for m in data]
        return []

    def module_info(self, module_type: str, name: str) -> dict[str, Any]:
        data = self.call("module.info", module_type, name)
        return data if isinstance(data, dict) else {}

    def module_options(self, module_type: str, name: str) -> dict[str, Any]:
        data = self.call("module.options", module_type, name)
        return data if isinstance(data, dict) else {}

    def module_check(self, module_type: str, name: str, options: dict[str, Any]) -> dict[str, Any]:
        """Запускает проверку эксплуатируемости (без запуска нагрузки)."""
        data = self.call("module.check", module_type, name, options)
        return data if isinstance(data, dict) else {}

    def module_results(self, uuid: str) -> dict[str, Any]:
        data = self.call("module.results", uuid)
        return data if isinstance(data, dict) else {}

    def module_execute(self, module_type: str, name: str, options: dict[str, Any]) -> dict[str, Any]:
        data = self.call("module.execute", module_type, name, options)
        return data if isinstance(data, dict) else {}

    def session_list(self) -> dict[str, Any]:
        data = self.call("session.list")
        return data if isinstance(data, dict) else {}

    def session_stop(self, session_id: str | int) -> dict[str, Any]:
        data = self.call("session.stop", str(session_id))
        return data if isinstance(data, dict) else {}

    def jobs(self) -> dict[str, Any]:
        data = self.call("job.list")
        return data if isinstance(data, dict) else {}

    def job_stop(self, job_id: str | int) -> dict[str, Any]:
        data = self.call("job.stop", str(job_id))
        return data if isinstance(data, dict) else {}


def client_from_settings() -> MsfRpcClient:
    s = get_settings()
    return MsfRpcClient(
        s.msf_rpc_host,
        s.msf_rpc_port,
        s.msf_rpc_password,
        ssl=s.msf_rpc_ssl,
        timeout=min(s.msf_timeout_minutes * 60, 120),
    )


def msf_configured() -> bool:
    s = get_settings()
    return bool(s.msf_enabled and s.msf_rpc_password)
