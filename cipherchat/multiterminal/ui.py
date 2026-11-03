"""Reuse the existing local UI without writing an audit file on every poll."""
from cipherchat.ui.server import _Handler


class LabUIHandler(_Handler):
    last_persisted_revision = -1

    def log_message(self, format: str, *args: object) -> None:
        if self.path != "/api/state":
            super().log_message(format, *args)

    def _log_request_json(self, method, path, status_code, duration_ms, client_ip, error=None):
        revision = self.controller.snapshot().get("revision", -1)
        if method == "GET" and path == "/api/state" and revision == self.__class__.last_persisted_revision:
            return
        super()._log_request_json(method, path, status_code, duration_ms, client_ip, error)
        self.__class__.last_persisted_revision = revision
