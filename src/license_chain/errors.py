"""许可与流转服务向 API 和 CLI 暴露的稳定错误。"""

from __future__ import annotations

from typing import Any


class LicenseChainError(RuntimeError):
    code = "license_chain_error"
    status = 400

    def __init__(self, message: str, details: Any = None) -> None:
        super().__init__(message)
        self.details = details


class NotFound(LicenseChainError):
    code = "not_found"
    status = 404


class Conflict(LicenseChainError):
    code = "conflict"
    status = 409


class Forbidden(LicenseChainError):
    code = "forbidden"
    status = 403


class InvalidState(LicenseChainError):
    code = "invalid_state"
    status = 409


class ValidationFailed(LicenseChainError):
    code = "validation_failed"
    status = 422
