"""许可流转服务向 API 和 CLI 暴露的稳定错误。"""


class LicensingError(RuntimeError):
    code = "licensing_error"
    status = 400

    def __init__(self, message: str, details: object | None = None) -> None:
        super().__init__(message)
        self.details = details


class NotFound(LicensingError):
    code = "not_found"
    status = 404


class Conflict(LicensingError):
    code = "conflict"
    status = 409


class Forbidden(LicensingError):
    code = "forbidden"
    status = 403


class InvalidState(LicensingError):
    code = "invalid_state"
    status = 409


class ValidationFailed(LicensingError):
    code = "validation_failed"
    status = 422


class AuthorizationBlocked(LicensingError):
    """拟办流转在当前已知事实下无法形成完整授权链。"""

    code = "authorization_blocked"
    status = 409
