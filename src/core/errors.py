import logging
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class ErrorCode(StrEnum):
  """Generic, app-wide codes. Feature-specific codes live next to their feature."""

  VALIDATION_ERROR = "VALIDATION_ERROR"
  BAD_REQUEST = "BAD_REQUEST"
  UNAUTHORIZED = "UNAUTHORIZED"
  INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS"
  RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
  CONFLICT = "CONFLICT"
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
  INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"


class AppError(Exception):
  """Base for every error returned to API clients.

  Features subclass one of the generic errors below and set their own `code`
  (any string), `status_code` and `message`.
  """

  code: str = ErrorCode.INTERNAL_SERVER_ERROR
  status_code: int = 500
  message: str = "Internal server error"

  def __init__(
    self,
    message: str | None = None,
    *,
    headers: dict[str, str] | None = None,
  ) -> None:
    self.message = message or type(self).message
    self.headers = headers
    super().__init__(self.message)


class CustomError(AppError):
  """Reusable application error with a caller-defined message and status.

  Example: ``raise CustomError("Auth service unavailable", status_code=503)``.
  """

  code = "CUSTOM_ERROR"

  def __init__(
    self,
    message: str,
    *,
    status_code: int = 500,
    code: str = "CUSTOM_ERROR",
    headers: dict[str, str] | None = None,
  ) -> None:
    self.code = code
    self.status_code = status_code
    super().__init__(message, headers=headers)


class BadRequest(AppError):
  code = ErrorCode.BAD_REQUEST
  status_code = 400
  message = "Bad request"


class Unauthorized(AppError):
  code = ErrorCode.UNAUTHORIZED
  status_code = 401
  message = "Authentication required"


class Forbidden(AppError):
  code = ErrorCode.INSUFFICIENT_PERMISSIONS
  status_code = 403
  message = "You do not have permission to perform this action"


class NotFound(AppError):
  code = ErrorCode.RESOURCE_NOT_FOUND
  status_code = 404
  message = "Resource not found"


class Conflict(AppError):
  code = ErrorCode.CONFLICT
  status_code = 409
  message = "Conflict with the current state of the resource"


class ValidationFailed(AppError):
  code = ErrorCode.VALIDATION_ERROR
  status_code = 422
  message = "Invalid request"


class RateLimited(AppError):
  code = ErrorCode.RATE_LIMIT_EXCEEDED
  status_code = 429
  message = "Too many requests"

  def __init__(self, message: str | None = None, *, retry_after: int | None = None) -> None:
    headers = {"Retry-After": str(retry_after)} if retry_after else None
    super().__init__(message, headers=headers)


class InternalError(AppError):
  code = ErrorCode.INTERNAL_SERVER_ERROR
  status_code = 500
  message = "Internal server error"


def _error_response(
  status_code: int,
  code: str,
  message: str,
  *,
  details: list[dict[str, Any]] | None = None,
  headers: dict[str, str] | None = None,
) -> JSONResponse:
  error: dict[str, Any] = {"code": str(code), "message": message}
  if details:
    error["details"] = details
  return JSONResponse(
    status_code=status_code,
    content={"success": False, "error": error},
    headers=headers,
  )


_HTTP_STATUS_CODES: dict[int, ErrorCode] = {
  400: ErrorCode.BAD_REQUEST,
  401: ErrorCode.UNAUTHORIZED,
  403: ErrorCode.INSUFFICIENT_PERMISSIONS,
  404: ErrorCode.RESOURCE_NOT_FOUND,
  409: ErrorCode.CONFLICT,
  422: ErrorCode.VALIDATION_ERROR,
  429: ErrorCode.RATE_LIMIT_EXCEEDED,
}


def register_error_handlers(app: FastAPI) -> None:
  @app.exception_handler(AppError)
  async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    if exc.status_code >= 500:
      logger.error("app error on %s %s: %s", request.method, request.url.path, exc.code)
      return _error_response(
        exc.status_code,
        ErrorCode.INTERNAL_SERVER_ERROR,
        "Internal server error",
        headers=exc.headers,
      )
    return _error_response(exc.status_code, exc.code, exc.message, headers=exc.headers)

  @app.exception_handler(RequestValidationError)
  async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # never echo the submitted input: it can contain passwords
    details = [
      {
        "field": ".".join(str(p) for p in err["loc"] if p != "body"),
        "message": err["msg"],
      }
      for err in exc.errors()
    ]
    return _error_response(
      422, ErrorCode.VALIDATION_ERROR, "Invalid request", details=details
    )

  @app.exception_handler(StarletteHTTPException)
  async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code >= 500:
      code = ErrorCode.INTERNAL_SERVER_ERROR
      message = "Internal server error"
    else:
      code = _HTTP_STATUS_CODES.get(exc.status_code, ErrorCode.BAD_REQUEST)
      message = str(exc.detail)
    return _error_response(
      exc.status_code, code, message, headers=getattr(exc, "headers", None)
    )

  @app.exception_handler(Exception)
  async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return _error_response(
      500, ErrorCode.INTERNAL_SERVER_ERROR, "Internal server error"
    )
