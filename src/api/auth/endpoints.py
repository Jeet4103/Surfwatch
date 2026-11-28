from fastapi import APIRouter, Request, Response, status

from src.api.auth.schemas import (RegisterRequest, UserResponse, LoginRequest, TokenResponse, SessionResponse, LogoutAllResponse)
from src.core.responses import ApiResponse
from src.dependencies.services import AuthActions
from src.dependencies.auth import CurrentIdentity

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
  "/register",
  response_model=ApiResponse[UserResponse],
  status_code=status.HTTP_201_CREATED,
)
async def register(
  body: RegisterRequest, action: AuthActions
) -> ApiResponse[UserResponse]:
  user = await action.register(body.email, body.password)
  return ApiResponse(data=UserResponse.model_validate(user))

@router.post("/login", response_model=ApiResponse[TokenResponse])
async def login(
  body: LoginRequest, request: Request, response: Response, action: AuthActions
) -> ApiResponse[TokenResponse]:
  result = await action.login(
    body.email,
    body.password,
    device_name=body.device_name,
    ip_address=request.client.host if request.client else None,
    user_agent=request.headers.get("user-agent"),
  )
  response.headers["Cache-Control"] = "no-store"
  return ApiResponse(
    data=TokenResponse(
      access_token=result.access_token,
      refresh_token=result.refresh_token,
      expires_in=result.expires_in,
      user=UserResponse.model_validate(result.user),
    )
  )


@router.get("/me", response_model=ApiResponse[UserResponse])
async def me(identity: CurrentIdentity, response: Response) -> ApiResponse[UserResponse]:
  response.headers["Cache-Control"] = "no-store"
  return ApiResponse(data=UserResponse.model_validate(identity.user))

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(identity: CurrentIdentity, action: AuthActions) -> None:
  await action.logout(user_id=identity.user.id, session_id=identity.session_id)


@router.post("/logout-all", response_model=ApiResponse[LogoutAllResponse])
async def logout_all(
  identity: CurrentIdentity,
  action: AuthActions,
  keep_current: bool = False,
) -> ApiResponse[LogoutAllResponse]:
  count = await action.logout_all(
    user_id=identity.user.id,
    keep_session_id=identity.session_id if keep_current else None,
  )
  return ApiResponse(data=LogoutAllResponse(revoked=count))


@router.get("/sessions", response_model=ApiResponse[list[SessionResponse]])
async def list_sessions(
  identity: CurrentIdentity, action: AuthActions, response: Response
) -> ApiResponse[list[SessionResponse]]:
  sessions = await action.list_sessions(
    user_id=identity.user.id, current_session_id=identity.session_id
  )
  response.headers["Cache-Control"] = "no-store"
  return ApiResponse(data=[SessionResponse.model_validate(s) for s in sessions])


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: int, identity: CurrentIdentity, action: AuthActions) -> None:
  await action.revoke_session(user_id=identity.user.id, session_id=session_id)