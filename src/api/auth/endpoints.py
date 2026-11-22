from fastapi import APIRouter, Request, Response, status

from src.api.auth.schemas import RegisterRequest, UserResponse, LoginRequest, TokenResponse
from src.core.responses import ApiResponse
from src.dependencies.services import AuthActions

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