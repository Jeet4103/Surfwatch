from fastapi import APIRouter, status

from src.api.auth.schemas import RegisterRequest, UserResponse
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