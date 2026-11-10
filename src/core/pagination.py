from dataclasses import dataclass
from math import ceil
from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel

from src.core.config import get_settings
from src.core.errors import ValidationFailed

# protocol limit, keeps OFFSET inside bigint and deep scans bounded
MAX_PAGE = 100_000


@dataclass(frozen=True, slots=True)
class PageParams:
  page: int
  page_size: int

  @property
  def limit(self) -> int:
    return self.page_size

  @property
  def offset(self) -> int:
    return (self.page - 1) * self.page_size


def get_page_params(
  page: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1,
  page_size: Annotated[int | None, Query(ge=1)] = None,
) -> PageParams:
  settings = get_settings()
  size = settings.pagination_default_page_size if page_size is None else page_size
  if size > settings.pagination_max_page_size:
    raise ValidationFailed(
      f"page_size must be at most {settings.pagination_max_page_size}"
    )
  return PageParams(page=page, page_size=size)


PageQuery = Annotated[PageParams, Depends(get_page_params)]


@dataclass(frozen=True, slots=True)
class Page[T]:
  """What repositories and operations return for a list query."""

  items: list[T]
  total: int
  params: PageParams

  @property
  def total_pages(self) -> int:
    return ceil(self.total / self.params.page_size)


class PageMeta(BaseModel):
  page: int
  page_size: int
  total: int
  total_pages: int
  has_next: bool
  has_previous: bool


class PaginatedData[T](BaseModel):
  items: list[T]
  pagination: PageMeta


def to_paginated[T, R](page: Page[T], items: list[R]) -> PaginatedData[R]:
  """Build the response body. `items` are the mapped response schemas."""
  p = page.params
  return PaginatedData[R](
    items=items,
    pagination=PageMeta(
      page=p.page,
      page_size=p.page_size,
      total=page.total,
      total_pages=page.total_pages,
      has_next=p.page < page.total_pages,
      has_previous=p.page > 1,
    ),
  )