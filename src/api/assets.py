from datetime import datetime
from enum import StrEnum

import asyncpg
from pydantic import BaseModel

from src.core.errors import ValidationFailed
from src.core.pagination import Page, PageQuery, PaginatedData, to_paginated

SORTABLE = {
  "created_at": "created_at",
  "domain": "domain",
  "last_seen": "last_seen",
}


class Order(StrEnum):
  asc = "asc"
  desc = "desc"


class AssetResponse(BaseModel):
  id: int
  domain: str
  created_at: datetime
  last_seen: datetime | None = None


async def fetch_assets(
  page: PageQuery,
  conn: asyncpg.Connection,
  query: str | None = None,
  sort_by: str = "created_at",
  order: Order = Order.desc,
) -> PaginatedData[AssetResponse]:
  if sort_by not in SORTABLE:
    raise ValidationFailed(f"sort_by must be one of: {', '.join(sorted(SORTABLE))}")

  where = ["deleted_at IS NULL"]
  filter_args: list[str] = []
  if query:
    filter_args.append(f"%{query}%")
    where.append(f"domain ILIKE ${len(filter_args)}")

  where_sql = " AND ".join(where)
  total = await conn.fetchval(
    f"SELECT COUNT(*) FROM assets WHERE {where_sql}", *filter_args  # noqa: S608
  )

  args: list[str | int] = [*filter_args, page.limit, page.offset]
  sql = f"""
    SELECT *
    FROM assets
    WHERE {where_sql}
    ORDER BY {SORTABLE[sort_by]} {order.value} NULLS LAST, id
    LIMIT ${len(args) - 1} OFFSET ${len(args)}
  """  # noqa: S608

  rows = await conn.fetch(sql, *args)
  items = [AssetResponse(**dict(r)) for r in rows]

  return to_paginated(Page(items=items, total=total or 0, params=page), items)
