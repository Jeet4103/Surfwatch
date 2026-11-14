import asyncio
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import asyncpg

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
ADVISORY_LOCK_ID = 727274
UP_MARKER = "-- migrate:up"
DOWN_MARKER = "-- migrate:down"
NAME_RE = re.compile(r"^(\d+)_[a-z0-9_]+\.sql$")
RESERVED = {"status", "rollback"}

USAGE = """usage:
  python migrate                         apply all pending migrations
  python migrate <folder>                apply pending migrations of one folder
  python migrate <folder> <file>.sql     go to that migration: apply up to it,
                                         roll back everything after it
  python migrate status                  show applied / pending
  python migrate rollback                roll back the last applied migration
  python migrate rollback all            roll back everything"""


@dataclass(frozen=True)
class Migration:
    number: int
    folder: str
    name: str
    version: str  # e.g. auth/001_create_users.sql
    checksum: str
    up_sql: str
    down_sql: str


def fail(message: str) -> None:
    print(f"error: {message}")
    sys.exit(1)


def load_migrations() -> list[Migration]:
    if not MIGRATIONS_DIR.is_dir():
        fail(f"migrations folder not found: {MIGRATIONS_DIR}")

    migrations: list[Migration] = []
    seen: dict[int, str] = {}

    for path in MIGRATIONS_DIR.rglob("*.sql"):
        match = NAME_RE.match(path.name)
        if not match:
            fail(f"invalid migration filename: {path.name}")
        number = int(match.group(1))
        version = path.relative_to(MIGRATIONS_DIR).as_posix()

        if number in seen:
            fail(f"duplicate migration number {number}: {seen[number]} and {version}")
        seen[number] = version

        sql = path.read_text(encoding="utf-8")
        if UP_MARKER not in sql or DOWN_MARKER not in sql or sql.index(UP_MARKER) > sql.index(DOWN_MARKER):
            fail(f"{version}: needs '{UP_MARKER}' followed by '{DOWN_MARKER}'")

        up_part, down_part = sql.split(DOWN_MARKER, 1)
        up_sql = up_part.split(UP_MARKER, 1)[1].strip()
        down_sql = down_part.strip()
        if not up_sql or not down_sql:
            fail(f"{version}: up and down sections must not be empty")

        migrations.append(
            Migration(
                number=number,
                folder=path.parent.relative_to(MIGRATIONS_DIR).as_posix(),
                name=path.name,
                version=version,
                checksum=hashlib.sha256(sql.encode()).hexdigest(),
                up_sql=up_sql,
                down_sql=down_sql,
            )
        )

    return sorted(migrations, key=lambda m: m.number)


async def ensure_table(conn: asyncpg.Connection) -> None:
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    TEXT PRIMARY KEY,
            checksum   TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )


async def get_applied(conn: asyncpg.Connection, files: list[Migration]) -> list[Migration]:
    rows = {r["version"]: r["checksum"] for r in await conn.fetch("SELECT version, checksum FROM schema_migrations")}
    by_version = {m.version: m for m in files}

    for version in rows:
        if version not in by_version:
            fail(f"applied migration has no file on disk: {version}")

    applied = sorted((by_version[v] for v in rows), key=lambda m: m.number)
    for m in applied:
        if rows[m.version] != m.checksum:
            fail(f"checksum mismatch (file edited after apply): {m.version}")
    return applied


async def apply(conn: asyncpg.Connection, m: Migration) -> None:
    async with conn.transaction():
        await conn.execute(m.up_sql)
        await conn.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)",
            m.version,
            m.checksum,
        )
    print(f"applied      {m.version}")


async def revert(conn: asyncpg.Connection, m: Migration) -> None:
    async with conn.transaction():
        await conn.execute(m.down_sql)
        await conn.execute("DELETE FROM schema_migrations WHERE version = $1", m.version)
    print(f"rolled back  {m.version}")


async def cmd_up(conn, files, folder: str | None) -> None:
    applied = {m.version for m in await get_applied(conn, files)}
    pending = [m for m in files if m.version not in applied and (folder is None or m.folder == folder)]
    if not pending:
        print("nothing to apply")
    for m in pending:
        await apply(conn, m)


async def cmd_goto(conn, files, target: Migration) -> None:
    applied = await get_applied(conn, files)
    applied_versions = {m.version for m in applied}

    # roll back everything after the target (newest first)
    to_revert = [m for m in reversed(applied) if m.number > target.number]
    # apply anything pending up to and including the target
    to_apply = [m for m in files if m.number <= target.number and m.version not in applied_versions]

    if not to_revert and not to_apply:
        print(f"already at {target.version}")
    for m in to_revert:
        await revert(conn, m)
    for m in to_apply:
        await apply(conn, m)


async def cmd_rollback(conn, files, everything: bool) -> None:
    applied = list(reversed(await get_applied(conn, files)))
    targets = applied if everything else applied[:1]
    if not targets:
        print("nothing to roll back")
    for m in targets:
        await revert(conn, m)


async def cmd_status(conn, files) -> None:
    applied = {m.version for m in await get_applied(conn, files)}
    for m in files:
        print(f"[{'x' if m.version in applied else ' '}] {m.version}")


async def main(argv: list[str]) -> None:
    if argv and argv[0] in {"-h", "--help", "help"}:
        print(USAGE)
        return

    files = load_migrations()
    folders = {m.folder for m in files}

    command, folder, target = "up", None, None
    if argv:
        if argv[0] == "status" and len(argv) == 1:
            command = "status"
        elif argv[0] == "rollback" and len(argv) <= 2:
            command = "rollback"
            if len(argv) == 2 and argv[1] != "all":
                fail("usage: python migrate rollback [all]")
        elif argv[0] not in RESERVED and len(argv) <= 2:
            folder = argv[0]
            if folder not in folders:
                fail(f"unknown folder '{folder}' (available: {', '.join(sorted(folders)) or 'none'})")
            if len(argv) == 2:
                target = next((m for m in files if m.folder == folder and m.name == argv[1]), None)
                if target is None:
                    fail(f"unknown migration '{argv[1]}' in '{folder}'")
                command = "goto"
        else:
            print(USAGE)
            sys.exit(1)

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        fail("DATABASE_URL is not set")

    conn = await asyncpg.connect(database_url)
    try:
        await conn.execute("SELECT pg_advisory_lock($1)", ADVISORY_LOCK_ID)
        await ensure_table(conn)
        if command == "up":
            await cmd_up(conn, files, folder)
        elif command == "goto":
            await cmd_goto(conn, files, target)
        elif command == "rollback":
            await cmd_rollback(conn, files, everything=len(argv) == 2)
        else:
            await cmd_status(conn, files)
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", ADVISORY_LOCK_ID)
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))