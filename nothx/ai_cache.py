"""Optional cache of AI content labels, keyed only by prompt fingerprints."""

import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from . import db
from .models import Action, Classification, EmailType

MAX_AGE_SECONDS = 7 * 24 * 60 * 60


def _path() -> Path:
    return Path(db.get_db_path()).with_suffix(".ai-cache.sqlite3")


def load(fingerprints: list[str]) -> dict[str, Classification]:
    path = _path()
    if not fingerprints or not path.is_file() or path.is_symlink():
        return {}
    results = {}
    try:
        with closing(
            sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
        ) as connection:
            for start in range(0, len(fingerprints), 400):
                chunk = fingerprints[start : start + 400]
                placeholders = ",".join("?" for _ in chunk)
                rows = connection.execute(
                    f"SELECT fingerprint, email_type, action, confidence FROM classifications "
                    f"WHERE fingerprint IN ({placeholders}) AND created_at >= ?",
                    [*chunk, time.time() - MAX_AGE_SECONDS],
                )
                for key, email_type, action, confidence in rows:
                    try:
                        confidence = float(confidence)
                        if not 0 <= confidence <= 1:
                            continue
                        parsed_type = EmailType(email_type)
                        parsed_action = Action(action)
                        safe_action = (
                            Action.REVIEW
                            if parsed_type is EmailType.UNKNOWN
                            and parsed_action in {Action.UNSUB, Action.BLOCK}
                            else parsed_action
                        )
                        results[key] = Classification(
                            parsed_type,
                            safe_action,
                            confidence,
                            "Reused unchanged AI classification; local policy rechecked",
                            "ai",
                            recommended_action=parsed_action,
                        )
                    except (TypeError, ValueError):
                        continue
    except (OSError, sqlite3.Error):
        return {}
    return results


def save(results: dict[str, Classification]) -> None:
    if not results:
        return
    path = _path()
    try:
        if path.is_symlink():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        path.chmod(0o600)
        with closing(sqlite3.connect(path, timeout=1)) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS classifications ("
                "fingerprint TEXT PRIMARY KEY CHECK (length(fingerprint) = 64), "
                "email_type TEXT NOT NULL, action TEXT NOT NULL, confidence REAL NOT NULL, "
                "created_at REAL NOT NULL)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS cache_created ON classifications(created_at)"
            )
            now = time.time()
            connection.executemany(
                "INSERT OR REPLACE INTO classifications VALUES (?, ?, ?, ?, ?)",
                [
                    (key, value.email_type.value, value.action.value, value.confidence, now)
                    for key, value in results.items()
                ],
            )
            connection.execute(
                "DELETE FROM classifications WHERE created_at < ?", (now - MAX_AGE_SECONDS,)
            )
            connection.execute(
                "DELETE FROM classifications WHERE fingerprint IN "
                "(SELECT fingerprint FROM classifications ORDER BY created_at DESC LIMIT -1 OFFSET 50000)"
            )
    except (OSError, sqlite3.Error):
        return
