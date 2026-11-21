"""Persistent identity, authorization, quota and audit storage for Sent Eye.

The database contains password hashes and hashed session/CSRF tokens only.
Raw passwords and raw session tokens must never be written to this database.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


class AccessDenied(Exception):
    """The account or module is not authorized."""


class QuotaExceeded(Exception):
    """A user's module quota has been exhausted."""


def utc_day_start(timestamp: Optional[float] = None) -> float:
    dt = datetime.fromtimestamp(timestamp or time.time(), timezone.utc)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def utc_month_start(timestamp: Optional[float] = None) -> float:
    dt = datetime.fromtimestamp(timestamp or time.time(), timezone.utc)
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp()


class AuthStore:
    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is not None:
            self.db_path = Path(db_path).expanduser()
        else:
            configured_dir = os.environ.get("SENT_EYE_DATA_DIR", "").strip()
            data_dir = (
                Path(configured_dir).expanduser()
                if configured_dir
                else Path(__file__).resolve().parents[2] / ".data"
            )
            self.db_path = data_dir / "sent-eye.sqlite3"

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.db_path.parent, 0o700)
        except OSError:
            pass

        connection = sqlite3.connect(
            str(self.db_path),
            timeout=20,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 20000")
        try:
            yield connection
            if connection.in_transaction:
                connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def init_db(self) -> None:
        with self._connection() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    full_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                        CHECK (role IN ('user', 'admin')),
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
                    created_at REAL NOT NULL,
                    approved_at REAL,
                    approved_by TEXT,
                    last_login_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_users_status
                    ON users(status, created_at);

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    csrf_hash TEXT NOT NULL,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    revoked_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_user
                    ON sessions(user_id, expires_at);

                CREATE TABLE IF NOT EXISTS module_permissions (
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    module_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
                    daily_limit INTEGER,
                    monthly_limit INTEGER,
                    updated_at REAL NOT NULL,
                    updated_by TEXT,
                    PRIMARY KEY (user_id, module_name),
                    CHECK (daily_limit IS NULL OR daily_limit >= 0),
                    CHECK (monthly_limit IS NULL OR monthly_limit >= 0)
                );

                CREATE TABLE IF NOT EXISTS investigations (
                    job_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    target_type TEXT NOT NULL,
                    target_display TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    finished_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_investigations_user
                    ON investigations(user_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS module_usage (
                    usage_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    module_name TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES investigations(job_id) ON DELETE CASCADE,
                    target_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    created_at REAL NOT NULL,
                    finished_at REAL
                );

                CREATE INDEX IF NOT EXISTS idx_module_usage_quota
                    ON module_usage(user_id, module_name, created_at);

                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    actor_user_id TEXT REFERENCES users(user_id),
                    subject_user_id TEXT REFERENCES users(user_id),
                    job_id TEXT,
                    module_name TEXT,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_created
                    ON audit_events(created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_audit_subject
                    ON audit_events(subject_user_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS login_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    email_key TEXT NOT NULL,
                    ip_key TEXT NOT NULL,
                    succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
                    attempted_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_login_email
                    ON login_attempts(email_key, attempted_at);

                CREATE INDEX IF NOT EXISTS idx_login_ip
                    ON login_attempts(ip_key, attempted_at);
                """
            )
            db.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (time.time() - 30 * 86400,),
            )

            investigation_columns = {
                row["name"]
                for row in db.execute(
                    "PRAGMA table_info(investigations)"
                ).fetchall()
            }
            if "report_json" not in investigation_columns:
                db.execute(
                    "ALTER TABLE investigations ADD COLUMN report_json TEXT"
                )

        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        return dict(row) if row is not None else None

    def create_user(
        self,
        email: str,
        full_name: str,
        password_hash: str,
        *,
        role: str = "user",
        status: str = "pending",
        approved_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        if role not in ("user", "admin"):
            raise ValueError("Invalid account role.")
        if status not in ("pending", "approved", "rejected", "suspended"):
            raise ValueError("Invalid account status.")

        now = time.time()
        user_id = uuid.uuid4().hex
        approved_at = now if status == "approved" else None

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO users (
                    user_id, email, full_name, password_hash,
                    role, status, created_at, approved_at, approved_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, email.strip().lower(), full_name.strip(),
                    password_hash, role, status, now, approved_at, approved_by,
                ),
            )
            row = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            return self._dict(row) or {}

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as db:
            row = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            return self._dict(row)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._connection() as db:
            row = db.execute(
                "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
                (email.strip(),),
            ).fetchone()
            return self._dict(row)

    def count_admins(self) -> int:
        with self._connection() as db:
            row = db.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
            ).fetchone()
            return int(row["n"])

    def create_first_admin(
        self,
        email: str,
        full_name: str,
        password_hash: str,
    ) -> Dict[str, Any]:
        """Create the initial administrator exactly once, atomically."""
        now = time.time()
        user_id = uuid.uuid4().hex

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
            ).fetchone()["n"]
            if int(count) != 0:
                raise ValueError(
                    "An administrator already exists. First-admin setup is disabled."
                )

            db.execute(
                """
                INSERT INTO users (
                    user_id, email, full_name, password_hash,
                    role, status, created_at, approved_at
                ) VALUES (?, ?, ?, ?, 'admin', 'approved', ?, ?)
                """,
                (
                    user_id, email.strip().lower(), full_name.strip(),
                    password_hash, now, now,
                ),
            )
            self._insert_audit(
                db, user_id, user_id, None, None,
                "admin.initial_account_created", {},
            )
            row = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            return self._dict(row) or {}

    def create_unrestricted_operator(
        self,
        email: str,
        full_name: str,
        password_hash: str,
        module_names: List[str],
        admin_user_id: str,
    ) -> Dict[str, Any]:
        """Atomically create an approved user with unlimited module access."""
        email = email.strip().lower()
        full_name = " ".join(full_name.split())
        names = list(module_names)

        if not email or len(email) > 254:
            raise ValueError("Invalid operator email.")
        if len(full_name) < 2 or len(full_name) > 100:
            raise ValueError("Operator name must be between 2 and 100 characters.")
        if not password_hash:
            raise ValueError("Password hash is required.")
        if not names or any(not isinstance(name, str) or not name.strip() for name in names):
            raise ValueError("At least one valid module is required.")

        names = sorted(set(names))
        now = time.time()
        user_id = uuid.uuid4().hex

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")

            admin = db.execute(
                "SELECT role, status FROM users WHERE user_id = ?",
                (admin_user_id,),
            ).fetchone()

            if admin is None or admin["role"] != "admin" or admin["status"] != "approved":
                raise ValueError("An approved administrator is required.")

            existing = db.execute(
                "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE",
                (email,),
            ).fetchone()

            if existing:
                raise ValueError("An account with this email already exists.")

            db.execute(
                """
                INSERT INTO users (
                    user_id, email, full_name, password_hash,
                    role, status, created_at, approved_at, approved_by
                ) VALUES (?, ?, ?, ?, 'user', 'approved', ?, ?, ?)
                """,
                (user_id, email, full_name, password_hash, now, now, admin_user_id),
            )

            self._insert_audit(
                db, admin_user_id, user_id, None, None,
                "user.unrestricted_operator_created",
                {"module_count": len(names), "daily_limit": None, "monthly_limit": None},
            )

            for module_name in names:
                db.execute(
                    """
                    INSERT INTO module_permissions (
                        user_id, module_name, enabled, daily_limit,
                        monthly_limit, updated_at, updated_by
                    ) VALUES (?, ?, 1, NULL, NULL, ?, ?)
                    """,
                    (user_id, module_name, now, admin_user_id),
                )
                self._insert_audit(
                    db, admin_user_id, user_id, None, module_name,
                    "module.permission_changed",
                    {
                        "enabled": True,
                        "daily_limit": None,
                        "monthly_limit": None,
                        "access_profile": "unrestricted_operator",
                    },
                )

            row = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            return self._dict(row) or {}

    def record_audit_event(
        self,
        *,
        actor_user_id: Optional[str],
        subject_user_id: Optional[str] = None,
        job_id: Optional[str] = None,
        module_name: Optional[str] = None,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._connection() as db:
            self._insert_audit(
                db,
                actor_user_id,
                subject_user_id,
                job_id,
                module_name,
                event_type,
                details or {},
            )

    def list_users(self) -> List[Dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users ORDER BY created_at DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def update_user_status(
        self,
        user_id: str,
        status: str,
        actor_user_id: str,
    ) -> Dict[str, Any]:
        if status not in ("approved", "rejected", "suspended"):
            raise ValueError("Invalid account status.")

        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT role, status FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if row is None:
                raise ValueError("User not found.")
            if row["role"] == "admin" and status != "approved":
                raise ValueError("Administrator accounts cannot be changed here.")

            db.execute(
                """
                UPDATE users
                SET status = ?,
                    approved_at = CASE WHEN ? = 'approved' THEN ? ELSE approved_at END,
                    approved_by = CASE WHEN ? = 'approved' THEN ? ELSE approved_by END
                WHERE user_id = ?
                """,
                (status, status, now, status, actor_user_id, user_id),
            )
            db.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (now, user_id),
            )
            self._insert_audit(
                db, actor_user_id, user_id, None, None,
                f"user.{status}", {},
            )
            result = db.execute(
                """
                SELECT user_id, email, full_name, role, status, created_at,
                       approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            return self._dict(result) or {}

    def update_user_role(
        self,
        user_id: str,
        role: str,
        actor_user_id: str,
    ) -> Dict[str, Any]:
        """Change a user's role with last-administrator protection."""
        if role not in ("user", "admin"):
            raise ValueError("Invalid account role.")

        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")

            row = db.execute(
                "SELECT role FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()

            if row is None:
                raise ValueError("User not found.")

            old_role = row["role"]

            if old_role == role:
                result = db.execute(
                    """
                    SELECT user_id, email, full_name, role, status,
                           created_at, approved_at, approved_by, last_login_at
                    FROM users WHERE user_id = ?
                    """,
                    (user_id,),
                ).fetchone()
                return self._dict(result) or {}

            if old_role == "admin" and role == "user":
                admin_count = db.execute(
                    "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
                ).fetchone()["n"]

                if int(admin_count) <= 1:
                    raise ValueError(
                        "The last administrator cannot be demoted."
                    )

            db.execute(
                "UPDATE users SET role = ? WHERE user_id = ?",
                (role, user_id),
            )

            # Role changes take effect after the account signs in again.
            db.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (now, user_id),
            )

            self._insert_audit(
                db,
                actor_user_id,
                user_id,
                None,
                None,
                "user.role_changed",
                {"old_role": old_role, "new_role": role},
            )

            result = db.execute(
                """
                SELECT user_id, email, full_name, role, status,
                       created_at, approved_at, approved_by, last_login_at
                FROM users WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            return self._dict(result) or {}

    def create_session(
        self,
        user_id: str,
        token_hash: str,
        csrf_hash: str,
        expires_at: float,
    ) -> None:
        now = time.time()
        with self._connection() as db:
            db.execute(
                """
                INSERT INTO sessions (
                    token_hash, csrf_hash, user_id,
                    created_at, expires_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_hash, csrf_hash, user_id, now, expires_at, now),
            )

    def get_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._connection() as db:
            row = db.execute(
                """
                SELECT s.token_hash, s.csrf_hash, s.user_id, s.expires_at,
                       u.email, u.full_name, u.role, u.status
                FROM sessions s
                JOIN users u ON u.user_id = s.user_id
                WHERE s.token_hash = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            if row is None or row["status"] != "approved":
                return None
            db.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (now, token_hash),
            )
            return dict(row)

    def revoke_session(self, token_hash: str) -> None:
        with self._connection() as db:
            db.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (time.time(), token_hash),
            )

    def revoke_user_sessions(self, user_id: str) -> None:
        with self._connection() as db:
            db.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (time.time(), user_id),
            )

    def update_last_login(self, user_id: str) -> None:
        with self._connection() as db:
            db.execute(
                "UPDATE users SET last_login_at = ? WHERE user_id = ?",
                (time.time(), user_id),
            )

    def record_login_attempt(
        self,
        email_key: str,
        ip_key: str,
        succeeded: bool,
        user_id: Optional[str] = None,
    ) -> None:
        now = time.time()
        with self._connection() as db:
            db.execute(
                """
                INSERT INTO login_attempts (
                    attempt_id, email_key, ip_key, succeeded, attempted_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex, email_key, ip_key,
                    int(succeeded), now,
                ),
            )
            self._insert_audit(
                db,
                user_id,
                user_id,
                None,
                None,
                "auth.login_succeeded" if succeeded else "auth.login_failed",
                {"email_key": email_key, "ip_key": ip_key},
            )
            db.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (now - 86400,),
            )

    def login_is_rate_limited(self, email_key: str, ip_key: str) -> bool:
        since = time.time() - 900
        with self._connection() as db:
            email_row = db.execute(
                """
                SELECT COUNT(*) AS n FROM login_attempts
                WHERE email_key = ? AND succeeded = 0 AND attempted_at >= ?
                """,
                (email_key, since),
            ).fetchone()
            ip_row = db.execute(
                """
                SELECT COUNT(*) AS n FROM login_attempts
                WHERE ip_key = ? AND succeeded = 0 AND attempted_at >= ?
                """,
                (ip_key, since),
            ).fetchone()
            return int(email_row["n"]) >= 8 or int(ip_row["n"]) >= 20

    def set_module_permission(
        self,
        user_id: str,
        module_name: str,
        enabled: bool,
        actor_user_id: str,
        daily_limit: Optional[int] = None,
        monthly_limit: Optional[int] = None,
    ) -> None:
        for limit in (daily_limit, monthly_limit):
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
            ):
                raise ValueError("Quota limits must be non-negative integers or null.")

        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone() is None:
                raise ValueError("User not found.")

            db.execute(
                """
                INSERT INTO module_permissions (
                    user_id, module_name, enabled, daily_limit,
                    monthly_limit, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, module_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    daily_limit = excluded.daily_limit,
                    monthly_limit = excluded.monthly_limit,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (
                    user_id, module_name, int(enabled), daily_limit,
                    monthly_limit, now, actor_user_id,
                ),
            )
            self._insert_audit(
                db, actor_user_id, user_id, None, module_name,
                "module.permission_changed",
                {
                    "enabled": bool(enabled),
                    "daily_limit": daily_limit,
                    "monthly_limit": monthly_limit,
                },
            )

    def get_module_permissions(self, user_id: str) -> List[Dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                """
                SELECT module_name, enabled, daily_limit, monthly_limit,
                       updated_at, updated_by
                FROM module_permissions
                WHERE user_id = ?
                ORDER BY module_name
                """,
                (user_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def record_investigation(
        self,
        job_id: str,
        user_id: str,
        target_type: str,
        target_display: str,
    ) -> None:
        now = time.time()
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO investigations (
                    job_id, user_id, target_type, target_display,
                    status, created_at
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (job_id, user_id, target_type, target_display, now),
            )
            self._insert_audit(
                db, user_id, user_id, job_id, None,
                "investigation.submitted",
                {"target_type": target_type, "target_display": target_display},
            )

    def finish_investigation(self, job_id: str, status: str) -> None:
        now = time.time()
        with self._connection() as db:
            row = db.execute(
                "SELECT user_id FROM investigations WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                return
            db.execute(
                """
                UPDATE investigations SET status = ?, finished_at = ?
                WHERE job_id = ?
                """,
                (status, now, job_id),
            )
            self._insert_audit(
                db, row["user_id"], row["user_id"], job_id, None,
                f"investigation.{status}", {},
            )

    def save_investigation_report(
        self,
        job_id: str,
        report: Dict[str, Any],
    ) -> None:
        """Persist a completed investigation report as JSON."""
        if not isinstance(report, dict):
            raise ValueError("Investigation report must be a JSON object.")

        report_json = json.dumps(
            report,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

        with self._connection() as db:
            cursor = db.execute(
                """
                UPDATE investigations
                SET report_json = ?
                WHERE job_id = ?
                """,
                (report_json, job_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Investigation record not found.")

    def get_investigation(
        self,
        job_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve investigation metadata and its saved report."""
        with self._connection() as db:
            row = db.execute(
                """
                SELECT job_id, user_id, target_type, target_display,
                       status, created_at, finished_at, report_json
                FROM investigations
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()

        if row is None:
            return None

        item = dict(row)
        raw_report = item.pop("report_json", None)
        report = None

        if raw_report:
            try:
                parsed = json.loads(raw_report)
                if isinstance(parsed, dict):
                    report = parsed
            except (TypeError, json.JSONDecodeError):
                report = None

        item["report"] = report
        item["report_available"] = report is not None
        return item

    def reserve_module_use(
        self,
        user_id: str,
        role: str,
        module_name: str,
        job_id: str,
        target_type: str,
    ) -> str:
        """Atomically authorize and charge one module execution attempt.

        Each module invocation counts once, including executions that later fail.
        This is an execution quota, not a count of individual provider HTTP calls.
        """
        now = time.time()
        usage_id = uuid.uuid4().hex

        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            user = db.execute(
                "SELECT status FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if user is None or user["status"] != "approved":
                raise AccessDenied("The account is not approved.")

            if role != "admin":
                permission = db.execute(
                    """
                    SELECT enabled, daily_limit, monthly_limit
                    FROM module_permissions
                    WHERE user_id = ? AND module_name = ?
                    """,
                    (user_id, module_name),
                ).fetchone()

                if permission is None or not permission["enabled"]:
                    raise AccessDenied(
                        f"Your account is not authorized to use {module_name}."
                    )

                day_count = db.execute(
                    """
                    SELECT COUNT(*) AS n FROM module_usage
                    WHERE user_id = ? AND module_name = ? AND created_at >= ?
                    """,
                    (user_id, module_name, utc_day_start(now)),
                ).fetchone()["n"]

                month_count = db.execute(
                    """
                    SELECT COUNT(*) AS n FROM module_usage
                    WHERE user_id = ? AND module_name = ? AND created_at >= ?
                    """,
                    (user_id, module_name, utc_month_start(now)),
                ).fetchone()["n"]

                if (
                    permission["daily_limit"] is not None
                    and int(day_count) >= permission["daily_limit"]
                ):
                    raise QuotaExceeded(
                        f"Daily limit reached for {module_name}."
                    )
                if (
                    permission["monthly_limit"] is not None
                    and int(month_count) >= permission["monthly_limit"]
                ):
                    raise QuotaExceeded(
                        f"Monthly limit reached for {module_name}."
                    )

            db.execute(
                """
                INSERT INTO module_usage (
                    usage_id, user_id, module_name, job_id,
                    target_type, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'running', ?)
                """,
                (usage_id, user_id, module_name, job_id, target_type, now),
            )
            self._insert_audit(
                db, user_id, user_id, job_id, module_name,
                "module.started", {},
            )

        return usage_id

    def finish_module_use(
        self,
        usage_id: str,
        status: str,
    ) -> None:
        allowed = {"success", "partial", "failed", "skipped", "error"}
        final_status = status if status in allowed else "error"
        now = time.time()

        with self._connection() as db:
            row = db.execute(
                """
                SELECT user_id, job_id, module_name
                FROM module_usage WHERE usage_id = ?
                """,
                (usage_id,),
            ).fetchone()
            if row is None:
                return
            db.execute(
                """
                UPDATE module_usage SET status = ?, finished_at = ?
                WHERE usage_id = ?
                """,
                (final_status, now, usage_id),
            )
            self._insert_audit(
                db, row["user_id"], row["user_id"], row["job_id"],
                row["module_name"], "module.finished",
                {"status": final_status},
            )

    def list_investigations(
        self,
        limit: int = 100,
        owner_user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List persistent investigations, optionally scoped to one user."""
        safe_limit = max(1, min(int(limit), 500))

        query = """
            SELECT i.job_id, i.user_id, u.email, u.full_name,
                   i.target_type, i.target_display, i.status,
                   i.created_at, i.finished_at,
                   CASE
                       WHEN i.report_json IS NOT NULL
                            AND length(i.report_json) > 0
                       THEN 1 ELSE 0
                   END AS report_available
            FROM investigations i
            JOIN users u ON u.user_id = i.user_id
        """
        params = []

        if owner_user_id is not None:
            query += " WHERE i.user_id = ?"
            params.append(owner_user_id)

        query += " ORDER BY i.created_at DESC LIMIT ?"
        params.append(safe_limit)

        with self._connection() as db:
            rows = db.execute(query, params).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["report_available"] = bool(item["report_available"])
            results.append(item)

        return results

    def get_admin_overview(self) -> Dict[str, Any]:
        """Return aggregate operational statistics for administrators."""
        now = time.time()
        since = now - 86400

        with self._connection() as db:
            users = db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved,
                    SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended,
                    SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
                    SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS administrators
                FROM users
                """
            ).fetchone()

            investigations = db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
                FROM investigations
                """
            ).fetchone()

            module_usage = db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status IN ('failed', 'error') THEN 1 ELSE 0 END) AS failed
                FROM module_usage
                WHERE created_at >= ?
                """,
                (since,),
            ).fetchone()

            login_attempts = db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN succeeded = 0 THEN 1 ELSE 0 END) AS failed,
                    SUM(CASE WHEN succeeded = 1 THEN 1 ELSE 0 END) AS succeeded
                FROM login_attempts
                WHERE attempted_at >= ?
                """,
                (since,),
            ).fetchone()

            sessions = db.execute(
                """
                SELECT COUNT(*) AS total
                FROM sessions
                WHERE revoked_at IS NULL AND expires_at > ?
                """,
                (now,),
            ).fetchone()

        def count(row, key):
            return int(row[key] or 0)

        return {
            "generated_at": now,
            "users": {
                key: count(users, key)
                for key in (
                    "total", "pending", "approved",
                    "suspended", "rejected", "administrators",
                )
            },
            "investigations": {
                key: count(investigations, key)
                for key in (
                    "total", "pending", "running",
                    "completed", "failed", "cancelled",
                )
            },
            "module_usage_24h": {
                "total": count(module_usage, "total"),
                "failed": count(module_usage, "failed"),
            },
            "login_attempts_24h": {
                "total": count(login_attempts, "total"),
                "failed": count(login_attempts, "failed"),
                "succeeded": count(login_attempts, "succeeded"),
            },
            "active_sessions": count(sessions, "total"),
        }

    def list_audit_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        with self._connection() as db:
            rows = db.execute(
                """
                SELECT a.event_id, a.actor_user_id, actor.email AS actor_email,
                       a.subject_user_id, subject.email AS subject_email,
                       a.job_id, a.module_name, a.event_type,
                       a.details_json, a.created_at
                FROM audit_events a
                LEFT JOIN users actor ON actor.user_id = a.actor_user_id
                LEFT JOIN users subject ON subject.user_id = a.subject_user_id
                ORDER BY a.created_at DESC LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    item["details"] = json.loads(item.pop("details_json") or "{}")
                except (TypeError, json.JSONDecodeError):
                    item["details"] = {}
                result.append(item)
            return result

    @staticmethod
    def _insert_audit(
        db: sqlite3.Connection,
        actor_user_id: Optional[str],
        subject_user_id: Optional[str],
        job_id: Optional[str],
        module_name: Optional[str],
        event_type: str,
        details: Dict[str, Any],
    ) -> None:
        db.execute(
            """
            INSERT INTO audit_events (
                event_id, actor_user_id, subject_user_id, job_id,
                module_name, event_type, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                actor_user_id,
                subject_user_id,
                job_id,
                module_name,
                event_type,
                json.dumps(details, ensure_ascii=False, separators=(",", ":")),
                time.time(),
            ),
        )


auth_store = AuthStore()
