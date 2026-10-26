"""Local authentication, authorization and immutable audit for logmask-web."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

ROLES = ("operator", "analyst", "reverser", "admin")
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "operator": frozenset({"anonymize"}),
    "analyst": frozenset({"anonymize", "reports"}),
    "reverser": frozenset({"anonymize", "reports", "reverse"}),
    "admin": frozenset({"anonymize", "reports", "reverse", "admin", "audit"}),
}
USERNAME_RX = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,63}$")
MIN_PASSWORD_LENGTH = 12

PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
_DUMMY_HASH = PH.hash("not-a-real-password-for-timing-equalization")


class AuthError(Exception):
    """Base authentication error."""


class InvalidCredentials(AuthError):
    pass


class RateLimited(AuthError):
    def __init__(self, retry_after: int):
        super().__init__("too many failed login attempts")
        self.retry_after = max(1, retry_after)


class PermissionDenied(AuthError):
    pass


class PasswordPolicyError(AuthError):
    pass


@dataclass(frozen=True)
class AuthUser:
    id: int
    username: str
    role: str
    active: bool
    must_change_password: bool
    tenants: frozenset[str]

    @property
    def permissions(self) -> frozenset[str]:
        return ROLE_PERMISSIONS[self.role]

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def can_access_tenant(self, tenant: str) -> bool:
        return self.role == "admin" or "*" in self.tenants or tenant in self.tenants


@dataclass(frozen=True)
class Session:
    token_hash: str
    csrf_hash: str
    user: AuthUser
    created_at: int
    last_seen: int
    expires_at: int


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK(role IN ('operator','analyst','reverser','admin')),
    active               INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_tenants (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant  TEXT NOT NULL,
    PRIMARY KEY(user_id, tenant)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip       TEXT NOT NULL,
    success  INTEGER NOT NULL,
    ts       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
    ON login_attempts(username, ip, success, ts);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    user_id  INTEGER,
    username TEXT,
    role     TEXT,
    tenant   TEXT,
    action   TEXT NOT NULL,
    success  INTEGER NOT NULL,
    ip       TEXT NOT NULL,
    details  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit(tenant, ts DESC);
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit rows are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit rows are immutable'); END;
"""


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_username(value: str) -> str:
    username = (value or "").strip().lower()
    if not USERNAME_RX.fullmatch(username):
        raise ValueError("username must be 3-64 lowercase letters, numbers or . _ @ -")
    return username


def validate_password(password: str, username: str | None = None) -> None:
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must contain at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > 1024:
        raise PasswordPolicyError("password is too long")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("password must not contain the username")


class AuthStore:
    def __init__(
        self,
        path: Path,
        *,
        session_idle_seconds: int = 1800,
        session_max_seconds: int = 28800,
        login_window_seconds: int = 900,
        login_max_failures: int = 5,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.session_idle_seconds = max(60, int(session_idle_seconds))
        self.session_max_seconds = max(self.session_idle_seconds, int(session_max_seconds))
        self.login_window_seconds = max(60, int(login_window_seconds))
        self.login_max_failures = max(1, int(login_max_failures))
        with self._db() as db:
            db.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def _db(self):
        db = self._connect()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def bootstrap_admin(
        self,
        username: str,
        password: str | None,
        bootstrap_file: Path,
    ) -> tuple[str, str | None]:
        """Create the first admin. Returns (username, generated_password_or_none)."""
        with self._db() as db:
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                return normalize_username(username), None

        username = normalize_username(username)
        generated = None
        if not password:
            generated = secrets.token_urlsafe(24)
            password = generated
        validate_password(password, username)
        self.create_user(
            username=username,
            password=password,
            role="admin",
            tenants=["*"],
            must_change_password=True,
        )
        if generated:
            bootstrap_file.parent.mkdir(parents=True, exist_ok=True)
            bootstrap_file.write_text(
                "LogMask bootstrap credentials\n"
                f"username={username}\n"
                f"password={generated}\n"
                "Delete this file after changing the password.\n",
                encoding="utf-8",
            )
            try:
                os.chmod(bootstrap_file, 0o600)
            except OSError:
                pass
        return username, generated

    def create_user(
        self,
        *,
        username: str,
        password: str,
        role: str,
        tenants: Iterable[str],
        active: bool = True,
        must_change_password: bool = True,
    ) -> int:
        username = normalize_username(username)
        if role not in ROLES:
            raise ValueError("invalid role")
        validate_password(password, username)
        tenant_set = sorted(set(tenants))
        if role == "admin":
            tenant_set = ["*"]
        elif "*" in tenant_set:
            raise ValueError("wildcard tenant is reserved for administrators")
        if not tenant_set and role != "admin":
            raise ValueError("at least one tenant is required")
        now = int(time.time())
        with self._db() as db:
            cur = db.execute(
                """INSERT INTO users(username,password_hash,role,active,must_change_password,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    username,
                    PH.hash(password),
                    role,
                    int(active),
                    int(must_change_password),
                    now,
                    now,
                ),
            )
            user_id = int(cur.lastrowid)
            db.executemany(
                "INSERT INTO user_tenants(user_id,tenant) VALUES(?,?)",
                [(user_id, tenant) for tenant in tenant_set],
            )
            return user_id

    def _user_from_row(self, db: sqlite3.Connection, row: sqlite3.Row) -> AuthUser:
        tenants = frozenset(
            r[0] for r in db.execute(
                "SELECT tenant FROM user_tenants WHERE user_id=? ORDER BY tenant", (row["id"],)
            ).fetchall()
        )
        return AuthUser(
            id=int(row["id"]),
            username=str(row["username"]),
            role=str(row["role"]),
            active=bool(row["active"]),
            must_change_password=bool(row["must_change_password"]),
            tenants=tenants,
        )

    def get_user(self, username: str) -> AuthUser | None:
        try:
            username = normalize_username(username)
        except ValueError:
            return None
        with self._db() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            return self._user_from_row(db, row) if row else None

    def authenticate(self, username: str, password: str, ip: str) -> tuple[str, str, AuthUser]:
        try:
            username = normalize_username(username)
        except ValueError:
            username = (username or "")[:64].lower()
        now = int(time.time())
        cutoff = now - self.login_window_seconds
        with self._db() as db:
            db.execute("DELETE FROM login_attempts WHERE ts < ?", (now - 86400,))
            failures = db.execute(
                """SELECT COUNT(*) FROM login_attempts
                   WHERE username=? AND ip=? AND success=0 AND ts>=?""",
                (username, ip, cutoff),
            ).fetchone()[0]
            if failures >= self.login_max_failures:
                oldest = db.execute(
                    """SELECT MIN(ts) FROM login_attempts
                       WHERE username=? AND ip=? AND success=0 AND ts>=?""",
                    (username, ip, cutoff),
                ).fetchone()[0]
                raise RateLimited(int(oldest + self.login_window_seconds - now))

            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            password_hash = row["password_hash"] if row else _DUMMY_HASH
            valid = False
            try:
                valid = PH.verify(password_hash, password or "")
            except (VerifyMismatchError, InvalidHashError):
                valid = False
            if not row or not valid or not bool(row["active"]):
                db.execute(
                    "INSERT INTO login_attempts(username,ip,success,ts) VALUES(?,?,0,?)",
                    (username, ip, now),
                )
                db.commit()
                raise InvalidCredentials("invalid username or password")

            if PH.check_needs_rehash(password_hash):
                db.execute(
                    "UPDATE users SET password_hash=?,updated_at=? WHERE id=?",
                    (PH.hash(password), now, row["id"]),
                )
            db.execute(
                "INSERT INTO login_attempts(username,ip,success,ts) VALUES(?,?,1,?)",
                (username, ip, now),
            )
            db.execute(
                "DELETE FROM login_attempts WHERE username=? AND ip=? AND success=0",
                (username, ip),
            )
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(24)
            token_hash = _hash_token(token)
            csrf_hash = _hash_token(csrf)
            expires_at = now + self.session_max_seconds
            db.execute(
                """INSERT INTO sessions(token_hash,user_id,csrf_hash,created_at,last_seen,expires_at,revoked)
                   VALUES(?,?,?,?,?,?,0)""",
                (token_hash, row["id"], csrf_hash, now, now, expires_at),
            )
            user = self._user_from_row(db, row)
            return token, csrf, user

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        token_hash = _hash_token(token)
        now = int(time.time())
        with self._db() as db:
            row = db.execute(
                """SELECT s.*,u.username,u.role,u.active,u.must_change_password,u.created_at AS u_created,
                          u.updated_at AS u_updated,u.password_hash
                   FROM sessions s JOIN users u ON u.id=s.user_id
                   WHERE s.token_hash=?""",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            expired = (
                bool(row["revoked"])
                or not bool(row["active"])
                or now >= int(row["expires_at"])
                or now - int(row["last_seen"]) > self.session_idle_seconds
            )
            if expired:
                db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (token_hash,))
                return None
            if now - int(row["last_seen"]) >= 60:
                db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))
            user_row = {
                "id": row["user_id"],
                "username": row["username"],
                "role": row["role"],
                "active": row["active"],
                "must_change_password": row["must_change_password"],
            }
            # sqlite.Row cannot be instantiated; fetch tenant set directly.
            tenants = frozenset(
                r[0] for r in db.execute(
                    "SELECT tenant FROM user_tenants WHERE user_id=? ORDER BY tenant",
                    (row["user_id"],),
                ).fetchall()
            )
            user = AuthUser(
                id=int(user_row["id"]),
                username=str(user_row["username"]),
                role=str(user_row["role"]),
                active=bool(user_row["active"]),
                must_change_password=bool(user_row["must_change_password"]),
                tenants=tenants,
            )
            return Session(
                token_hash=token_hash,
                csrf_hash=str(row["csrf_hash"]),
                user=user,
                created_at=int(row["created_at"]),
                last_seen=int(row["last_seen"]),
                expires_at=int(row["expires_at"]),
            )

    def verify_csrf(self, session: Session, supplied: str | None) -> bool:
        if not supplied:
            return False
        return hmac.compare_digest(session.csrf_hash, _hash_token(supplied))

    def revoke_session(self, token: str | None) -> None:
        if not token:
            return
        with self._db() as db:
            db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (_hash_token(token),))

    def revoke_user_sessions(self, user_id: int, except_token_hash: str | None = None) -> None:
        with self._db() as db:
            if except_token_hash:
                db.execute(
                    "UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash<>?",
                    (user_id, except_token_hash),
                )
            else:
                db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))

    def change_password(
        self,
        user: AuthUser,
        current_password: str,
        new_password: str,
        current_session_hash: str,
    ) -> None:
        validate_password(new_password, user.username)
        now = int(time.time())
        with self._db() as db:
            row = db.execute("SELECT password_hash FROM users WHERE id=?", (user.id,)).fetchone()
            if not row:
                raise InvalidCredentials("user not found")
            try:
                PH.verify(row["password_hash"], current_password or "")
            except (VerifyMismatchError, InvalidHashError) as exc:
                raise InvalidCredentials("current password is incorrect") from exc
            db.execute(
                """UPDATE users SET password_hash=?,must_change_password=0,updated_at=? WHERE id=?""",
                (PH.hash(new_password), now, user.id),
            )
            db.execute(
                "UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash<>?",
                (user.id, current_session_hash),
            )

    def list_users(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT id,username,role,active,must_change_password,created_at,updated_at FROM users ORDER BY username"
            ).fetchall()
            out = []
            for row in rows:
                tenants = [
                    r[0] for r in db.execute(
                        "SELECT tenant FROM user_tenants WHERE user_id=? ORDER BY tenant", (row["id"],)
                    ).fetchall()
                ]
                out.append(
                    {
                        "id": int(row["id"]),
                        "username": row["username"],
                        "role": row["role"],
                        "active": bool(row["active"]),
                        "must_change_password": bool(row["must_change_password"]),
                        "tenants": tenants,
                        "created_at": int(row["created_at"]),
                        "updated_at": int(row["updated_at"]),
                    }
                )
            return out

    def update_user(
        self,
        user_id: int,
        *,
        role: str | None = None,
        tenants: Iterable[str] | None = None,
        active: bool | None = None,
        reset_password: str | None = None,
    ) -> None:
        now = int(time.time())
        with self._db() as db:
            row = db.execute("SELECT username,role FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                raise ValueError("user not found")
            new_role = role or row["role"]
            if new_role not in ROLES:
                raise ValueError("invalid role")
            if row["role"] == "admin" and new_role != "admin" and tenants is None:
                raise ValueError("tenants are required when demoting an administrator")
            updates = ["role=?", "updated_at=?"]
            args: list[object] = [new_role, now]
            if active is not None:
                updates.append("active=?")
                args.append(int(active))
            if reset_password is not None:
                validate_password(reset_password, row["username"])
                updates.extend(["password_hash=?", "must_change_password=1"])
                args.append(PH.hash(reset_password))
            args.append(user_id)
            db.execute(f"UPDATE users SET {','.join(updates)} WHERE id=?", args)
            if tenants is not None or new_role == "admin":
                tenant_set = ["*"] if new_role == "admin" else sorted(set(tenants or []))
                if not tenant_set:
                    raise ValueError("at least one tenant is required")
                if "*" in tenant_set and new_role != "admin":
                    raise ValueError("wildcard tenant is reserved for administrators")
                db.execute("DELETE FROM user_tenants WHERE user_id=?", (user_id,))
                db.executemany(
                    "INSERT INTO user_tenants(user_id,tenant) VALUES(?,?)",
                    [(user_id, tenant) for tenant in tenant_set],
                )
            db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))

    def audit(
        self,
        *,
        action: str,
        success: bool,
        ip: str,
        user: AuthUser | None = None,
        username: str | None = None,
        tenant: str | None = None,
        details: dict | None = None,
    ) -> None:
        safe_details = json.dumps(details or {}, separators=(",", ":"), ensure_ascii=False)
        if len(safe_details) > 4096:
            safe_details = safe_details[:4096]
        with self._db() as db:
            db.execute(
                """INSERT INTO audit(ts,user_id,username,role,tenant,action,success,ip,details)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    int(time.time()),
                    user.id if user else None,
                    user.username if user else username,
                    user.role if user else None,
                    tenant,
                    action,
                    int(success),
                    ip,
                    safe_details,
                ),
            )

    def list_audit(self, *, limit: int = 200, tenant: str | None = None) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._db() as db:
            if tenant:
                rows = db.execute(
                    "SELECT * FROM audit WHERE tenant=? ORDER BY id DESC LIMIT ?", (tenant, limit)
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "ts": int(r["ts"]),
                    "username": r["username"],
                    "role": r["role"],
                    "tenant": r["tenant"],
                    "action": r["action"],
                    "success": bool(r["success"]),
                    "ip": r["ip"],
                    "details": json.loads(r["details"] or "{}"),
                }
                for r in rows
            ]
