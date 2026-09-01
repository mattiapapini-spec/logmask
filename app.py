"""logmask-web — authenticated, tenant-isolated pseudonymization service."""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from starlette.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from auth import (
    ROLES,
    AuthStore,
    AuthUser,
    InvalidCredentials,
    PasswordPolicyError,
    PermissionDenied,
    RateLimited,
    Session,
)
import logmask
import pdf_anon
import pst_anon
import docx_anon
from logmask import (
    LEGACY_TENANT,
    ORDER,
    Anonymizer,
    CsvAnonymizer,
    Deanonymizer,
    csv_deanonymize,
    Options,
    Vault,
    apply_safe_policy,
    default_policy,
    derive_tenant_master,
    detect_family,
    is_safe_column,
    normalize_tenant_id,
    read_samples,
    NO_ELISION_DLP_POLICY,
    PseudonymSpaceExhausted,
    pseudonymize_residuals,
    redact_residuals,
    scan_sensitive_residuals,
    sweep_known,
    tenant_vault_path,
)
import vendor_kits
from vendor_kits import canonical_kit_id, detect_vendor_kit, kit_info, kit_metadata, reload_kits_if_changed
from dlp import dlp_metadata, normalize_dlp_policy
from workflows import workflow_profiles, workflow_profile

from structured import (
    STRUCTURED_FORMATS,
    anonymize_structured,
    deanonymize_structured,
    detect_structured_format,
    transpose_keyvalue_csv,
)

VERSION = "0.27.6"
DATA = Path(os.environ.get("LOGMASK_DATA", "./data"))
KEY_PATH = Path(os.environ.get("LOGMASK_KEY_FILE", str(DATA / "master.key")))
VAULT_PATH = DATA / "vault.db"  # reserved for the pre-v0.3 `legacy` tenant
TENANTS_DIR = DATA / "tenants"
AUTH_PATH = DATA / "auth.db"
BOOTSTRAP_FILE = DATA / "bootstrap-admin.txt"
SESSION_COOKIE = "logmask_session"
CSRF_COOKIE = "logmask_csrf"
COOKIE_SECURE = os.environ.get("LOGMASK_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
MAX_BODY_BYTES = int(os.environ.get("LOGMASK_MAX_BODY_BYTES", str(12 * 1024 * 1024)))
MAX_FILE_BYTES = int(os.environ.get("LOGMASK_MAX_FILE_BYTES", str(8 * 1024 * 1024)))
# Customer-name denylist: always elided from free text (v0.10.7).
# Sources: LOGMASK_CLIENT_TERMS (comma-separated) and/or a one-name-per-line
# file (default data/client_terms.txt). Kept out of the shipped sources.
CLIENT_TERMS_FILE = Path(os.environ.get("LOGMASK_CLIENT_TERMS_FILE", str(DATA / "client_terms.txt")))
_CLIENT_TERMS_CACHE: tuple[float, tuple[str, ...]] = (-1.0, ())
LOCK = threading.Lock()


def load_client_terms() -> tuple[str, ...]:
    global _CLIENT_TERMS_CACHE
    env_terms = tuple(
        term.strip() for term in os.environ.get("LOGMASK_CLIENT_TERMS", "").split(",") if term.strip()
    )
    try:
        mtime = CLIENT_TERMS_FILE.stat().st_mtime
    except OSError:
        return env_terms
    if _CLIENT_TERMS_CACHE[0] != mtime:
        try:
            lines = CLIENT_TERMS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        file_terms = tuple(
            line.strip() for line in lines if line.strip() and not line.strip().startswith("#")
        )
        _CLIENT_TERMS_CACHE = (mtime, file_terms)
    return tuple(dict.fromkeys(env_terms + _CLIENT_TERMS_CACHE[1]))


# Public CIDR ranges owned by the tenant (egress/NAT): masked even when
# ip_mode=internal, because they identify the organization (v0.10.9).
TENANT_NETWORKS_FILE = Path(os.environ.get("LOGMASK_TENANT_NETWORKS_FILE", str(DATA / "tenant_networks.txt")))
_TENANT_NETWORKS_CACHE: tuple[float, tuple[str, ...]] = (-1.0, ())


def load_tenant_networks() -> tuple[str, ...]:
    global _TENANT_NETWORKS_CACHE
    env_nets = tuple(
        net.strip() for net in os.environ.get("LOGMASK_TENANT_NETWORKS", "").split(",") if net.strip()
    )
    try:
        mtime = TENANT_NETWORKS_FILE.stat().st_mtime
    except OSError:
        return env_nets
    if _TENANT_NETWORKS_CACHE[0] != mtime:
        try:
            lines = TENANT_NETWORKS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        file_nets = tuple(
            line.strip() for line in lines if line.strip() and not line.strip().startswith("#")
        )
        _TENANT_NETWORKS_CACHE = (mtime, file_nets)
    return tuple(dict.fromkeys(env_nets + _TENANT_NETWORKS_CACHE[1]))


# Hostname naming conventions ("srv-*", literal names): bare machine names in
# pasted tables are masked reversibly (v0.10.9).
HOST_TERMS_FILE = Path(os.environ.get("LOGMASK_HOST_TERMS_FILE", str(DATA / "host_terms.txt")))
_HOST_TERMS_CACHE: tuple[float, tuple[str, ...]] = (-1.0, ())


def load_host_terms() -> tuple[str, ...]:
    global _HOST_TERMS_CACHE
    env_terms = tuple(
        term.strip() for term in os.environ.get("LOGMASK_HOST_TERMS", "").split(",") if term.strip()
    )
    try:
        mtime = HOST_TERMS_FILE.stat().st_mtime
    except OSError:
        return env_terms
    if _HOST_TERMS_CACHE[0] != mtime:
        try:
            lines = HOST_TERMS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        file_terms = tuple(
            line.strip() for line in lines if line.strip() and not line.strip().startswith("#")
        )
        _HOST_TERMS_CACHE = (mtime, file_terms)
    return tuple(dict.fromkeys(env_terms + _HOST_TERMS_CACHE[1]))


KEEP_FIELDS_FILE = Path(os.environ.get("LOGMASK_KEEP_FIELDS_FILE", str(DATA / "keep_fields.txt")))
_KEEP_FIELDS_CACHE: tuple[float, frozenset[str]] = (-1.0, frozenset())


_PERSON_TERMS_CACHE: tuple = (None, ())
PERSON_TERMS_FILE = Path(os.environ.get("LOGMASK_PERSON_TERMS_FILE",
                                        str(DATA / "person_terms.txt")))


def load_person_terms() -> tuple[str, ...]:
    """v0.22.0: persone realmente esistenti nel tenant (data/person_terms.txt).
    Solo questi vengono mascherati anche come token singolo."""
    global _PERSON_TERMS_CACHE
    env_terms = tuple(
        term.strip() for term in os.environ.get("LOGMASK_PERSON_TERMS", "").split(",")
        if term.strip()
    )
    try:
        mtime = PERSON_TERMS_FILE.stat().st_mtime
    except OSError:
        return env_terms
    if _PERSON_TERMS_CACHE[0] != mtime:
        try:
            lines = PERSON_TERMS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        file_terms = tuple(
            line.strip() for line in lines if line.strip() and not line.strip().startswith("#")
        )
        _PERSON_TERMS_CACHE = (mtime, file_terms)
    return tuple(dict.fromkeys(env_terms + _PERSON_TERMS_CACHE[1]))


FIELD_OVERRIDES_FILE = Path(os.environ.get(
    "LOGMASK_FIELD_OVERRIDES_FILE", str(DATA / "field_overrides.json")))
_FIELD_OVERRIDES_CACHE: tuple = (None, {})


def _norm_field(name: str) -> str:
    return re.sub(r"\s+", "_", str(name).strip().lower())


def load_field_overrides() -> dict:
    """Override per campo (nome normalizzato -> {action, kind}). File JSON
    ricaricato a caldo, come gli altri config."""
    global _FIELD_OVERRIDES_CACHE
    try:
        mtime = FIELD_OVERRIDES_FILE.stat().st_mtime
    except OSError:
        return {}
    if _FIELD_OVERRIDES_CACHE[0] != mtime:
        try:
            raw = json.loads(FIELD_OVERRIDES_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        clean = {}
        for name, spec in (raw or {}).items():
            if not isinstance(spec, dict):
                continue
            action = str(spec.get("action", "")).strip().lower()
            if action not in logmask.OVERRIDE_ACTIONS:
                continue
            # v0.27.1: mask -> sempre opaque (vedi resolve_field). Nessun kind
            # tipizzato per gli override: eviterebbe il mascheramento su valori
            # non conformi.
            kind = "opaque" if action == "mask" else None
            clean[_norm_field(name)] = {"action": action, "kind": kind}
        _FIELD_OVERRIDES_CACHE = (mtime, clean)
    return dict(_FIELD_OVERRIDES_CACHE[1])


def save_field_overrides(updates: dict) -> dict:
    """Fonde gli update negli override esistenti e persiste. Ritorna la mappa
    completa. Un valore action='' o None rimuove l'override del campo."""
    global _FIELD_OVERRIDES_CACHE
    current = {}
    try:
        current = json.loads(FIELD_OVERRIDES_FILE.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        current = {}
    if not isinstance(current, dict):
        current = {}
    for name, spec in (updates or {}).items():
        key = _norm_field(name)
        if not key:
            continue
        action = str((spec or {}).get("action", "")).strip().lower()
        if action in ("", "auto", "none"):
            current.pop(key, None)
            continue
        if action not in logmask.OVERRIDE_ACTIONS:
            raise ValueError(f"azione non valida per '{name}': {action}")
        current[key] = {"action": action, "kind": "opaque" if action == "mask" else None}
    FIELD_OVERRIDES_FILE.parent.mkdir(parents=True, exist_ok=True)
    FIELD_OVERRIDES_FILE.write_text(
        json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    _FIELD_OVERRIDES_CACHE = (None, {})   # forza reload al prossimo load
    return current


def load_keep_fields() -> set[str]:
    global _KEEP_FIELDS_CACHE
    def _norm(name: str) -> str:
        return re.sub(r"\s+", "_", name.strip().lower())
    env_fields = {_norm(f) for f in os.environ.get("LOGMASK_KEEP_FIELDS", "").split(",") if f.strip()}
    try:
        mtime = KEEP_FIELDS_FILE.stat().st_mtime
    except OSError:
        return env_fields
    if _KEEP_FIELDS_CACHE[0] != mtime:
        try:
            lines = KEEP_FIELDS_FILE.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        file_fields = frozenset(
            _norm(line) for line in lines if line.strip() and not line.strip().startswith("#")
        )
        _KEEP_FIELDS_CACHE = (mtime, file_fields)
    return env_fields | set(_KEEP_FIELDS_CACHE[1])

app = FastAPI(title="logmask", version=VERSION, docs_url=None, redoc_url=None)


def _master() -> bytes:
    DATA.mkdir(parents=True, exist_ok=True)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        KEY_PATH.write_text(base64.b64encode(os.urandom(32)).decode(), encoding="utf-8")
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
    raw = base64.b64decode(KEY_PATH.read_text(encoding="utf-8").strip())
    if len(raw) != 32:
        raise RuntimeError(f"invalid master key at {KEY_PATH}")
    return raw


MASTER = _master()
AUTH = AuthStore(
    AUTH_PATH,
    session_idle_seconds=int(os.environ.get("LOGMASK_SESSION_IDLE_SECONDS", "1800")),
    session_max_seconds=int(os.environ.get("LOGMASK_SESSION_MAX_SECONDS", "28800")),
    login_window_seconds=int(os.environ.get("LOGMASK_LOGIN_WINDOW_SECONDS", "900")),
    login_max_failures=int(os.environ.get("LOGMASK_LOGIN_MAX_FAILURES", "5")),
)
AUTH.bootstrap_admin(
    os.environ.get("LOGMASK_ADMIN_USER", "admin"),
    os.environ.get("LOGMASK_ADMIN_PASSWORD") or None,
    BOOTSTRAP_FILE,
)


@app.exception_handler(PseudonymSpaceExhausted)
async def pseudonym_space_json(request: Request, exc: PseudonymSpaceExhausted):
    """v0.23.4: lo spazio pseudonimi esaurito non e' un guasto del server ma un
    limite raggiunto, e ha una via d'uscita precisa. Merita il proprio
    messaggio, non un generico "errore interno (RuntimeError)"."""
    return JSONResponse({"detail": str(exc), "error_type": "PseudonymSpaceExhausted"},
                        status_code=422)


@app.exception_handler(Exception)
async def unhandled_error_json(request: Request, exc: Exception):
    """v0.23.3: un errore non previsto usciva come TESTO semplice ("Internal
    Server Error"). Il browser non riusciva a interpretarlo e la pagina
    mostrava soltanto "risposta non valida dal backend": nessuna diagnosi, per
    l'utente e per chi legge la segnalazione. Ora ogni errore esce in JSON e
    porta almeno il tipo dell'eccezione; la traccia completa resta nei log del
    container, dove sta bene. Starlette rilancia comunque l'eccezione dopo
    questo handler, quindi il log non si perde.
    """
    return JSONResponse(
        {"detail": f"Errore interno del server ({type(exc).__name__}). "
                   f"La traccia completa e' nei log: docker compose logs logmask",
         "error_type": type(exc).__name__},
        status_code=500,
    )


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse({"error": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"error": "invalid content-length"}, status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------- auth helpers


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _session_from_request(request: Request) -> Session:
    session = AUTH.session(request.cookies.get(SESSION_COOKIE))
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    request.state.auth_session = session
    return session


def _csrf_session(request: Request, session: Session = Depends(_session_from_request)) -> Session:
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        supplied = request.headers.get("x-csrf-token")
        if not AUTH.verify_csrf(session, supplied):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")
    return session


def require(permission: str, *, csrf: bool = False) -> Callable:
    dependency = _csrf_session if csrf else _session_from_request

    def checker(session: Session = Depends(dependency)) -> Session:
        if session.user.must_change_password:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="password change required",
            )
        if not session.user.has_permission(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
        return session

    return checker


def _authorize_tenant(raw_tenant: str, user: AuthUser) -> str:
    try:
        tenant = normalize_tenant_id(raw_tenant)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid tenant: {exc}") from exc
    if not user.can_access_tenant(tenant):
        raise HTTPException(status_code=403, detail="tenant access denied")
    return tenant


def _set_session_cookies(response: Response, token: str, csrf: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=AUTH.session_max_seconds,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=AUTH.session_max_seconds,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


# --------------------------------------------------------------- tenant/vault


def _tenant_context(tenant: str) -> tuple[str, Path, bytes]:
    path = tenant_vault_path(VAULT_PATH, tenant)
    key = derive_tenant_master(MASTER, tenant)
    return tenant, path, key


def _open_tenant_vault(tenant: str) -> tuple[str, Path, Vault]:
    tenant, path, key = _tenant_context(tenant)
    return tenant, path, Vault(path, key)


def _all_vault_files() -> list[Path]:
    """Tutti i file vault esistenti: legacy (data/vault.db) e per tenant
    (data/tenants/<t>/vault.db)."""
    files: list[Path] = []
    if VAULT_PATH.exists():
        files.append(VAULT_PATH)
    if TENANTS_DIR.exists():
        for entry in TENANTS_DIR.iterdir():
            v = entry / VAULT_PATH.name
            if entry.is_dir() and v.exists():
                files.append(v)
    return files


def _known_tenants() -> list[str]:
    tenants: set[str] = set()
    if VAULT_PATH.exists():
        tenants.add(LEGACY_TENANT)
    if TENANTS_DIR.exists():
        for entry in TENANTS_DIR.iterdir():
            if not entry.is_dir() or not (entry / VAULT_PATH.name).exists():
                continue
            try:
                tenants.add(normalize_tenant_id(entry.name))
            except ValueError:
                continue
    return sorted(tenants)


# --------------------------------------------------------------- detection


def looks_like_csv(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()][:20]
    if len(lines) < 2:
        return False
    for delim in (",", ";", "\t", "|"):
        n = lines[0].count(delim)
        if n < 2:
            continue
        try:
            rows = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=delim))
        except csv.Error:
            continue
        width = len(rows[0])
        if width >= 3 and sum(1 for r in rows if len(r) == width) >= max(2, int(len(rows) * 0.8)):
            return True
    return False


# ----------------------------------------------------------- vendor coverage


def _looks_delimiter_collapsed(columns: list[str], samples: dict[str, list[str]]) -> bool:
    """Detect a TSV whose tabs were lost (e.g. pasted from a rendered table).
    The delimiter sniffer then finds nothing and returns the whole header as a
    single column. The columns cannot be recovered because the field names
    themselves contain spaces, so we fail loudly instead of silently
    mishandling the row (a keep-classified mega-column would pass data in clear)."""
    if len(columns) != 1:
        return False
    return len(str(columns[0]).split()) >= 8


def _requested_catalog(value: str | None) -> str | None:
    if value is None or not value.strip() or value.strip().lower() == "auto":
        return None
    canonical = canonical_kit_id(value)
    if not canonical:
        raise HTTPException(status_code=400, detail=f"unknown vendor kit: {value}")
    return canonical


def _coverage_payload(fields: list[dict], catalog: str | None) -> dict:
    populated = [field for field in fields if int(field.get("nonempty", 0)) > 0]
    vendor_prefix = f"vendor:{catalog}" if catalog else None
    vendor_fields = [
        field for field in populated
        if str(field.get("inferred_by") or "").startswith("vendor:")
        and (not vendor_prefix or field.get("inferred_by") == vendor_prefix or catalog == "elastic_ecs")
    ]
    classified = [
        field for field in populated
        if field.get("inferred_by") not in {"", "safe", None}
        or field.get("safe_keep")
    ]
    unknown = [
        str(field.get("column")) for field in populated
        if field.get("action") == "redact"
        or field.get("inferred_by") in {"", "safe", None}
        and not field.get("safe_keep")
    ]
    total = len(populated)
    return {
        "total_fields": total,
        "vendor_fields": len(vendor_fields),
        "classified_fields": len(classified),
        "vendor_percent": round(100 * len(vendor_fields) / total, 1) if total else 100.0,
        "classified_percent": round(100 * len(classified) / total, 1) if total else 100.0,
        "unknown_fields": sorted(dict.fromkeys(unknown))[:100],
        "unknown_total": len(set(unknown)),
    }


# ------------------------------------------------------------------ models


class LoginReq(BaseModel):
    username: str
    password: str


class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str


class AnonReq(BaseModel):
    tenant: str
    text: str
    format: Literal["auto", "text", "csv", "json", "ndjson", "syslog", "cef", "leef"] = "auto"
    preserve_subnet: bool = True
    ip_mode: Literal["none", "internal", "all"] = "all"
    url_mode: Literal["none", "internal", "all"] = "all"
    mask_tenant_networks: bool = True
    safe_mode: bool = True
    source: str = Field(default="paste", max_length=64)
    catalog: str | None = None
    workflow_profile: str | None = Field(default=None, max_length=64)
    dlp_policy: dict[str, Literal["pseudonymize", "redact", "block", "keep"]] = Field(default_factory=dict)


class DeanonReq(BaseModel):
    tenant: str
    text: str
    format: Literal["auto", "text", "csv", "json", "ndjson", "syslog", "cef", "leef"] = "auto"
    source: str = Field(default="paste", max_length=64)


class KitDryRunReq(BaseModel):
    columns: list[str] = Field(default_factory=list, max_length=4000)
    family: str | None = Field(default=None, max_length=64)
    safe_mode: bool = True


class KitFileReq(BaseModel):
    content: str = Field(max_length=262144)


class VaultResetReq(BaseModel):
    tenant: str
    confirm: str          # deve ripetere il nome del tenant


class FieldOverrideReq(BaseModel):
    # nome campo -> {"action": "keep"|"mask"|"redact"|"", "kind": <opzionale>}
    overrides: dict[str, dict] = Field(default_factory=dict, max_length=2000)


SECRET_RESET_PHRASE = "RESET"


class SecretResetReq(BaseModel):
    confirm: str          # deve valere esattamente SECRET_RESET_PHRASE


class CreateUserReq(BaseModel):
    username: str
    password: str
    role: Literal["operator", "analyst", "reverser", "admin"]
    tenants: list[str] = Field(default_factory=list)


class UpdateUserReq(BaseModel):
    role: Literal["operator", "analyst", "reverser", "admin"] | None = None
    tenants: list[str] | None = None
    active: bool | None = None
    reset_password: str | None = None


# --------------------------------------------------------------- auth endpoints


@app.post("/api/login")
def api_login(req: LoginReq, request: Request):
    ip = _client_ip(request)
    try:
        token, csrf, user = AUTH.authenticate(req.username, req.password, ip)
    except RateLimited as exc:
        AUTH.audit(action="login", success=False, ip=ip, username=req.username[:64].lower(), details={"reason": "rate_limited"})
        response = JSONResponse({"error": "too many failed attempts"}, status_code=429)
        response.headers["Retry-After"] = str(exc.retry_after)
        return response
    except InvalidCredentials:
        AUTH.audit(action="login", success=False, ip=ip, username=req.username[:64].lower(), details={"reason": "invalid_credentials"})
        return JSONResponse({"error": "invalid username or password"}, status_code=401)

    AUTH.audit(action="login", success=True, ip=ip, user=user)
    response = JSONResponse(
        {
            "username": user.username,
            "role": user.role,
            "permissions": sorted(user.permissions),
            "tenants": sorted(user.tenants),
            "must_change_password": user.must_change_password,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_body_bytes": MAX_BODY_BYTES,
            "pst_available": pst_anon.readpst_available(),
        "pdf_available": pdf_anon.available(),
        }
    )
    _set_session_cookies(response, token, csrf)
    return response


@app.get("/api/me")
def api_me(session: Session = Depends(_session_from_request)):
    user = session.user
    return {
        "username": user.username,
        "role": user.role,
        "permissions": sorted(user.permissions),
        "tenants": sorted(user.tenants),
        "must_change_password": user.must_change_password,
        "expires_at": session.expires_at,
        "max_file_bytes": MAX_FILE_BYTES,
        "max_body_bytes": MAX_BODY_BYTES,
        "pst_available": pst_anon.readpst_available(),
        "pdf_available": pdf_anon.available(),
    }


@app.post("/api/logout")
def api_logout(request: Request, session: Session = Depends(_csrf_session)):
    AUTH.revoke_session(request.cookies.get(SESSION_COOKIE))
    AUTH.audit(action="logout", success=True, ip=_client_ip(request), user=session.user)
    response = JSONResponse({"ok": True})
    _clear_session_cookies(response)
    return response


@app.post("/api/change-password")
def api_change_password(
    req: ChangePasswordReq,
    request: Request,
    session: Session = Depends(_csrf_session),
):
    try:
        AUTH.change_password(
            session.user,
            req.current_password,
            req.new_password,
            session.token_hash,
        )
    except (InvalidCredentials, PasswordPolicyError) as exc:
        AUTH.audit(
            action="change_password",
            success=False,
            ip=_client_ip(request),
            user=session.user,
            details={"reason": str(exc)},
        )
        return JSONResponse({"error": str(exc)}, status_code=400)
    BOOTSTRAP_FILE.unlink(missing_ok=True)
    AUTH.audit(action="change_password", success=True, ip=_client_ip(request), user=session.user)
    return {"ok": True}


# --------------------------------------------------------------- operational endpoints


def _enforce_upload_size(text: str, source: str) -> None:
    if source.startswith("upload:") and len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="uploaded file exceeds configured limit")


@app.get("/api/vendor-kits")
def api_vendor_kits(session: Session = Depends(_session_from_request)):
    reload_kits_if_changed()
    return {"kits": kit_metadata()}


@app.post("/api/kit-dry-run")
def api_kit_dry_run(
    req: KitDryRunReq,
    session: Session = Depends(require("anonymize", csrf=True)),
):
    """Classify a header against the kits WITHOUT masking any data: which kit is
    detected, per-field action/kind, and which fields Safe mode would elide."""
    cols = [c.strip() for c in req.columns if c and c.strip()][:4000]
    if not cols:
        return JSONResponse({"error": "no columns"}, status_code=400)
    return logmask.kit_dry_run(cols, family=req.family, safe=req.safe_mode)


# ------------------------------------------------------------------ kit studio

KIT_FILE_RX = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\.(yaml|yml)$")


def _user_kits_dir() -> Path:
    return Path(vendor_kits.USER_KITS_DIR)


def _user_kit_path(name: str) -> Path:
    if not KIT_FILE_RX.fullmatch(name):
        raise HTTPException(status_code=400,
                            detail="nome file non valido (minuscole/cifre/_/-, estensione .yaml)")
    base = _user_kits_dir().resolve()
    path = (base / name).resolve()
    if path.parent != base:
        raise HTTPException(status_code=400, detail="percorso non valido")
    return path


@app.get("/api/kits/files")
def api_kits_files(session: Session = Depends(require("admin"))):
    vendor_kits.reload_kits_if_changed()
    bundled = []
    for doc in vendor_kits._read_dir(vendor_kits.BUNDLED_KITS_DIR):
        if isinstance(doc, dict) and doc.get("id"):
            bundled.append({"id": str(doc["id"]), "label": str(doc.get("label") or doc["id"]),
                            "version": str(doc.get("version") or ""),
                            "rules": len(doc.get("rules") or []),
                            "fingerprints": len(doc.get("fingerprints") or [])})
    user_files = []
    base = _user_kits_dir()
    if base.is_dir():
        for path in sorted(list(base.glob("*.yaml")) + list(base.glob("*.yml"))):
            try:
                report = vendor_kits.validate_kit_yaml(path.read_text(encoding="utf-8"))
            except OSError:
                continue
            user_files.append({"name": path.name, "size": path.stat().st_size,
                               "ok": report["ok"], "errors": report["errors"],
                               "warnings": report["warnings"], "kit": report["kit"]})
    effective = [{"id": kid, "label": kit.label, "rules": len(kit.rules)}
                 for kid, kit in sorted(vendor_kits.KITS.items())]
    return {"bundled": sorted(bundled, key=lambda k: k["id"]), "user_files": user_files,
            "effective": effective, "user_dir": str(base)}


@app.get("/api/kits/files/{name}")
def api_kits_file_get(name: str, session: Session = Depends(require("admin"))):
    path = _user_kit_path(name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="file non trovato")
    return {"name": name, "content": path.read_text(encoding="utf-8")}


@app.get("/api/kits/bundled/{kit_id}")
def api_kits_bundled_get(kit_id: str, session: Session = Depends(require("admin"))):
    if not re.fullmatch(r"[a-z0-9_]{2,64}", kit_id):
        raise HTTPException(status_code=400, detail="id kit non valido")
    path = vendor_kits.BUNDLED_KITS_DIR / f"{kit_id}.yaml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="kit di serie non trovato")
    return {"id": kit_id, "content": path.read_text(encoding="utf-8")}


@app.post("/api/kits/validate")
def api_kits_validate(req: KitFileReq, session: Session = Depends(require("admin", csrf=True))):
    return vendor_kits.validate_kit_yaml(req.content)


@app.put("/api/kits/files/{name}")
def api_kits_file_put(name: str, req: KitFileReq, request: Request,
                      session: Session = Depends(require("admin", csrf=True))):
    path = _user_kit_path(name)
    report = vendor_kits.validate_kit_yaml(req.content)
    if not report["ok"]:
        return JSONResponse({"error": "kit non valido", "report": report}, status_code=400)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(req.content, encoding="utf-8")
    vendor_kits.force_reload()
    AUTH.audit(action="kit_write", success=True, ip=_client_ip(request), user=session.user,
               details={"file": name, "kit": (report["kit"] or {}).get("id"),
                        "rules_kept": (report["kit"] or {}).get("rules_kept")})
    return {"saved": name, "report": report,
            "effective_kits": len(vendor_kits.KITS)}


@app.delete("/api/kits/files/{name}")
def api_kits_file_delete(name: str, request: Request,
                         session: Session = Depends(require("admin", csrf=True))):
    path = _user_kit_path(name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="file non trovato")
    path.unlink()
    vendor_kits.force_reload()
    AUTH.audit(action="kit_delete", success=True, ip=_client_ip(request), user=session.user,
               details={"file": name})
    return {"deleted": name, "effective_kits": len(vendor_kits.KITS)}


@app.get("/api/dlp-categories")
def api_dlp_categories(session: Session = Depends(_session_from_request)):
    return {"categories": dlp_metadata(), "actions": ["pseudonymize", "redact", "block", "keep"]}


@app.get("/api/field-overrides")
def api_field_overrides_get(session: Session = Depends(_session_from_request)):
    """Override per campo attualmente salvati (mappa nome -> {action, kind})."""
    return {"overrides": load_field_overrides(),
            "actions": ["keep", "mask", "redact"]}


@app.post("/api/field-overrides")
def api_field_overrides_post(req: FieldOverrideReq, request: Request,
                             session: Session = Depends(require("admin", csrf=True))):
    """Salva/aggiorna gli override per campo (config dei campi non tracciati).
    keep = mantieni leggibile, mask = pseudonimizza (kind opaco di default),
    redact = elidi. Un'azione vuota rimuove l'override. Hot reload immediato."""
    try:
        saved = save_field_overrides(req.overrides)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logmask.FIELD_OVERRIDES = load_field_overrides()
    AUTH.audit(action="field-overrides", success=True, ip=_client_ip(request),
               user=session.user, details={"fields": len(saved),
                                            "changed": len(req.overrides)})
    return {"overrides": saved, "count": len(saved)}


@app.get("/api/workflow-profiles")
def api_workflow_profiles(session: Session = Depends(_session_from_request)):
    return {"profiles": workflow_profiles()}


@app.get("/api/workflow-profiles/{profile_id}")
def api_workflow_profile(profile_id: str, session: Session = Depends(_session_from_request)):
    profile = workflow_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="workflow profile not found")
    return profile


@app.get("/api/tenants")
def api_tenants(session: Session = Depends(_session_from_request)):
    user = session.user
    known = set(_known_tenants())
    if user.role == "admin" or "*" in user.tenants:
        tenants = sorted(known)
    else:
        tenants = sorted(user.tenants)
    default = LEGACY_TENANT if LEGACY_TENANT in tenants else (tenants[0] if tenants else None)
    return {"tenants": tenants, "legacy_available": LEGACY_TENANT in tenants, "default": default}


@app.post("/api/anonymize")
def api_anonymize(
    req: AnonReq,
    request: Request,
    session: Session = Depends(require("anonymize", csrf=True)),
):
    if not req.text.strip():
        return JSONResponse({"error": "empty input"}, status_code=400)
    _enforce_upload_size(req.text, req.source)
    tenant = _authorize_tenant(req.tenant, session.user)
    fmt = req.format
    if fmt == "auto":
        fmt = detect_structured_format(req.text) or ("csv" if looks_like_csv(req.text) else "text")
    try:
        dlp_policy = normalize_dlp_policy(req.dlp_policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    opt = Options(
        preserve_subnet=req.preserve_subnet,
        keep_domain=False,
        keep_scope=True,
        ip_mode=req.ip_mode,
        url_mode=req.url_mode,
        dlp_policy=dlp_policy,
        client_terms=load_client_terms(),
        client_term_mode=os.environ.get("LOGMASK_CLIENT_TERM_MODE", "pseudonymize"),
        client_term_label=os.environ.get("LOGMASK_CLIENT_TERM_LABEL", "[CLIENTE]"),
        tenant_networks=load_tenant_networks() if req.mask_tenant_networks else (),
        host_terms=load_host_terms(),
    )

    try:
        with LOCK:
            logmask.EXTRA_KEEP_FIELDS = load_keep_fields()
            logmask.FIELD_OVERRIDES = load_field_overrides()
            tenant, _path, vault = _open_tenant_vault(tenant)
            try:
                anon = Anonymizer(vault, set(ORDER), opt)
                if fmt == "csv":
                    resp = _anonymize_csv(req, tenant, vault, anon)
                elif fmt in STRUCTURED_FORMATS:
                    resp = _anonymize_structured(req, tenant, vault, anon, fmt)
                else:
                    resp = _anonymize_text(req, tenant, vault, anon)
                vault.commit()
            finally:
                vault.db.close()
        AUTH.audit(
            action="anonymize",
            success=True,
            ip=_client_ip(request),
            user=session.user,
            tenant=tenant,
            details={
                "format": resp.get("format"),
                "vendor_kit": (resp.get("vendor_kit") or {}).get("id"),
                "workflow_profile": req.workflow_profile,
                "ip_mode": req.ip_mode,
                "url_mode": req.url_mode,
                "blocked": bool(resp.get("blocked")),
                "masked": sum(resp.get("counts", {}).values()),
                "elided": int(resp.get("elided", 0)),
                "dlp_actions": (resp.get("dlp") or {}).get("actions", {}),
                "input_chars": len(req.text),
            },
        )
        return resp
    except Exception as exc:
        AUTH.audit(
            action="anonymize",
            success=False,
            ip=_client_ip(request),
            user=session.user,
            tenant=tenant,
            details={"error_type": type(exc).__name__},
        )
        raise


def _dlp_payload(anon: Anonymizer) -> dict:
    blocked_categories: dict[str, int] = {}
    for finding in anon.dlp_blocked:
        category = str(finding.get("kind", "unknown"))
        blocked_categories[category] = blocked_categories.get(category, 0) + 1
    return {
        "policy": dict(anon.opt.dlp_policy or {}),
        "counts": dict(anon.dlp_counts),
        "actions": dict(anon.dlp_actions),
        "blocked": blocked_categories,
    }


def _anonymize_text(req: AnonReq, tenant: str, vault: Vault, anon: Anonymizer) -> dict:
    out = anon.process(req.text)
    swept = 0
    elided, samples = 0, []
    if req.safe_mode:
        out, swept = sweep_known(vault, out, anon.opt)
        out, elided, samples = redact_residuals(out, anon.opt.dlp_policy)
    findings = scan_sensitive_residuals(out, anon.opt.dlp_policy)
    dlp_failed = len(anon.dlp_blocked)
    blocked = bool(findings) or dlp_failed > 0
    return {
        "tenant": tenant,
        "format": "text",
        "ip_mode": req.ip_mode,
        "policy_kept": sum(anon.policy_kept.values()),
        "catalog": None,
        "vendor_kit": kit_info(None),
        "coverage": None,
        "unknown_fields": [],
        "output": out,
        "counts": dict(anon.counts),
        "skipped": dict(anon.skipped),
        "swept": swept,
        "elided": elided + anon.dlp_actions.get("redact", 0),
        "elided_samples": samples,
        "dlp": _dlp_payload(anon),
        "fields": None,
        "exposed": len(findings),
        "failed": len(findings) + dlp_failed,
        "failed_samples": [str(f["value"]) for f in findings[:10]],
        "verification": "blocked" if blocked else "pass",
        "blocked": blocked,
    }


@app.post("/api/anonymize-pst")
async def api_anonymize_pst(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form(...),
    format: str = Form("ndjson"),
    ip_mode: str = Form("all"),
    url_mode: str = Form("all"),
    mask_tenant_networks: bool = Form(True),
    session: Session = Depends(require("anonymize", csrf=True)),
):
    if not pst_anon.readpst_available():
        raise HTTPException(status_code=501,
                            detail="Estrazione PST non disponibile: manca pst-utils nel container.")
    fmt = format if format in ("ndjson", "csv") else "ndjson"
    tenant = _authorize_tenant(tenant, session.user)
    total = 0
    with tempfile.NamedTemporaryFile("wb", suffix=".pst", delete=False) as tf:
        pst_path = Path(tf.name)
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                tf.close(); pst_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413,
                    detail=f"File troppo grande. Limite {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
            tf.write(chunk)
    opt = Options(
        preserve_subnet=False, keep_domain=False, keep_scope=True, ip_mode=ip_mode,
        url_mode=url_mode if url_mode in ("none", "internal", "all") else "all",
        client_terms=load_client_terms(),
        client_term_mode="pseudonymize",
        dlp_policy=dict(NO_ELISION_DLP_POLICY),          # v0.23.0: mai elisioni
        tenant_networks=load_tenant_networks() if mask_tenant_networks else (),
        host_terms=load_host_terms(),
        person_terms=load_person_terms(),         # v0.23.0: i nomi nei corpi e-mail
    )
    def _work():
        # v0.22.6: readpst e' un sottoprocesso BLOCCANTE. Eseguirlo dentro
        # l'endpoint async congelava l'intero event loop: nessun'altra
        # richiesta veniva servita per tutta l'estrazione. Qui gira su un
        # thread, cosi' il server resta reattivo.
        with LOCK:
            logmask.EXTRA_KEEP_FIELDS = load_keep_fields()
            logmask.FIELD_OVERRIDES = load_field_overrides()
            t, _p, vault = _open_tenant_vault(tenant)
            try:
                anon = Anonymizer(vault, set(ORDER), opt)

                def scrub(text: str) -> str:
                    # v0.23.0: stessa catena dei .docx - motore, sweep del
                    # vault (uno stesso nome resta lo stesso pseudonimo in
                    # tutti i messaggi) e residui pseudonimizzati, mai elisi.
                    out = anon.process(text)
                    out, _swept = sweep_known(vault, out, opt, prose=True)
                    out, _n, _kinds = pseudonymize_residuals(out, anon, opt.dlp_policy)
                    return out

                body, count = pst_anon.anonymize_pst(pst_path, anon, fmt=fmt, scrub=scrub)
                vault.commit()
                return t, body, count
            finally:
                vault.db.close()

    try:
        tenant, body, count = await run_in_threadpool(_work)
        AUTH.audit(action="anonymize-pst", success=True, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"messages": count, "format": fmt, "filename": file.filename})
        stem = (file.filename or "mailbox").rsplit(".", 1)[0]
        return {"output": body, "messages": count, "format": fmt,
                "filename": f"{stem}.anon.{fmt}"}
    except HTTPException:
        raise
    except PseudonymSpaceExhausted as exc:
        AUTH.audit(action="anonymize-pst", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=422, detail=str(exc))
    except pst_anon.PstExtractionError as exc:
        AUTH.audit(action="anonymize-pst", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        AUTH.audit(action="anonymize-pst", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error_type": type(exc).__name__})
        raise HTTPException(status_code=422,
            detail=f"Anonimizzazione PST fallita ({type(exc).__name__}). "
                   "Controlla i log del server per il dettaglio.")
    finally:
        pst_path.unlink(missing_ok=True)


@app.post("/api/anonymize-docx")
async def api_anonymize_docx(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form(...),
    ip_mode: str = Form("all"),
    url_mode: str = Form("all"),
    mask_tenant_networks: bool = Form(True),
    session: Session = Depends(require("anonymize", csrf=True)),
):
    """Anonimizza un .docx restituendo un .docx: stili, tabelle, intestazioni e
    numerazione restano; cambia solo il testo. La risposta e' base64 perche' il
    documento e' binario."""
    tenant = _authorize_tenant(tenant, session.user)
    payload = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        payload += chunk
        if len(payload) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413,
                detail=f"File troppo grande. Limite {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
    if not docx_anon.is_docx(payload):
        raise HTTPException(status_code=400,
                            detail="Il file non e' un documento .docx valido.")
    opt = Options(
        preserve_subnet=False, keep_domain=False, keep_scope=True, ip_mode=ip_mode,
        url_mode=url_mode if url_mode in ("none", "internal", "all") else "all",
        client_terms=load_client_terms(),
        # v0.23.0: documenti e posta non vengono mai elisi, nemmeno se
        # l'installazione ha impostato LOGMASK_CLIENT_TERM_MODE=elide/label:
        # un .docx con [ELIDED] al posto del nome cliente non e' ripristinabile.
        client_term_mode="pseudonymize",
        dlp_policy=dict(NO_ELISION_DLP_POLICY),
        tenant_networks=load_tenant_networks() if mask_tenant_networks else (),
        host_terms=load_host_terms(),
        person_terms=load_person_terms(),
    )
    try:
        with LOCK:
            logmask.EXTRA_KEEP_FIELDS = load_keep_fields()
            logmask.FIELD_OVERRIDES = load_field_overrides()
            tenant, _p, vault = _open_tenant_vault(tenant)
            try:
                anon = Anonymizer(vault, set(ORDER), opt)

                def scrub(text: str) -> str:
                    # v0.23.0: nei documenti si pseudonimizza, non si elide.
                    out = anon.process(text)
                    out, _swept = sweep_known(vault, out, opt, prose=True)
                    out, _n, _kinds = pseudonymize_residuals(out, anon, opt.dlp_policy)
                    return out

                result = docx_anon.anonymize_docx(payload, scrub)
                vault.commit()
            finally:
                vault.db.close()
        AUTH.audit(action="anonymize-docx", success=True, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"paragraphs": result.paragraphs, "changed": result.changed,
                            "collapsed": result.collapsed, "filename": file.filename})
        stem = (file.filename or "documento").rsplit(".", 1)[0]
        return {
            "document_b64": base64.b64encode(result.data).decode("ascii"),
            "filename": f"{stem}.anon.docx",
            "paragraphs": result.paragraphs,
            "changed": result.changed,
            "collapsed": result.collapsed,
            "metadata_scrubbed": result.metadata_scrubbed,
            "warnings": result.warnings,
        }
    except HTTPException:
        raise
    except docx_anon.DocxTooLargeError as exc:
        AUTH.audit(action="anonymize-docx", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=413, detail=str(exc))
    except PseudonymSpaceExhausted as exc:
        AUTH.audit(action="anonymize-docx", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        AUTH.audit(action="anonymize-docx", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"error_type": type(exc).__name__})
        raise HTTPException(status_code=422,
            detail="Anonimizzazione del documento fallita (file .docx non valido?).")


async def _read_upload(file: UploadFile) -> bytes:
    """Legge un upload binario rispettando il limite di dimensione."""
    payload = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        payload += chunk
        if len(payload) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413,
                detail=f"File troppo grande. Limite {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
    return payload


def _binary_options(ip_mode: str, url_mode: str, mask_tenant_networks: bool) -> Options:
    """Opzioni condivise dai percorsi binari (.docx, .pst, .pdf): mai elisioni,
    nomi di persona attivi, policy IP/URL scelte dall'utente."""
    return Options(
        preserve_subnet=False, keep_domain=False, keep_scope=True, ip_mode=ip_mode,
        url_mode=url_mode if url_mode in ("none", "internal", "all") else "all",
        client_terms=load_client_terms(),
        client_term_mode="pseudonymize",
        dlp_policy=dict(NO_ELISION_DLP_POLICY),
        tenant_networks=load_tenant_networks() if mask_tenant_networks else (),
        host_terms=load_host_terms(),
        person_terms=load_person_terms(),
    )


@app.post("/api/anonymize-pdf")
async def api_anonymize_pdf(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form(...),
    output: str = Form("pdf"),
    ip_mode: str = Form("all"),
    url_mode: str = Form("all"),
    mask_tenant_networks: bool = Form(True),
    session: Session = Depends(require("anonymize", csrf=True)),
):
    """Anonimizza un PDF. output='pdf' restituisce un PDF con l'impaginazione
    al suo posto e il testo originale RIMOSSO davvero; output='text'
    restituisce il testo estratto e anonimizzato, senza impaginazione."""
    if not pdf_anon.available():
        raise HTTPException(status_code=501, detail=str(pdf_anon.PdfUnavailableError.__doc__))
    tenant = _authorize_tenant(tenant, session.user)
    fmt = output if output in ("pdf", "text") else "pdf"
    payload = await _read_upload(file)
    if not pdf_anon.is_pdf(payload):
        raise HTTPException(status_code=400, detail="Il file non e' un PDF valido.")
    opt = _binary_options(ip_mode, url_mode, mask_tenant_networks)
    try:
        with LOCK:
            logmask.EXTRA_KEEP_FIELDS = load_keep_fields()
            logmask.FIELD_OVERRIDES = load_field_overrides()
            tenant, _p, vault = _open_tenant_vault(tenant)
            try:
                anon = Anonymizer(vault, set(ORDER), opt)

                def scrub(text: str) -> str:
                    out = anon.process(text)
                    out, _swept = sweep_known(vault, out, opt, prose=True)
                    out, _n, _k = pseudonymize_residuals(out, anon, opt.dlp_policy)
                    return out

                if fmt == "text":
                    pages = [scrub(page) for page in pdf_anon.extract_text(payload)]
                    body = "\n\n".join(pages)
                    result = pdf_anon.PdfResult(text=body, pages=len(pages))
                else:
                    result = pdf_anon.anonymize_pdf(payload, scrub)
                vault.commit()
            finally:
                vault.db.close()
        AUTH.audit(action="anonymize-pdf", success=True, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"pages": result.pages, "output": fmt,
                            "filename": file.filename})
        stem = (file.filename or "documento").rsplit(".", 1)[0]
        payload_out = {
            "tenant": tenant, "pages": result.pages, "output": fmt,
            "spans": result.spans, "changed": result.changed,
            "metadata_scrubbed": result.metadata_scrubbed,
            "annotations": result.annotations, "widgets": result.widgets,
            "attachments_removed": result.attachments_removed,
            "image_only_pages": result.image_only_pages,
            "warnings": result.warnings,
        }
        if fmt == "text":
            payload_out["output_text"] = result.text
            payload_out["filename"] = f"{stem}.anon.txt"
        else:
            payload_out["document_b64"] = base64.b64encode(result.data).decode()
            payload_out["filename"] = f"{stem}.anon.pdf"
        return payload_out
    except HTTPException:
        raise
    except pdf_anon.PdfLeakError as exc:
        AUTH.audit(action="anonymize-pdf", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=422, detail=str(exc))
    except pdf_anon.PdfUnreadableError as exc:
        AUTH.audit(action="anonymize-pdf", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant, details={"error": str(exc)[:200]})
        raise HTTPException(status_code=400, detail=str(exc))
    except pdf_anon.PdfTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except pdf_anon.PdfUnavailableError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except PseudonymSpaceExhausted as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        AUTH.audit(action="anonymize-pdf", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"error_type": type(exc).__name__})
        raise HTTPException(status_code=422,
            detail=f"Anonimizzazione del PDF fallita ({type(exc).__name__}).")


@app.post("/api/deanonymize-pdf")
async def api_deanonymize_pdf(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form(...),
    session: Session = Depends(require("reverse", csrf=True)),
):
    """Ripristina un PDF anonimizzato. Le posizioni restano quelle del
    documento anonimizzato: il file e' leggibile e completo, non identico
    all'originale di partenza."""
    if not pdf_anon.available():
        raise HTTPException(status_code=501, detail=str(pdf_anon.PdfUnavailableError.__doc__))
    tenant = _authorize_tenant(tenant, session.user)
    payload = await _read_upload(file)
    if not pdf_anon.is_pdf(payload):
        raise HTTPException(status_code=400, detail="Il file non e' un PDF valido.")
    opt = _binary_options("all", "all", True)
    try:
        with LOCK:
            tenant, _p, vault = _open_tenant_vault(tenant)
            try:
                before = pdf_anon.count_pseudonyms(payload)
                result = pdf_anon.deanonymize_pdf(payload, Deanonymizer(vault, opt).process)
                after = pdf_anon.count_pseudonyms(result.data)
            finally:
                vault.db.close()
        AUTH.audit(action="deanonymize-pdf", success=True, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"pages": result.pages, "tokens_in": before,
                            "tokens_left": after, "filename": file.filename})
        stem = (file.filename or "documento").rsplit(".", 1)[0]
        return {"tenant": tenant, "pages": result.pages,
                "tokens_in": before, "tokens_resolved": before - after,
                "tokens_unresolved": after,
                "document_b64": base64.b64encode(result.data).decode(),
                "filename": f"{stem}.restored.pdf",
                "warnings": result.warnings}
    except HTTPException:
        raise
    except pdf_anon.PdfUnreadableError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        AUTH.audit(action="deanonymize-pdf", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"error_type": type(exc).__name__})
        raise HTTPException(status_code=422,
            detail=f"Ripristino del PDF fallito ({type(exc).__name__}).")


@app.post("/api/deanonymize-docx")
async def api_deanonymize_docx(
    request: Request,
    file: UploadFile = File(...),
    tenant: str = Form(...),
    session: Session = Depends(require("reverse", csrf=True)),
):
    """Ripristina un .docx anonimizzato restituendo un .docx con la stessa
    struttura. Richiede il permesso di reverse ed e' tracciato nell'audit."""
    tenant = _authorize_tenant(tenant, session.user)
    payload = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        payload += chunk
        if len(payload) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413,
                detail=f"File troppo grande. Limite {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
    if not docx_anon.is_docx(payload):
        raise HTTPException(status_code=400,
                            detail="Il file non e' un documento .docx valido.")
    try:
        with LOCK:
            tenant, _p, vault = _open_tenant_vault(tenant)
            try:
                deanon = Deanonymizer(vault, Options())
                result = docx_anon.deanonymize_docx(payload, deanon.process)
            finally:
                vault.db.close()
        AUTH.audit(action="deanonymize-docx", success=True, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"paragraphs": result.paragraphs, "restored": result.changed,
                            "filename": file.filename})
        stem = (file.filename or "documento").rsplit(".", 1)[0]
        if stem.endswith(".anon"):
            stem = stem[:-5]
        return {
            "document_b64": base64.b64encode(result.data).decode("ascii"),
            "filename": f"{stem}.restored.docx",
            "paragraphs": result.paragraphs,
            "restored": result.changed,
            "tokens_in": result.tokens_in,
            "tokens_resolved": result.tokens_in - result.tokens_left,
            "tokens_unresolved": result.tokens_left,
        }
    except HTTPException:
        raise
    except docx_anon.DocxTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:
        AUTH.audit(action="deanonymize-docx", success=False, ip=_client_ip(request),
                   user=session.user, tenant=tenant,
                   details={"error_type": type(exc).__name__})
        raise HTTPException(status_code=422, detail="Ripristino del documento fallito.")


def _anonymize_csv(req: AnonReq, tenant: str, vault: Vault, anon: Anonymizer) -> dict:
    # v0.21.1: export verticale "campo -> valore" (un singolo alert, un campo
    # per riga). Se la prima colonna identifica un kit, lo si ribalta in
    # orizzontale cosi' ogni campo viene classificato invece di finire tutto
    # nella colonna elisa. Se non c'e' un kit non si tocca nulla.
    text_in = req.text
    transposed_note = None
    if not _requested_catalog(req.catalog):
        flipped = transpose_keyvalue_csv(req.text)
        if flipped is not None:
            text_in = flipped
            transposed_note = (
                "Rilevato export verticale campo/valore: ribaltato in orizzontale "
                "per classificare ogni campo. Se non e' cio' che volevi, forza il "
                "kit o incolla l'export in formato tabellare."
            )
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
        tf.write(text_in)
        tmp = Path(tf.name)
    try:
        columns, samples, dialect = read_samples(tmp, 200)
        if not columns:
            raise HTTPException(status_code=400, detail="no CSV header found")
        if _looks_delimiter_collapsed(columns, samples):
            # TSV whose tabs were lost -> columns can't be separated. Instead of
            # failing, process the whole input as free text (every sensitive
            # token is still masked) and warn that the per-column view needs a
            # properly delimited file (v0.10.17).
            result = _anonymize_text(req, tenant, vault, anon)
            result["warning"] = (
                "Colonne non separabili: il testo sembra un TSV che ha perso le "
                "tabulazioni (campi separati da spazi). E stato elaborato come testo "
                "— IP, host, utenti, email e nomi cliente sono comunque mascherati "
                "— ma senza vista a colonne. Per l'analisi per-colonna carica il "
                "file .tsv/.csv o incolla il TSV mantenendo le tabulazioni."
            )
            return result
        forced_catalog = _requested_catalog(req.catalog)
        detection = kit_info(forced_catalog, forced=True) if forced_catalog else detect_vendor_kit(columns)
        family = forced_catalog or detection.get("id") or detect_family(columns)
        policy = default_policy(columns, samples, family)
        if req.safe_mode:
            policy = apply_safe_policy(policy, samples)
        cp = CsvAnonymizer(anon, policy, req.source, safe=req.safe_mode)
        buf = io.StringIO()
        cp.process(tmp, buf, dialect, columns)

        fields, exposed_values = [], 0
        for c in columns:
            spec = policy["columns"].get(c, {})
            ne, mk, el, failed, policy_kept = cp.per_col.get(c, [0, 0, 0, 0, 0])
            action = spec.get("action", "keep")
            inferred_by = str(spec.get("inferred_by") or "")
            safe_keep = action == "keep" and (
                inferred_by.startswith("vendor:") or is_safe_column(c, samples.get(c, []))
            )
            is_exposed = action == "keep" and ne > 0 and not safe_keep
            if is_exposed:
                exposed_values += ne
            fields.append(
                {
                    "column": c,
                    "kind": spec.get("kind"),
                    "action": action,
                    "inferred_by": spec.get("inferred_by", ""),
                    "nonempty": ne,
                    "masked": mk,
                    "elided": el,
                    "failed": failed,
                    "policy_kept": policy_kept,
                    "safe_keep": safe_keep or policy_kept > 0,
                    "exposed": is_exposed,
                }
            )
        dlp_failed = len(anon.dlp_blocked)
        blocked = exposed_values > 0 or cp.failed > 0 or dlp_failed > 0
        coverage = _coverage_payload(fields, str(family) if family else None)
        return {
            "tenant": tenant,
            "format": "csv",
            "ip_mode": req.ip_mode,
            "policy_kept": sum(anon.policy_kept.values()),
            "catalog": family or "generic",
            "vendor_kit": detection,
            "coverage": coverage,
            "unknown_fields": coverage["unknown_fields"],
            "rows": cp.stats_rows,
            "output": buf.getvalue(),
            "counts": dict(anon.counts),
            "skipped": dict(anon.skipped),
            "swept": 0,
            "elided": cp.elided,
            "elided_samples": cp.elided_samples,
            "dlp": _dlp_payload(anon),
            "fields": fields,
            "exposed": exposed_values,
            "failed": cp.failed + dlp_failed,
            "failed_samples": cp.failed_samples,
            "verification": "blocked" if blocked else "pass",
            "blocked": blocked,
            **({"warning": transposed_note} if transposed_note else {}),
        }
    finally:
        tmp.unlink(missing_ok=True)


def _anonymize_structured(req: AnonReq, tenant: str, vault: Vault, anon: Anonymizer, fmt: str) -> dict:
    try:
        forced_catalog = _requested_catalog(req.catalog)
        result = anonymize_structured(
            fmt,
            req.text,
            anon,
            vault,
            safe=req.safe_mode,
            source=req.source,
            family=forced_catalog,
        )
    except (ValueError, csv.Error) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # Structured parsers validate every scalar and relevant header/prefix.
    # A second scan over serialized output would treat safe dotted metadata
    # (for example ECS event.dataset) as an exposed hostname.
    findings: list[dict] = []
    failed_samples = list(result.failed_samples)
    dlp_failed = len(anon.dlp_blocked)
    blocked = result.failed > 0 or result.exposed > 0 or dlp_failed > 0
    field_payload = result.fields_payload()
    coverage = _coverage_payload(field_payload, result.catalog)
    return {
        "tenant": tenant,
        "format": fmt,
        "ip_mode": req.ip_mode,
        "policy_kept": result.policy_kept,
        "catalog": result.catalog or fmt,
        "vendor_kit": result.vendor_detection,
        "coverage": coverage,
        "unknown_fields": coverage["unknown_fields"],
        "rows": result.records,
        "output": result.output,
        "counts": dict(anon.counts),
        "skipped": dict(anon.skipped),
        "swept": result.swept,
        "elided": result.elided,
        "elided_samples": result.elided_samples,
        "dlp": _dlp_payload(anon),
        "fields": field_payload,
        "exposed": result.exposed,
        "failed": result.failed + len(findings) + dlp_failed,
        "failed_samples": failed_samples,
        "verification": "blocked" if blocked else "pass",
        "blocked": blocked,
    }


def _deanonymize_csv_text(text: str, deanon: Deanonymizer) -> str:
    """Reverse a CSV/TSV document without breaking quoting or embedded delimiters."""
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "input.csv"
        inp.write_text(text, encoding="utf-8")
        out = io.StringIO(newline="")
        csv_deanonymize(inp, out, deanon)
        return out.getvalue()


@app.post("/api/deanonymize")
def api_deanonymize(
    req: DeanonReq,
    request: Request,
    session: Session = Depends(require("reverse", csrf=True)),
):
    if not req.text.strip():
        return JSONResponse({"error": "empty input"}, status_code=400)
    _enforce_upload_size(req.text, req.source)
    tenant = _authorize_tenant(req.tenant, session.user)
    fmt = req.format
    if fmt == "auto":
        fmt = detect_structured_format(req.text) or ("csv" if looks_like_csv(req.text) else "text")
    try:
        with LOCK:
            tenant, _path, vault = _open_tenant_vault(tenant)
            try:
                deanon = Deanonymizer(vault, Options())
                try:
                    if fmt == "csv":
                        out = _deanonymize_csv_text(req.text, deanon)
                    elif fmt in STRUCTURED_FORMATS:
                        out = deanonymize_structured(fmt, req.text, deanon)
                    else:
                        out = deanon.process(req.text)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
                result = {
                    "tenant": tenant,
                    "format": fmt,
                    "output": out,
                    "resolved": deanon.hits.get("resolved", 0),
                    "unresolved": sorted(deanon.misses.keys())[:20],
                    "unresolved_total": sum(deanon.misses.values()),
                }
            finally:
                vault.db.close()
        AUTH.audit(
            action="reverse",
            success=True,
            ip=_client_ip(request),
            user=session.user,
            tenant=tenant,
            details={
                "format": result["format"],
                "resolved": result["resolved"],
                "unresolved": result["unresolved_total"],
                "input_chars": len(req.text),
            },
        )
        return result
    except Exception as exc:
        AUTH.audit(
            action="reverse",
            success=False,
            ip=_client_ip(request),
            user=session.user,
            tenant=tenant,
            details={"error_type": type(exc).__name__, "input_chars": len(req.text)},
        )
        raise


@app.get("/api/fields")
def api_fields(
    tenant: str = Query(...),
    session: Session = Depends(require("reports")),
):
    tenant = _authorize_tenant(tenant, session.user)
    with LOCK:
        tenant, path, key = _tenant_context(tenant)
        if not path.exists():
            return {"tenant": tenant, "fields": []}
        vault = Vault(path, key)
        try:
            rows = vault.fields_report(None)
            return {
                "tenant": tenant,
                "fields": [
                    {
                        "source": r[0], "column": r[1], "kind": r[2], "action": r[3],
                        "rows": r[4], "nonempty": r[5], "masked": r[6], "elided": r[7], "failed": r[8],
                    }
                    for r in rows
                ],
            }
        finally:
            vault.db.close()


@app.get("/api/stats")
def api_stats(
    tenant: str = Query(...),
    session: Session = Depends(require("reports")),
):
    tenant = _authorize_tenant(tenant, session.user)
    with LOCK:
        tenant, path, key = _tenant_context(tenant)
        vault_name = str(path.relative_to(DATA)) if path.is_relative_to(DATA) else str(path)
        if not path.exists():
            return {"tenant": tenant, "vault": vault_name, "kinds": []}
        vault = Vault(path, key)
        try:
            return {
                "tenant": tenant,
                "vault": vault_name,
                "kinds": [{"kind": k, "entries": n, "hits": h or 0} for k, n, h in vault.stats()],
            }
        finally:
            vault.db.close()


# --------------------------------------------------------------- admin endpoints


def _validate_assigned_tenants(tenants: list[str], role: str) -> list[str]:
    if role == "admin":
        return ["*"]
    return sorted({normalize_tenant_id(t) for t in tenants})


@app.get("/api/admin/users")
def api_admin_users(session: Session = Depends(require("admin"))):
    return {"users": AUTH.list_users(), "roles": list(ROLES)}


@app.post("/api/admin/users")
def api_admin_create_user(
    req: CreateUserReq,
    request: Request,
    session: Session = Depends(require("admin", csrf=True)),
):
    try:
        tenants = _validate_assigned_tenants(req.tenants, req.role)
        user_id = AUTH.create_user(
            username=req.username,
            password=req.password,
            role=req.role,
            tenants=tenants,
            must_change_password=True,
        )
    except (ValueError, PasswordPolicyError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    AUTH.audit(
        action="admin_create_user",
        success=True,
        ip=_client_ip(request),
        user=session.user,
        details={"target_user_id": user_id, "target_username": req.username.lower(), "role": req.role, "tenants": tenants},
    )
    return {"ok": True, "user_id": user_id}


@app.patch("/api/admin/users/{user_id}")
def api_admin_update_user(
    user_id: int,
    req: UpdateUserReq,
    request: Request,
    session: Session = Depends(require("admin", csrf=True)),
):
    if user_id == session.user.id and (req.active is False or (req.role and req.role != "admin")):
        return JSONResponse({"error": "cannot deactivate or demote the current administrator"}, status_code=400)
    try:
        role = req.role
        tenants = None
        if req.tenants is not None:
            target_role = role or next((u["role"] for u in AUTH.list_users() if u["id"] == user_id), "")
            tenants = _validate_assigned_tenants(req.tenants, target_role)
        AUTH.update_user(
            user_id,
            role=role,
            tenants=tenants,
            active=req.active,
            reset_password=req.reset_password,
        )
    except (ValueError, PasswordPolicyError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    AUTH.audit(
        action="admin_update_user",
        success=True,
        ip=_client_ip(request),
        user=session.user,
        details={"target_user_id": user_id, "role": role, "tenants": tenants, "active": req.active, "password_reset": req.reset_password is not None},
    )
    return {"ok": True}


@app.post("/api/admin/vault/reset")
def api_admin_vault_reset(
    req: VaultResetReq,
    request: Request,
    session: Session = Depends(require("admin", csrf=True)),
):
    """Azzera il vault di un tenant ARCHIVIANDO il file, non cancellandolo.

    Il vault e' l'unica cosa che rende reversibili gli export gia' condivisi:
    perderlo significa non poter piu' risalire da uno pseudonimo al valore
    originale, per sempre. Per questo il file viene rinominato con un
    timestamp invece di essere eliminato: se l'azzeramento e' stato un errore
    basta rimetterlo al suo posto. La cancellazione definitiva resta una scelta
    manuale e consapevole.

    NB: i token NON cambiano dopo l'azzeramento - la derivazione e'
    deterministica sulla master key del tenant - quindi la correlazione con gli
    export precedenti si mantiene. Si perde solo la reversibilita'.
    """
    tenant = _authorize_tenant(req.tenant, session.user)
    if req.confirm.strip().lower() != tenant:
        raise HTTPException(status_code=400,
                            detail="conferma non corrispondente: ripetere il nome del tenant")
    _tenant, path, _key = _tenant_context(tenant)
    archived = None
    with LOCK:
        if Path(path).exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            target = Path(path).with_name(f"{Path(path).stem}-{stamp}.db")
            Path(path).rename(target)
            archived = target.name
    AUTH.audit(action="vault_reset", success=True, ip=_client_ip(request),
               user=session.user, tenant=tenant,
               details={"archived_as": archived})
    return {"tenant": tenant, "archived_as": archived,
            "note": "vault archiviato: gli export precedenti non sono piu' reversibili "
                    "finche' il file non viene ripristinato"}


@app.post("/api/admin/secret/reset")
def api_admin_secret_reset(
    req: SecretResetReq,
    request: Request,
    session: Session = Depends(require("admin", csrf=True)),
):
    """Rigenera la master key - il "secret" da cui derivano TUTTI i token.

    Effetto: ogni token futuro cambia (lo stesso valore produce uno pseudonimo
    diverso, secret-... compresi) e OGNI vault esistente diventa non piu'
    reversibile, perche' cifrato con la chiave precedente. Non e' un reset per
    tenant: azzera la reversibilita' di tutto.

    Come per il reset del vault, nulla viene distrutto: la vecchia chiave e i
    vault esistenti vengono ARCHIVIATI con un timestamp. Restano recuperabili
    SOLO insieme (vecchia chiave + vecchi vault): rimettendo entrambi al loro
    posto si torna indietro. Utenti e sessioni non dipendono dalla master key,
    quindi restano validi: nessuno viene disconnesso.
    """
    global MASTER
    if req.confirm.strip().upper() != SECRET_RESET_PHRASE:
        raise HTTPException(status_code=400,
            detail=f"conferma non corrispondente: digitare '{SECRET_RESET_PHRASE}' per confermare")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archived_vaults: list[str] = []
    with LOCK:
        # 1) archivia i vault: con la nuova chiave sarebbero comunque orfani,
        #    e mescolare righe vecchie e nuove corromperebbe la reversibilita'.
        for vf in _all_vault_files():
            target = vf.with_name(f"{vf.stem}-prereset-{stamp}.db")
            vf.rename(target)
            archived_vaults.append(str(target.relative_to(DATA)))
        # 2) archivia la vecchia chiave e generane una nuova.
        archived_key = None
        if KEY_PATH.exists():
            archived_key = KEY_PATH.with_name(f"{KEY_PATH.stem}-prereset-{stamp}{KEY_PATH.suffix}")
            KEY_PATH.rename(archived_key)
        KEY_PATH.write_text(base64.b64encode(os.urandom(32)).decode(), encoding="utf-8")
        try:
            os.chmod(KEY_PATH, 0o600)
        except OSError:
            pass
        # 3) ricarica la master in memoria: gli endpoint la rileggono a ogni
        #    richiesta, quindi il cambio ha effetto subito, senza riavvio.
        MASTER = _master()
    AUTH.audit(action="secret_reset", success=True, ip=_client_ip(request),
               user=session.user,
               details={"vaults_archived": len(archived_vaults),
                        "key_archived_as": archived_key.name if archived_key else None})
    return {"reset": True,
            "vaults_archived": len(archived_vaults),
            "archived_key": archived_key.name if archived_key else None,
            "note": "master key rigenerata: i nuovi token sono diversi e i vault "
                    "precedenti non sono piu' reversibili (archiviati, recuperabili "
                    "solo insieme alla vecchia chiave). Nessun utente e' stato disconnesso."}


@app.get("/api/admin/audit")
def api_admin_audit(
    limit: int = Query(200, ge=1, le=1000),
    tenant: str | None = Query(None),
    session: Session = Depends(require("audit")),
):
    if tenant:
        tenant = normalize_tenant_id(tenant)
    return {"events": AUTH.list_audit(limit=limit, tenant=tenant)}


# ---------------------------------------------------------------- frontend

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
