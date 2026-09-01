#!/usr/bin/env python3
"""
logmask - deterministic log pseudonymization with reversible encrypted vault.

Design:
  - Deterministic: pseudonym = HMAC-SHA256(master_key, type|normalized_value)
    => same input always yields same pseudonym, across files and runs.
    => cross-log correlation is preserved without exposing the original value.
  - Reversible: vault (SQLite) stores original encrypted with AES-GCM.
    Reversal requires the master key. Blind index (HMAC) is used for lookup,
    so the plaintext original never appears in an index.
  - Format-preserving-ish: pseudo-IPs are valid IPs, pseudo-MACs valid MACs,
    pseudo-emails valid emails => downstream parsers keep working.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hmac
import hashlib
import ipaddress
from functools import lru_cache
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vendor_kits import canonical_kit_id, detect_vendor_kit, kit_catalogs, match_rule
from dlp import (
    WELL_KNOWN_GUIDS,
    apply as apply_dlp,
    apply_field as apply_dlp_field,
    normalize_dlp_policy,
)

DEFAULT_KEY = Path.home() / ".logmask" / "master.key"
DEFAULT_VAULT = Path.home() / ".logmask" / "vault.db"

LEGACY_TENANT = "legacy"
TENANT_RX = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def normalize_tenant_id(value: str) -> str:
    """Validate and canonicalize a tenant identifier safe for paths and keys."""
    tenant = (value or "").strip().lower()
    if not TENANT_RX.fullmatch(tenant):
        raise ValueError(
            "tenant must be 2-64 chars: lowercase letters, numbers, dot, dash or underscore"
        )
    if tenant in {".", ".."} or tenant.startswith(".") or ".." in tenant:
        raise ValueError("tenant contains an unsafe path sequence")
    return tenant


def derive_tenant_master(master: bytes, tenant: str) -> bytes:
    """Derive a cryptographically isolated key namespace for one tenant.

    The reserved ``legacy`` tenant deliberately keeps the original master key
    so vaults created before v0.3 remain reversible without migration.
    """
    tenant = normalize_tenant_id(tenant)
    if tenant == LEGACY_TENANT:
        return master
    return hmac.new(
        subkey(master, "tenant-root-v1"), tenant.encode(), hashlib.sha256
    ).digest()


def tenant_vault_path(base_vault: Path, tenant: str) -> Path:
    """Resolve the isolated vault path for a tenant."""
    tenant = normalize_tenant_id(tenant)
    base_vault = Path(base_vault)
    if tenant == LEGACY_TENANT:
        return base_vault
    return base_vault.parent / "tenants" / tenant / base_vault.name

# ---------------------------------------------------------------- key / crypto


def load_key(path: Path) -> bytes:
    if not path.exists():
        sys.exit(f"[!] master key not found: {path}  (run: logmask init)")
    raw = base64.b64decode(path.read_text().strip())
    if len(raw) != 32:
        sys.exit("[!] invalid master key length (expected 32 bytes)")
    return raw


def subkey(master: bytes, label: str) -> bytes:
    return hmac.new(master, label.encode(), hashlib.sha256).digest()


def encrypt(master: bytes, plaintext: str) -> bytes:
    aes = AESGCM(subkey(master, "vault-enc"))
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, plaintext.encode(), None)


def decrypt(master: bytes, blob: bytes) -> str:
    aes = AESGCM(subkey(master, "vault-enc"))
    return aes.decrypt(blob[:12], blob[12:], None).decode()


def blind_index(master: bytes, kind: str, value: str) -> str:
    return hmac.new(
        subkey(master, "blind-idx"), f"{kind}|{value}".encode(), hashlib.sha256
    ).hexdigest()


def prf(master: bytes, kind: str, value: str, salt: int = 0) -> bytes:
    """Deterministic pseudo-random bytes driving the pseudonym."""
    msg = f"{kind}|{value}|{salt}".encode()
    return hmac.new(subkey(master, "pseudo"), msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------- vault

SCHEMA = """
CREATE TABLE IF NOT EXISTS mappings (
    bidx       TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    pseudonym  TEXT NOT NULL UNIQUE,
    orig_enc   BLOB NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pseudo ON mappings(pseudonym);
CREATE INDEX IF NOT EXISTS idx_kind   ON mappings(kind);

-- every column ever seen in a CSV export, with what we inferred and what we did
CREATE TABLE IF NOT EXISTS fields (
    source     TEXT NOT NULL,
    column     TEXT NOT NULL,
    kind       TEXT,
    action     TEXT NOT NULL,
    rows_seen  INTEGER NOT NULL DEFAULT 0,
    nonempty   INTEGER NOT NULL DEFAULT 0,
    masked     INTEGER NOT NULL DEFAULT 0,
    elided     INTEGER NOT NULL DEFAULT 0,
    failed     INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (source, column)
);
"""


class PseudonymSpaceExhausted(RuntimeError):
    """Lo spazio di pseudonimi di un kind e' finito: nessun valore libero.

    Non e' un errore da nascondere - riusare uno pseudonimo gia' assegnato
    fonderebbe due entita' diverse nello stesso token, corrompendo l'analisi in
    modo silenzioso - ma va detto in modo comprensibile.
    """


class Vault:
    def __init__(self, path: Path, master: bytes):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30.0)   # v0.20.2: attesa sul lock
        self.db.executescript(SCHEMA)
        self.master = master
        self._cache: dict[str, str] = {}
        # v0.23.4: quante volte si e' dovuto rinunciare al raggruppamento
        # per subnet perche' lo spazio delle reti sintetiche era pieno.
        self.subnet_overflow = 0
        self._owned: dict[str, bool] = {}       # v0.18.0: cache di owns()

    def owns(self, pseudonym: str) -> bool:
        """True se lo pseudonimo e' stato emesso da QUESTO vault (tenant).

        v0.18.0 - fail-closed: una stringa con la FORMA di uno pseudonimo non
        e' di per se' sicura (un host del cliente potrebbe chiamarsi davvero
        'host-abcd1234'). Passa invariata solo se la riconosciamo come nostra.
        Il confronto accetta anche la label breve di un nostro FQDN
        ("host-x" per "host-x.masked.local"), che e' una forma che emettiamo.
        """
        hit = self._owned.get(pseudonym)
        if hit is not None:
            return hit
        row = self.db.execute(
            "SELECT 1 FROM mappings WHERE pseudonym=? LIMIT 1", (pseudonym,)
        ).fetchone()
        if row is None and "." not in pseudonym:
            row = self.db.execute(
                "SELECT 1 FROM mappings WHERE pseudonym LIKE ? LIMIT 1",
                (pseudonym.replace("%", "").replace("_", "") + ".%",),
            ).fetchone()
        res = row is not None
        if len(self._owned) < 65536:
            self._owned[pseudonym] = res
        return res

    def get_or_create(self, kind: str, norm: str, raw: str, builder) -> str:
        bidx = blind_index(self.master, kind, norm)
        if bidx in self._cache:
            return self._cache[bidx]

        row = self.db.execute(
            "SELECT pseudonym FROM mappings WHERE bidx=?", (bidx,)
        ).fetchone()
        if row:
            self.db.execute("UPDATE mappings SET hits=hits+1 WHERE bidx=?", (bidx,))
            self._cache[bidx] = row[0]
            return row[0]

        # Deriva deterministica; il salt sale sulla (rara) collisione di
        # pseudonimo. v0.20.2: fra il controllo e l'INSERT un'ALTRA connessione
        # sullo stesso vault (CLI mentre gira l'app, oppure uvicorn --workers)
        # puo' inserire la stessa riga: l'INSERT falliva con IntegrityError e
        # l'anonimizzazione abortiva. I dati restavano integri, ma l'operazione
        # si interrompeva. Qui la corsa viene assorbita: se nel frattempo il
        # valore e' stato mappato da altri si riusa quel pseudonimo (identico,
        # perche' la derivazione e' deterministica); se invece a collidere e'
        # solo il pseudonimo si passa al salt successivo.
        # v0.23.4: 4096 tentativi, non 64. Il salt e' un sondaggio casuale
        # in una tabella: con 255 posti su 256 occupati, 64 sondaggi falliscono
        # nel 78% dei casi PUR ESSENDOCI un posto libero. Il costo si paga solo
        # quando lo spazio e' quasi pieno.
        for salt in range(4096):
            pseudo = builder(prf(self.master, kind, norm, salt))
            clash = self.db.execute(
                "SELECT 1 FROM mappings WHERE pseudonym=?", (pseudo,)
            ).fetchone()
            if clash:
                continue
            try:
                self.db.execute(
                    "INSERT INTO mappings(bidx,kind,pseudonym,orig_enc,hits)"
                    " VALUES(?,?,?,?,1)",
                    (bidx, kind, pseudo, encrypt(self.master, raw)),
                )
            except sqlite3.IntegrityError:
                row = self.db.execute(
                    "SELECT pseudonym FROM mappings WHERE bidx=?", (bidx,)
                ).fetchone()
                if row:                      # stesso valore, inserito da altri
                    self._cache[bidx] = row[0]
                    return row[0]
                continue                     # collisione vera: cambia salt
            self._cache[bidx] = pseudo
            return pseudo
        raise PseudonymSpaceExhausted(
            f"spazio pseudonimi esaurito per '{kind}': il vault di questo "
            "cliente ha gia' usato tutti i valori disponibili. Usa Reset vault "
            "oppure un tenant separato per questo materiale.")

    def register_alias(self, kind: str, norm: str, raw: str, pseudo: str) -> None:
        """Registra una mappatura secondaria (v0.20.3).

        Serve alla label breve di un FQDN: "web01" deve risolvere alla radice
        del token di "web01.corp.local". Prima ci pensava lo sweep leggendo
        tutto il vault; con la ricerca per blind index la label va resa
        trovabile qui. Se esiste gia' (stessa label in un altro dominio) non
        viene toccata: vince la prima, come faceva lo sweep precedente.
        """
        bidx = blind_index(self.master, kind, norm)
        if bidx in self._cache:
            return
        try:
            self.db.execute(
                "INSERT INTO mappings(bidx,kind,pseudonym,orig_enc,hits)"
                " VALUES(?,?,?,?,0)",
                (bidx, kind, pseudo, encrypt(self.master, raw)),
            )
        except sqlite3.IntegrityError:
            return                      # gia' presente: si tiene quella
        self._cache[bidx] = pseudo

    def reverse(self, pseudonym: str) -> str | None:
        row = self.db.execute(
            "SELECT orig_enc FROM mappings WHERE pseudonym=?", (pseudonym,)
        ).fetchone()
        return decrypt(self.master, row[0]) if row else None

    def lookup_original(self, kind: str, norm: str) -> str | None:
        row = self.db.execute(
            "SELECT pseudonym FROM mappings WHERE bidx=?",
            (blind_index(self.master, kind, norm),),
        ).fetchone()
        return row[0] if row else None

    def register_field(self, source: str, column: str, kind: str | None,
                       action: str, rows: int, nonempty: int, masked: int,
                       elided: int = 0, failed: int = 0):
        # In-place migration for vaults created by previous releases.
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(fields)")}
        if "elided" not in columns:
            self.db.execute(
                "ALTER TABLE fields ADD COLUMN elided INTEGER NOT NULL DEFAULT 0")
        if "failed" not in columns:
            self.db.execute(
                "ALTER TABLE fields ADD COLUMN failed INTEGER NOT NULL DEFAULT 0")
        self.db.execute(
            """INSERT INTO fields(source,column,kind,action,rows_seen,nonempty,
                                  masked,elided,failed)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(source,column) DO UPDATE SET
                 kind=excluded.kind, action=excluded.action,
                 rows_seen=rows_seen+excluded.rows_seen,
                 nonempty=nonempty+excluded.nonempty,
                 masked=masked+excluded.masked,
                 elided=elided+excluded.elided,
                 failed=failed+excluded.failed""",
            (source, column, kind, action, rows, nonempty, masked, elided, failed),
        )

    def fields_report(self, source: str | None = None) -> list[tuple]:
        q = ("SELECT source, column, kind, action, rows_seen, nonempty, masked, "
             "elided, failed FROM fields")
        args = ()
        if source:
            q += " WHERE source=?"
            args = (source,)
        return self.db.execute(q + " ORDER BY source, column", args).fetchall()

    def stats(self) -> list[tuple]:
        return self.db.execute(
            "SELECT kind, COUNT(*), SUM(hits) FROM mappings GROUP BY kind ORDER BY 2 DESC"
        ).fetchall()

    def commit(self):
        self.db.commit()


# ------------------------------------------------------------------ detectors

TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "biz", "info",
    "it", "eu", "de", "fr", "uk", "es", "nl", "ch", "us", "ru", "cn", "jp",
    "xyz", "top", "online", "site", "shop", "cloud", "dev", "app",
    "local", "lan", "corp", "internal", "intranet", "home", "localdomain",
}

RESERVED_HOSTS = {"localhost", "localhost.localdomain"}

# never treat these as an NT domain in DOMAIN\user matches
NOT_DOMAINS = {
    "users", "windows", "programdata", "program", "temp", "tmp", "appdata",
    "system32", "documents", "desktop", "downloads", "windows\\system32",
    "device", "harddiskvolume1", "harddiskvolume2", "sysvol", "netlogon",
    "files", "common", "roaming", "local", "locallow", "syswow64", "system",
    "microsoft", "google", "mozilla", "application", "applications", "public",
    # registry hive prefixes (v0.10.14): registry.key values start with
    # these; keep "HKLM\\SOFTWARE\\..." intact instead of reading the
    # leading hive as an NT domain.
    "hklm", "hkcu", "hku", "hkcr", "hkcc", "hkey_local_machine",
    "hkey_current_user", "hkey_users", "hkey_classes_root", "hkey_current_config",
}
NOT_DOMAINS |= {
    "nt authority", "nt service", "nt virtual machine", "window manager",
    "font driver host", "builtin", "workgroup", "iis apppool", "-",
}

# Well-known Windows accounts: identical on every system, identify nobody,
# and their visibility matters for analysis (Administrator, krbtgt, ...).
WELL_KNOWN_USERS = {
    "system", "local service", "network service", "anonymous logon",
    "administrator", "guest", "krbtgt", "defaultaccount",
    "wdagutilityaccount", "localsystem", "-", "n/a", "not_translated",
}
WELL_KNOWN_USER_PREFIXES = ("dwm-", "umfd-", "iusr", "healthmailbox")

# standard AD container CNs in distinguished names: not people
WELL_KNOWN_CN = {
    "users", "computers", "builtin", "system", "configuration", "schema",
    "program data", "foreignsecurityprincipals", "managed service accounts",
    "domain controllers", "keys", "tpm devices",
}

PATTERNS = {
    # Full URLs are handled atomically (v0.10.7 hardening): the host is always
    # pseudonymized regardless of TLD, opaque identifiers in the path are
    # vaulted and query parameters are elided unless they carry a safe shape
    # (timestamps, small integers, booleans).
    "url": r"(?P<url>\bhttps?://[^\s\"'<>\\^`{}|\[\]]+)",
    # v0.26.2: local part e dominio LIMITATI. Con "+" illimitato la scansione
    # e' quadratica: "user_user_user..." (nessun @) fa ritentare @ a ogni
    # posizione - 8000 caratteri = 11s, un file di un solo token blocca il
    # worker. RFC 5321 limita la local part a 64 caratteri e un'etichetta di
    # dominio a 63, quindi il limite non perde e-mail valide.
    "email": r"(?P<email>[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24})",
    # UPN / e-mail with a single-label domain (no public TLD): user@COMPANY,
    # jdoe@INTERNAL. Tried after "email" so real TLD addresses win.
    "upn": r"(?P<upn>(?<![\w.@+\-/])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z][A-Za-z0-9\-]{1,62})(?![\w.@\-])",
    # MAC must be tried before IPv6: 00:1a:2b:3c:4d:5e is a valid IPv6 candidate.
    "mac": r"(?P<mac>\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)",
    # full form, or any form containing "::" (so timestamps like 08:14:02 never match)
    "ipv6": (
        r"(?P<ipv6>(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4})*::"
        r"(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4})*)"
    ),
    "ipv4": r"(?P<ipv4>\b(?:\d{1,3}\.){3}\d{1,3}\b)",
    # C:\Users\jdoe\...  and  /home/jdoe/...  -> mask only the account name
    "userpath": (
        r"(?P<userpath>(?P<ppre>(?:[A-Za-z]:\\Users\\|\\Users\\|/home/|/Users/))"
        r"(?P<pusr>[A-Za-z0-9._\-$]{1,64}))"
    ),
    # DOMAIN\user, but never right after a path separator (avoids C:\Users\x)
    "winuser": (
        r"(?P<winuser>(?<![:\\/\w.])(?P<wdom>[A-Za-z][A-Za-z0-9\-]{1,20})"
        r"\\(?!S-1-\d)(?P<wusr>[A-Za-z0-9._\-$]{1,32})\b)"
    ),
    "userkv": (
        r"(?P<userkv>\b(?P<ukey>user|username|usr|account|user_name|"
        r"src_user|dst_user|samaccountname|account_name|login|uid)"
        r"(?P<usep>\s*[=:]\s*\"?)(?P<uval>[A-Za-z0-9._\-$]{2,32}))"
    ),
    # "workstation WKS-0421", "server srv01", "host: DB-03" in free text.
    # Value must carry a digit or hyphen: real machine names almost always
    # do, common words after these keys ("server error") almost never.
    "hostkv": (
        # (?=(...))(?P=...) emulates the possessive quantifier {2,62}+ so the
        # same pattern compiles on Python 3.10 too (possessive needs 3.11+).
        # Lookaheads are atomic in `re`: identical matching behaviour.
        r"(?P<hostkv>(?P<hkey>\b(?:host(?:name)?|workstation|computer"
        r"|server|machine|device)\b(?:\s*[:=]\s*|\s+))"
        r"(?P<hval>(?=(?P<hvatom>[A-Za-z][A-Za-z0-9\-]{2,62}))(?P=hvatom))(?!\.[A-Za-z0-9]))"
    ),
    # domain SIDs (S-1-5-21-...); well-known SIDs are handled in map_sid
    "sid": r"(?P<sid>\bS-1-5-21(?:-\d{1,12}){3,}\b)",
    # Trend Workbench / alert identifiers embedded in URLs and free text.
    "opaqueid": r"(?P<opaqueid>\bWB-[A-Za-z0-9][A-Za-z0-9\-]{6,80}\b)",
    # Labeled tenant identifiers in pasted Defender/Sentinel tables
    # ("WorkspaceName<TAB>ws-snt-gr-prd-it-001", "mdeDeviceId  d5917...").
    "wskv": (
        r"(?P<wskv>\b(?P<wkey>workspace\s?name|data\s?sources?|mde\s?device\s?id"
        r"|system\s?alert\s?id|detector\s?id|alert\s?type|azure\s?ad\s?device\s?id)"
        r"(?P<wsep>\s*[:=]\s*|\s+)(?P<wval>[A-Za-z0-9][A-Za-z0-9._\-]{3,120}))"
    ),
    # CN=<name> inside distinguished names (MemberName in 4728/4729 etc.)
    "cn": r"(?P<cn>\bCN=(?P<cnval>[^,=\r\n\\/]{2,64}))",
    "fqdn": r"(?P<fqdn>\b(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}\b)",
}

# Scalar UPN check (single-label domain, no TLD) for the structured cell masker.
UPN_RX = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z][A-Za-z0-9\-]{1,62}", re.IGNORECASE)
# E-mail + UPN together, to mask them inside fields kept in clear.
EMAIL_UPN_RX = re.compile(PATTERNS["email"] + "|" + PATTERNS["upn"], re.IGNORECASE)

# Priority order matters: first alternative that matches wins.
# "url" must come first so a URL is consumed atomically before the email/fqdn
# alternatives can nibble at its components.
ORDER = ["url", "email", "upn", "mac", "ipv6", "sid", "opaqueid", "wskv", "ipv4", "userpath",
         "winuser", "userkv", "hostkv", "cn", "fqdn"]


# --------------------------------------------------------------- url helpers

# Trailing prose punctuation that is almost never part of the URL itself.
URL_TRAIL_RX = re.compile(r"[.,;:!?'\")\]]+$")
# Long hex tokens inside URLs are document/alert identifiers, not IOC hashes:
# they are vaulted as reversible opaque pseudonyms (id-xxxx).
URL_HEX_ID_RX = re.compile(r"^[0-9A-Fa-f]{24,64}$")
URL_UUID_RX = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
URL_WB_RX = re.compile(r"^WB-[A-Za-z0-9][A-Za-z0-9\-]{6,80}$")
# Query/fragment values that may stay in clear: ISO-ish timestamps, epochs,
# booleans and tiny integers. Everything else is elided (fail-closed).
URL_SAFE_VALUE_RX = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}(?:[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"|\d{1,13}"
    r"|true|false|yes|no)$", re.IGNORECASE)
# Parameters whose value is ALWAYS elided, never pseudonymized: references,
# index names, tokens and redirect targets (spec v0.10.6: ref=, index=).
URL_SENSITIVE_KEYS = {
    "ref", "index", "token", "key", "sig", "signature", "apikey", "api_key",
    "access_token", "id_token", "refresh_token", "code", "state", "session",
    "sessionid", "session_id", "auth", "jwt", "password", "pwd", "secret",
    "redirect", "redirect_to", "redirect_uri", "return", "returnurl", "back",
    "next", "target", "url", "continue",
}


def build_master_regex(enabled: set[str]) -> re.Pattern:
    parts = [PATTERNS[k] for k in ORDER if k in enabled]
    return re.compile("|".join(parts), re.IGNORECASE)


def _client_term_pattern(term: str) -> str:
    """Word-boundary pattern for a customer name, tolerant to formatting.

    Tokens (spaces and camel-case boundaries) may be joined by up to four
    separator characters, so "Acme Calcio", "AcmeCalcio", "acme-calcio" and
    "Ente   Pubblico" (stray double/triple spaces) all match.
    """
    parts: list[str] = []
    for token in term.split():
        parts.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", token) or [token])
    joined = r"[\s\-_.]{0,4}".join(re.escape(part) for part in parts)
    return rf"(?<![A-Za-z0-9]){joined}(?![A-Za-z0-9])"


def build_client_terms_regex(terms: tuple[str, ...]):
    """Return (regex, {group_name: canonical_term}) or (None, {}).

    Each configured term gets its own named group so a match can be mapped
    back to the canonical name (hence a stable per-client token), whatever
    spacing/camel-case variant actually matched.
    """
    cleaned = [term for term in dict.fromkeys(t.strip() for t in terms) if term]
    if not cleaned:
        return None, {}
    # Longest first so "Acme Water Group" wins over a hypothetical "Acme".
    cleaned.sort(key=len, reverse=True)
    groups, mapping = [], {}
    for i, term in enumerate(cleaned):
        name = f"ct{i}"
        mapping[name] = term
        groups.append(f"(?P<{name}>{_client_term_pattern(term)})")
    return re.compile("|".join(groups), re.IGNORECASE), mapping


# ------------------------------------------------- bare hostname heuristic

# Machine names pasted in evidence tables carry no key ("hostName" sits in a
# header row far away): catch bare tokens that LOOK like infrastructure names.
# A token is masked only when an infra word anchors it on one end AND it either
# contains a digit or is infra-anchored on BOTH ends: "server-sso" and "dc01"
# match, prose like "web-based", "non-computer" or "left-outer" does not.
HOST_TOKEN_RX = re.compile(
    r"(?<![\w.@\-/\\])(?P<htok>[A-Za-z][A-Za-z0-9]{0,15}(?:[-_][A-Za-z0-9]{1,15}){1,4}"
    r"|[A-Za-z]{2,6}\d{1,3})"
    r"(?![\w.\-])"
)
INFRA_PREFIXES = {
    "srv", "server", "dc", "db", "sql", "ad", "vpn", "fw", "nas", "dmz",
    "mail", "smtp", "dns", "ntp", "dhcp", "hv", "esx", "esxi", "vc", "san",
    "ws", "pc", "vm", "host", "node", "gw", "proxy", "prx", "lb", "rdp",
    "app", "web", "wks", "nb", "lt", "kiosk", "cam", "print",
}
INFRA_SUFFIXES = {
    "sso", "dc", "srv", "db", "sql", "ad", "vpn", "fw", "nas", "dmz",
    "mgmt", "prod", "prd", "dev", "tst", "test", "bkp", "backup", "core",
    "edge", "mail", "smtp", "dns", "ntp", "dhcp", "file", "print", "hv",
    "esx", "vc", "san", "gw", "lb", "sso2",
}


_IOC_HEX_RX = re.compile(r"^[0-9a-fA-F]{16,}$")


def sweepable_host_original(value: str) -> bool:
    """v0.21.6: questo originale-host merita di essere sostituito nel testo?

    Il vault puo' contenere, per un mascheramento passato, valori che NON sono
    nomi macchina: parole di prodotto ("Windows", "Management"), nomi di
    processo ("WmiPrvSE.exe"). Da quel momento lo sweep li sostituiva in OGNI
    job successivo del tenant, corrompendo il testo tecnico in modo persistente
    e retroattivo ("Windows 10" -> "host-xxxx 10"). Qui si spazzano solo i
    valori che hanno la FORMA di un nome macchina:
      - contengono un punto (FQDN) ma non sono un nome file (.exe, .dll, ...);
      - oppure contengono una cifra o un trattino (WKS0421, srv-sso, DC01).
    Una parola puramente alfabetica non viene mai spazzata: e' il caso in cui
    il danno al testo supera il beneficio. Il mascheramento nel CAMPO dedicato
    resta invariato: cambia solo la sostituzione nel testo libero.
    """
    token = value.strip()
    if len(token) < 3:
        return False
    if "." in token:
        ext = token.rsplit(".", 1)[-1].lower()
        return ext not in FILE_EXTS          # nome file -> non e' un host
    return any(ch.isdigit() for ch in token) or "-" in token


def inside_opaque_blob(text: str, start: int, end: int) -> bool:
    """v0.21.5: il match e' dentro un blob opaco (base64, ID evento)?

    Un hostname puo' contenere solo lettere, cifre, punto e trattino: se il
    carattere adiacente al match e' "+", "/" o "=" siamo dentro un base64 o un
    identificativo opaco, non davanti a un nome macchina. Serve perche' le
    convenzioni host (host_terms) fanno match su SOTTOSTRINGHE: un glob come
    *DC* o WKS* combacia con pezzi casuali dentro un _id base64
    ("6bI/+VVDCxxxx==") e lo corrompe silenziosamente, rompendo dedup,
    correlazione evento-alert e ogni join su quella chiave.
    """
    # NB: "" in "qualsiasi" e' True in Python: il caso inizio/fine stringa va
    # trattato esplicitamente, altrimenti un hostname che occupa tutto il
    # valore non verrebbe mai mascherato.
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return bool(before and before in "+/=") or bool(after and after in "+/=")


def looks_like_ioc_hex(token: str) -> bool:
    """v0.21.3: un valore che e' una lunga stringa esadecimale e' un IOC
    (hash MD5/SHA1/SHA256, ID esadecimali), MAI un hostname. I match delle
    convenzioni host (host_terms) e le euristiche host non devono toccarlo:
    distruggerebbero proprio il valore su cui si fa pivot in un'indagine.
    Un glob "contains" mal configurato come *DC* altrimenti mangia ogni hash
    che contiene "dc"."""
    return bool(_IOC_HEX_RX.match(token.strip()))


def looks_like_bare_hostname(token: str) -> bool:
    if "." in token or len(token) < 4:
        return False
    parts = re.split(r"[-_]", token.lower())
    if len(parts) < 2:
        # compact form: infra prefix glued to a short number (dc01, esx3).
        m = re.fullmatch(r"([a-z]{2,6})(\d{1,3})", token.lower())
        return bool(m) and m.group(1) in INFRA_PREFIXES
    head, tail = parts[0], parts[-1]
    anchored_head = head in INFRA_PREFIXES
    anchored_tail = tail in INFRA_SUFFIXES or tail.isdigit()
    has_digit = any(ch.isdigit() for ch in token)
    if anchored_head and anchored_tail:
        return True
    return (anchored_head or tail in INFRA_SUFFIXES) and has_digit


def _host_term_pattern(term: str) -> str:
    """Naming convention -> regex. '*' is a wildcard (host characters) and may
    appear anywhere: "srv-*" (prefix), "*QNS" (suffix), "KDA*QNS" (middle),
    "*.WORKGROUP" / "*ZCORP.DOM" (domain suffix), or several at once. A term
    with no '*' is matched literally. Anchored to token boundaries so it never
    fires inside a longer word."""
    term = term.strip()
    wild = r"[A-Za-z0-9._\-]*"
    body = wild.join(re.escape(part) for part in term.split("*"))
    return rf"(?<![\w.@\-]){body}(?![\w.\-])"


# ---------------------------------------------- nomi di persona (v0.19.0)

BUNDLED_PERSONS_DIR = Path(__file__).resolve().parent / "persons"
USER_PERSONS_DIR = Path(os.environ.get(
    "LOGMASK_PERSONS_DIR",
    os.path.join(os.environ.get("LOGMASK_DATA", "data"), "persons")))

# Solo COPPIE "Nome Cognome" adiacenti e capitalizzate vengono mascherate.
# Un token singolo NON viene mai mascherato da queste liste: cognomi come
# "Costa"/"Monti"/"Riva" e nomi internazionali come "Will"/"May"/"Mark" sono
# anche parole comuni dei log, e mascherarli isolati distrugge il testo
# (date, verbi, brand nei phishing). Per il token singolo serve la lista
# aziendale person_terms, che contiene persone realmente esistenti.
PERSON_TOKEN_RX = re.compile(r"(?<![\w.@-])[A-Za-zÀ-ÿ'][A-Za-zÀ-ÿ']{2,39}(?![\w.@-])")
# Parola capitalizzata singola: le coppie si valutano con una finestra
# scorrevole, non con una regex che consuma due token per volta. Con la sub
# diretta una parola capitalizzata di troppo (inizio frase: "Contattare Giulia
# Ferrari") si mangiava il nome e la coppia vera non veniva piu' esaminata.
# v0.20.0: le parole si cercano SENZA vincolo di maiuscola (i log scrivono
# spesso "mario rossi" minuscolo) e i confini si verificano sul PERIMETRO della
# coppia, non sui singoli token: cosi' "mario.rossi" viene visto, mentre
# "mario.rossi@dominio" o "mario.rossi.corp.local" no (li gestiscono le regole
# e-mail/FQDN, che sono piu' specifiche).
# Segmento identita' nei percorsi OneDrive/SharePoint personali.
SHAREPOINT_IDENTITY_RX = re.compile(
    r"(?i)/(?:personal|users?)/(?P<who>[A-Za-z0-9][A-Za-z0-9._%+-]{2,80})(?=[/?#]|$)")

PERSON_WORD_RX = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ']{2,20}")
PERSON_SEPARATORS = (" ", ".", "_", "-")


def _person_sep_ok(sep: str) -> bool:
    """Separatore ammesso fra nome e cognome.

    v0.20.1: non basta il singolo spazio. Gli export reali usano tab (TSV),
    allineamenti a piu' spazi (tabelle) e la forma "Cognome, Nome" tipica di
    AD/LDAP. Restano esclusi il ritorno a capo (un nome non si spezza su due
    righe) e i separatori ripetuti come "..".
    """
    if not sep:
        return False
    if sep in (".", "_", "-"):
        return True
    stripped = sep.strip(" \t")
    return stripped in ("", ",")
# "m.rossi" / "m_rossi": il separatore e' gia' un segnale forte -> basta il
# cognome in person_terms. "mrossi" attaccato invece e' indistinguibile da una
# parola comune ("scosta" = s+costa, "amare" = a+mare), quindi richiede una
# parola di contesto subito prima.
PERSON_INITIAL_SEP_RX = re.compile(
    r"(?<![\w.@-])([A-Za-z])[._]([A-Za-zÀ-ÖØ-öø-ÿ']{3,20})(?![\w.@-])")
PERSON_INITIAL_CTX_RX = re.compile(
    r"(?i)(?<![\w.@-])(?:user|username|utente|account|login|uid|owner|assegnato a|da|by)"
    r"[\s:=]+([A-Za-z])([A-Za-zÀ-ÖØ-öø-ÿ']{3,20})(?![\w.@-])")

# Senza la maiuscola si perde un segnale forte, e le liste internazionali
# contengono parole funzionali inglesi (the, not, will, may, mark...) come
# nomi o cognomi. Queste non formano mai una coppia.
PERSON_STOPWORDS = frozenset("""
the a an and or not but for from with without into onto over under of to in on at by as is are was
were be been being do did does done has have had can could will would shall should may might must
this that these those there here when where which who whom whose what why how all any both each few
more most other some such no nor only own same so than too very just now then once again
new old top end run set get put add out off up down back next last first second third one two three
four five six seven eight nine ten il lo la i gli le un uno una del dello della dei degli delle al
allo alla ai agli alle dal dalla dai nel nella nei negli nelle sul sulla sui col con per tra fra
non piu meno molto poco tutto tutti tutte ogni qualche come quando dove chi che cosa perche se ma
anche ancora gia sempre mai sono stato stati stata state essere avere fatto fare visto viene vengono
deve devono puo possono alert alerts event events log logs host hosts user users file files path
rule rules policy action status severity source dest destination network traffic session account
service system security threat malware access denied allowed blocked failed success error warning
info debug scan detected match matched mark may will june july august april march chase hunter rose
grace faith joy hope king prince major victor
""".split())


def _person_boundary_ok(text: str, start: int, end: int) -> bool:
    """La coppia non deve essere incastonata in e-mail, FQDN o percorso."""
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    # Lo spazio e' un separatore VALIDO attorno alla coppia: a invalidarla sono
    # solo i caratteri che la incastonano in un token piu' grande (e-mail,
    # FQDN, percorso) o che indicano un terzo pezzo di un nome puntato.
    # NB: "" in "qualsiasi" e' True in Python, quindi il caso "inizio/fine
    # stringa" va trattato esplicitamente, altrimenti ogni coppia a bordo riga
    # verrebbe scartata.
    # v0.22.2: "/" e "\\" delimitano un SEGMENTO di percorso, quindi sono
    # confini validi per un nome persona: le cartelle profilo si chiamano
    # spesso "virgili_sara". Restano bloccanti @ . - _ , che indicano un
    # token piu' grande (e-mail, FQDN, nome composto).
    bad = "@._-"
    def _blocks(ch: str) -> bool:
        return bool(ch) and (ch.isalnum() or ch in bad)
    return not (_blocks(before) or _blocks(after))


# Un nome accettabile: solo lettere (con accenti), apostrofo o trattino
# interni. Scarta righe di prosa (disclaimer), markup HTML e binario che
# capitano in coda ai file scaricati dalla pagina invece che dal raw.
_PERSON_ENTRY_RX = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'\-]{1,39}$")


def _read_person_file(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    out = set()
    for line in lines:
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        token = token.split(",")[0].split(";")[0].split("\t")[0].strip()
        if _PERSON_ENTRY_RX.fullmatch(token):
            out.add(token.lower())
    return out


@lru_cache(maxsize=1)
def load_person_lists() -> tuple[frozenset, frozenset]:
    """(nomi, cognomi): liste bundled UNITE a quelle utente in data/persons/."""
    given, family = set(), set()
    for base in (BUNDLED_PERSONS_DIR, USER_PERSONS_DIR):
        try:
            if not Path(base).is_dir():
                continue
        except OSError:
            continue
        # match per prefisso: nomi*.txt / first_names*.txt / names*.txt ecc.,
        # cosi' i file scaricati mantengono il nome originale.
        for path in sorted(Path(base).glob("*.txt")):
            stem = path.name.lower()
            if stem.startswith(("nomi", "first_name", "firstname", "given", "names")):
                given |= _read_person_file(path)
            elif stem.startswith(("cognomi", "last_name", "lastname", "surname")):
                family |= _read_person_file(path)
    return frozenset(given), frozenset(family)


def build_host_terms_regex(terms: tuple[str, ...]) -> re.Pattern | None:
    cleaned = [t for t in dict.fromkeys(t.strip() for t in terms)
               if t and t.strip("*")]
    if not cleaned:
        return None
    cleaned.sort(key=len, reverse=True)
    return re.compile("|".join(_host_term_pattern(t) for t in cleaned), re.IGNORECASE)


# ---------------------------------------------------------------- pseudonyms


IP_MODES = {"none", "internal", "all"}
IPV4_PRIVATE_LOCAL = tuple(
    ipaddress.ip_network(net) for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",
        "100.64.0.0/10", "198.18.0.0/15",
    )
)
IPV6_PRIVATE_LOCAL = tuple(
    ipaddress.ip_network(net) for net in ("fc00::/7", "fe80::/10", "::1/128")
)


_FQDN_LIKE_RX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\.?$")


def build_host_label_index(values) -> "dict[str, set[str]]":
    """label-breve -> FQDN che la contengono (v0.18.0).

    Considera solo stringhe che sembrano hostname puntati; la label deve
    essere abbastanza lunga da non generare falsi accoppiamenti.
    """
    index: dict[str, set[str]] = {}
    for value in values:
        if not isinstance(value, str):
            continue
        tok = value.strip().rstrip(".")
        if not tok or len(tok) > 253 or " " in tok or "." not in tok:
            continue
        if not _FQDN_LIKE_RX.fullmatch(tok):
            continue
        label = tok.split(".", 1)[0].lower()
        if len(label) < 3 or label in RESERVED_HOSTS or PSEUDO_RX.fullmatch(label):
            continue
        index.setdefault(label, set()).add(tok.lower())
    return index


@lru_cache(maxsize=16384)
def is_internal_ip(value: str) -> bool:
    """Internal/non-public ranges: RFC1918/ULA, loopback, link-local, CGNAT and benchmark."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    networks = IPV4_PRIVATE_LOCAL if ip.version == 4 else IPV6_PRIVATE_LOCAL
    return any(ip in network for network in networks)


@dataclass
class Options:
    preserve_subnet: bool = False   # same /24 -> same pseudo /24
    keep_domain: bool = False       # keep the real email/fqdn domain
    keep_scope: bool = True         # private IPs stay private, public stay public
    ip_mode: str = "all"            # none | internal | all
    # v0.24.0: policy URL, speculare alla policy IP.
    #   none     -> l'URL resta com'e' (ma credenziali e token nella query
    #               vengono comunque trattati: sono segreti, non indirizzi)
    #   internal -> maschera solo gli host riconducibili al cliente (IP interni
    #               o delle reti tenant, FQDN gia' nel vault, nomi cliente);
    #               il resto dell'URL resta leggibile - e' il comportamento IOC
    #   all      -> mascheratura completa (default)
    url_mode: str = "all"           # none | internal | all
    dlp_policy: dict[str, str] | None = None
    # Customer/organization names that must ALWAYS be elided from free text.
    # Populated from configuration (env/file), never hardcoded in the sources.
    client_terms: tuple[str, ...] = ()
    # Public networks that BELONG to the tenant (egress/NAT ranges): they
    # identify the organization, so they are masked even with ip_mode=internal.
    # CIDR strings from configuration (env/file).
    tenant_networks: tuple[str, ...] = ()
    # Tenant hostname naming conventions ("srv-*", "XWS*", literal names):
    # bare machine names in pasted tables are masked reversibly as hosts.
    host_terms: tuple[str, ...] = ()
    person_terms: tuple[str, ...] = ()      # v0.19.0: persone REALI del tenant
    # How configured customer names are handled in free text:
    #   pseudonymize -> deterministic tenant-keyed token (CLIENT-xxxxxx),
    #                   the default; readable, clients stay distinct, and
    #                   irreversible (never vaulted).
    #   elide        -> [ELIDED] (previous behaviour).
    #   label        -> one fixed client_term_label for every client.
    client_term_mode: str = "pseudonymize"
    client_term_label: str = "[CLIENTE]"

    def __post_init__(self):
        if self.ip_mode not in IP_MODES:
            raise ValueError(f"invalid ip_mode: {self.ip_mode}")
        self.dlp_policy = normalize_dlp_policy(self.dlp_policy)
        self.client_terms = tuple(
            term.strip() for term in (self.client_terms or ()) if term and term.strip()
        )
        self.person_terms = tuple(
            term.strip() for term in (self.person_terms or ()) if term and term.strip()
        )
        self._person_set = frozenset(t.lower() for t in self.person_terms if len(t) >= 3)
        self.host_terms = tuple(
            term.strip() for term in (self.host_terms or ()) if term and term.strip()
        )
        self.url_mode = (self.url_mode or "all").strip().lower()
        if self.url_mode not in ("none", "internal", "all"):
            self.url_mode = "all"
        self.client_term_mode = (self.client_term_mode or "pseudonymize").strip().lower()
        if self.client_term_mode not in ("pseudonymize", "elide", "label"):
            self.client_term_mode = "pseudonymize"
        parsed = []
        for net in (self.tenant_networks or ()):
            net = str(net).strip()
            if not net:
                continue
            try:
                parsed.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                continue
        self._tenant_nets = tuple(parsed)

    def is_tenant_ip(self, value: str) -> bool:
        if not self._tenant_nets:
            return False
        cache = self.__dict__.setdefault("_tenant_ip_cache", {})   # v0.17.0
        hit = cache.get(value)
        if hit is not None:
            return hit
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError:
            cache[value] = False
            return False
        res = any(ip in net for net in self._tenant_nets if net.version == ip.version)
        if len(cache) < 16384:
            cache[value] = res
        return res

    def should_anonymize_ip(self, value: str) -> bool:
        if self.ip_mode == "none":
            return False
        if self.ip_mode == "internal":
            return is_internal_ip(value) or self.is_tenant_ip(value)
        return True


def _pseudo_ipv4_scope_octet(original: str, opt: Options) -> int:
    """Return the benchmark-space second octet for a pseudonymized IPv4.

    v0.10.2 moved synthetic IPv4s away from tenant-realistic ranges
    such as 10.0.0.0/8 and 100.64.0.0/10. The default output now uses
    198.18.0.0/15, reserved for benchmarking (RFC 2544/RFC 6890) and not
    expected to collide with normal production/private customer networks.

    keep_scope=True keeps a readable distinction: 198.18/16 for internal
    sources and 198.19/16 for public/external sources. keep_scope=False uses
    198.19/16 for all IPv4 pseudonyms.
    """
    if opt.keep_scope and is_internal_ip(original):
        return 18
    return 19


def pseudo_ipv4(seed: bytes, original: str, opt: Options) -> str:
    try:
        ipaddress.IPv4Address(original)
    except ValueError:
        return original
    scope = _pseudo_ipv4_scope_octet(original, opt)
    # v0.23.4: seed[1] usa tutti i 256 valori. Con "or 1" gli indirizzi
    # disponibili erano 65.280 invece di 65.536, e soprattutto la stessa scelta
    # nel builder dell'ottetto host lasciava 255 posti per 256 valori possibili:
    # un export che toccava tutti gli host di una subnet falliva per forza.
    return f"198.{scope}.{seed[0]}.{seed[1]}"


def pseudo_ipv4_subnet(vault: Vault, original: str, opt: Options) -> str:
    """Map network and host parts separately so /24 grouping survives."""
    try:
        ipaddress.IPv4Address(original)
    except ValueError:
        return original
    net = ".".join(original.split(".")[:3])
    host = original.split(".")[3]

    def net_builder(seed: bytes) -> str:
        scope = _pseudo_ipv4_scope_octet(original, opt)
        return f"198.{scope}.{seed[0]}"

    try:
        pnet = vault.get_or_create("ipv4net", net, net, net_builder)
    except PseudonymSpaceExhausted:
        # v0.23.4: "preserva subnet" assegna una /24 sintetica a ogni /24 reale,
        # e in 198.18.0.0/15 ce ne stanno 256 per ambito: e' il limite della
        # modalita', non un guasto. Si dice chiaramente cosa fare invece di
        # ripiegare su un altro schema, che rischierebbe di assegnare lo stesso
        # indirizzo sintetico a due indirizzi reali diversi - una fusione
        # silenziosa di due macchine, molto peggio di un errore esplicito.
        vault.subnet_overflow += 1
        raise PseudonymSpaceExhausted(
            "«Preserva subnet» puo' rappresentare al massimo 256 reti /24 per "
            "ambito e questo cliente le ha gia' usate tutte. Disattiva "
            "«preserva subnet» per questo export, oppure usa un tenant "
            "separato.") from None
    phost = vault.get_or_create("ipv4host", host, host, lambda s: str(s[0]))
    return f"{pnet}.{phost}"


def pseudo_ipv6(seed: bytes, original: str, opt: Options) -> str:
    body = seed[:6].hex()
    return f"fd00:{body[0:4]}:{body[4:8]}:{body[8:12]}::1"


def pseudo_mac(seed: bytes, original: str, opt: Options) -> str:
    # 0x02 = locally administered, unicast -> clearly synthetic
    octets = [0x02] + list(seed[:5])
    return ":".join(f"{o:02x}" for o in octets)


def _tag(seed: bytes, n: int = 8) -> str:
    return base64.b32encode(seed).decode().lower().rstrip("=")[:n]


def pseudo_email(seed: bytes, original: str, opt: Options) -> str:
    local, _, domain = original.partition("@")
    dom = domain if opt.keep_domain else f"{_tag(seed[8:], 6)}.masked"
    return f"usr-{_tag(seed)}@{dom}"


def pseudo_fqdn(seed: bytes, original: str, opt: Options) -> str:
    if "." not in original:               # short/NetBIOS name: keep it short
        return f"host-{_tag(seed)}"
    labels = original.split(".")
    if opt.keep_domain and len(labels) > 2:
        return f"host-{_tag(seed)}." + ".".join(labels[-2:])
    return f"host-{_tag(seed)}.masked.local"


def pseudo_user(seed: bytes, original: str, opt: Options) -> str:
    return f"usr-{_tag(seed)}"


def pseudo_opaque(seed: bytes, original: str, opt: Options) -> str:
    """Reversible pseudonym for GUIDs and vendor-specific opaque identifiers."""
    return f"id-{_tag(seed, 12)}"


def pseudo_taxid(seed: bytes, original: str, opt: Options) -> str:
    return f"cf-{_tag(seed, 12)}"


def pseudo_iban(seed: bytes, original: str, opt: Options) -> str:
    return f"iban-{_tag(seed, 12)}"


def pseudo_phone(seed: bytes, original: str, opt: Options) -> str:
    return f"tel-{_tag(seed, 12)}"


def pseudo_person(seed: bytes, original: str, opt: Options) -> str:
    return f"person-{_tag(seed, 12)}"


def pseudo_address(seed: bytes, original: str, opt: Options) -> str:
    return f"addr-{_tag(seed, 12)}"


def pseudo_vat(seed: bytes, original: str, opt: Options) -> str:
    return f"vat-{_tag(seed, 12)}"


def pseudo_cloud(seed: bytes, original: str, opt: Options) -> str:
    return f"cloud-{_tag(seed, 12)}"


def pseudo_secret(seed: bytes, original: str, opt: Options) -> str:
    return f"secret-{_tag(seed, 12)}"


def pseudo_domain(seed: bytes, original: str, opt: Options) -> str:
    # 40-bit tag avoids the tiny 100-value DOM00..DOM99 space used by old releases.
    return f"DOM-{_tag(seed)}"


def pseudo_siddomain(seed: bytes, original: str, opt: Options) -> str:
    a = int.from_bytes(seed[0:4], "big") or 1
    b = int.from_bytes(seed[4:8], "big") or 1
    c = int.from_bytes(seed[8:12], "big") or 1
    return f"S-1-5-21-{a}-{b}-{c}"


BUILDERS = {
    "ipv4": pseudo_ipv4,
    "ipv6": pseudo_ipv6,
    "mac": pseudo_mac,
    "email": pseudo_email,
    "fqdn": pseudo_fqdn,
    "user": pseudo_user,
    "opaque": pseudo_opaque,
    "taxid": pseudo_taxid,
    "iban": pseudo_iban,
    "phone": pseudo_phone,
    "person": pseudo_person,
    "address": pseudo_address,
    "vat": pseudo_vat,
    "cloud": pseudo_cloud,
    "secret": pseudo_secret,
    "windomain": pseudo_domain,
    "siddomain": pseudo_siddomain,
}


# ------------------------------------------------------------------- engine


def valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def valid_ipv6(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False) if "/" in s else ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


class Anonymizer:
    def __init__(self, vault: Vault, enabled: set[str], opt: Options):
        self.vault = vault
        self.opt = opt
        self.rx = build_master_regex(enabled)
        self.client_rx, self.client_group_terms = build_client_terms_regex(opt.client_terms)
        self.host_rx = build_host_terms_regex(opt.host_terms)
        self.counts: Counter = Counter()
        self.skipped: Counter = Counter()
        self.policy_kept: Counter = Counter()
        self.dlp_counts: Counter = Counter()
        self.dlp_actions: Counter = Counter()
        self.dlp_blocked: list[dict[str, object]] = []
        self.dlp_samples: list[str] = []
        # Passthrough caches: values that a keep-cell (DLP+sweeps) or a
        # text-cell (process) leaves UNCHANGED. Low-cardinality columns
        # (enums, timestamps, numbers) then cost O(1) on repeats. Only
        # unchanged values are cached, so per-cell stats stay correct.
        self._pt_keep: set = set()
        self._pt_text: set = set()

    def set_host_label_index(self, index: "dict[str, set[str]]") -> None:
        """v0.18.0: mappa label-breve -> insieme di FQDN visti nel documento.

        Serve a dare allo stesso host UN SOLO token quando compare sia come
        nome corto ("web01") sia come FQDN ("web01.corp.local"). Se la stessa
        label esiste in piu' domini l'informazione per decidere NON e' nel
        dato: in quel caso non si indovina, il nome corto prende un token
        proprio e il caso viene contato come ambiguo.
        """
        self._host_labels = index or {}

    def _resolve_bare_host(self, norm: str) -> str | None:
        """Radice del token dell'FQDN corrispondente, se non ambiguo."""
        idx = getattr(self, "_host_labels", None)
        if not idx:
            return None
        fqdns = idx.get(norm)
        if not fqdns:
            return None
        if len(fqdns) > 1:
            self.counts["host_label_ambiguous"] += 1
            return None
        full = next(iter(fqdns))
        return self._map("fqdn", full).split(".", 1)[0]

    def _own_pseudo(self, token: str) -> bool:
        """v0.18.0: forma di pseudonimo E davvero emesso da questo vault."""
        return bool(PSEUDO_RX.fullmatch(token)) and self.vault.owns(token)

    def _keep_ip_by_policy(self, kind: str) -> None:
        self.policy_kept[kind] += 1
        self.skipped[f"{kind}_policy"] += 1

    def _secret_token(self, value: str) -> str:
        """v0.23.0: token deterministico e tenant-keyed per un segreto, MAI
        scritto nel vault. Stesso segreto -> stesso token (le occorrenze
        restano correlabili), ma il valore non e' recuperabile: uno strumento
        di anonimizzazione non deve diventare un deposito di password e chiavi
        private dei clienti."""
        return f"secret-{_tag(prf(self.vault.master, 'secret', value.strip()), 12)}"

    def _map(self, kind: str, raw: str, norm: str | None = None) -> str:
        if kind == "secret":
            return self._secret_token(raw)
        # v0.18.0: se il valore e' gia' un NOSTRO pseudonimo lo lasciamo com'e'
        # (ri-anonimizzare un export gia' trattato non deve cambiare i token);
        # se ha solo la forma di uno pseudonimo ma non e' nostro, prosegue e
        # viene mascherato come qualsiasi altro dato (fail-closed).
        if PSEUDO_RX.fullmatch(raw) and self.vault.owns(raw):
            return raw
        norm = (norm or raw).lower()
        if kind == "fqdn" and "." not in norm:          # v0.18.0: nome corto
            linked = self._resolve_bare_host(norm)
            if linked:
                return linked
        if kind == "email" and not self.opt.keep_domain and "@" in norm:
            # The masked domain is derived from the DOMAIN alone, so every
            # address at the same domain shares one constant masked domain
            # (e.g. *@contoso.com -> *@abc123.masked); the local part stays
            # unique per address. The whole e-mail is still vaulted (reversible).
            _local, _, dom = norm.partition("@")
            if dom:
                dtag = _tag(prf(self.vault.master, "emaildomain", dom), 6) + ".masked"
                pseudo = self.vault.get_or_create(
                    kind, norm, raw, lambda seed: f"usr-{_tag(seed)}@{dtag}")
                self.counts[kind] += 1
                return pseudo
        builder = lambda seed: BUILDERS[kind](seed, norm, self.opt)  # noqa: E731
        pseudo = self.vault.get_or_create(kind, norm, raw, builder)
        if kind == "fqdn" and "." in norm and "." in pseudo:
            label = norm.split(".", 1)[0]
            root = pseudo.split(".", 1)[0]
            if len(label) >= 4 and label not in RESERVED_HOSTS and label != root:
                self.vault.register_alias("fqdn", label, label, root)
        self.counts[kind] += 1
        return pseudo

    # ---- kind-aware mappers with SOC-sane skip rules ----------------------

    def map_user(self, raw: str) -> str:
        v = raw.strip()
        lv = v.lower()
        if not v or lv in WELL_KNOWN_USERS or lv.startswith(WELL_KNOWN_USER_PREFIXES):
            self.skipped["user"] += 1
            return raw
        if v.endswith("$") and len(v) > 2:
            # machine account: same pseudonym as the hostname it belongs to
            return self._map("fqdn", v[:-1]) + "$"
        return self._map("user", v)

    def map_windomain(self, raw: str) -> str:
        if raw.strip().lower() in NOT_DOMAINS:
            self.skipped["windomain"] += 1
            return raw
        return self._map("windomain", raw)

    def map_sid(self, raw: str) -> str:
        v = raw.strip()
        if not v.startswith("S-1-5-21-"):   # well-known / non-domain SIDs stay
            self.skipped["sid"] += 1
            return raw
        prefix, _, rid = v.rpartition("-")
        if not rid.isdigit():
            return raw
        # domain part vaulted, RID in clear: 500/krbtgt/user-RID stay analyzable
        return self._map("siddomain", prefix) + f"-{rid}"

    # ---- URL hardening (v0.10.7, spec v0.10.6) ----------------------------

    def _url_host(self, host: str) -> str:
        """Pseudonymize the authority part of a URL. Unlike free-text FQDN
        matching this is not gated on public TLDs: internal hostnames such as
        neteye4.example.local must be masked too."""
        if not host:
            return host
        if host.startswith("[") and host.endswith("]"):      # bracketed IPv6
            inner = host[1:-1]
            if valid_ipv6(inner):
                if not self.opt.should_anonymize_ip(inner):
                    self._keep_ip_by_policy("ipv6")
                    return host
                return "[" + self._map("ipv6", inner) + "]"
            return host
        if valid_ipv4(host):
            if not self.opt.should_anonymize_ip(host):
                self._keep_ip_by_policy("ipv4")
                return host
            if self.opt.preserve_subnet:
                self.counts["ipv4"] += 1
                return pseudo_ipv4_subnet(self.vault, host, self.opt)
            return self._map("ipv4", host)
        lowered = host.lower()
        if lowered in RESERVED_HOSTS or ".masked" in lowered or PSEUDO_RX.fullmatch(host):
            self.skipped["url_host"] += 1
            return host
        return self._map("fqdn", host)

    def _url_segment(self, segment: str) -> str:
        if URL_WB_RX.fullmatch(segment) or URL_HEX_ID_RX.fullmatch(segment) \
                or URL_UUID_RX.fullmatch(segment):
            return self._map("opaque", segment)
        return segment

    def _url_value(self, value: str) -> str:
        """Fail-closed policy for query/fragment values."""
        if value == "" or value == ELIDED or PSEUDO_RX.fullmatch(value):
            return value
        if URL_WB_RX.fullmatch(value) or URL_HEX_ID_RX.fullmatch(value) \
                or URL_UUID_RX.fullmatch(value):
            return self._map("opaque", value)
        if URL_SAFE_VALUE_RX.fullmatch(value):
            return value
        self.counts["url_query_elided"] += 1
        self.dlp_actions["redact"] += 1
        return ELIDED

    def _url_params(self, query: str, *, ioc: bool = False) -> str:
        out_params = []
        for param in query.split("&"):
            key, eq, value = param.partition("=")
            if eq:
                if key.lower() in URL_SENSITIVE_KEYS and value not in ("", ELIDED):
                    self.counts["url_query_elided"] += 1
                    self.dlp_actions["redact"] += 1
                    out_params.append(key + "=" + ELIDED)
                elif ioc:
                    # IOC mode: the query is part of the indicator, keep it.
                    out_params.append(param)
                else:
                    out_params.append(key + "=" + self._url_value(value))
            elif key and not ioc:
                out_params.append(self._url_value(key))
            else:
                out_params.append(param)
        return "&".join(out_params)

    def _anonymize_url_ioc(self, url: str) -> str:
        """IOC fields (Malicious URLs, Indicator, RemoteUrl): the URL itself is
        detection content and stays readable. Only token-like query values are
        elided, and hosts that are demonstrably the tenant's (internal or
        tenant-network IPs, vault-known FQDNs, client names) are still masked."""
        trail = ""
        m = URL_TRAIL_RX.search(url)
        if m:
            trail = m.group(0)
            url = url[:m.start()]
        scheme, sep, rest = url.partition("://")
        if not sep:
            return url + trail
        authority, slash, tail = rest.partition("/")
        if not slash:
            for cut in ("?", "#"):
                if cut in authority:
                    authority, _, extra = authority.partition(cut)
                    tail = cut + extra
                    break
        creds = ""
        if "@" in authority:
            _, _, authority = authority.rpartition("@")
            creds = ELIDED + "@"
            self.dlp_actions["redact"] += 1
        host, port = authority, ""
        if authority.startswith("[") and "]" in authority:
            host, _, port_part = authority.partition("]")
            host += "]"
            port = port_part
        elif authority.count(":") == 1:
            host, _, port_part = authority.partition(":")
            port = ":" + port_part if port_part else ""
        bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        masked_host = host
        if valid_ipv4(bare) or valid_ipv6(bare):
            if is_internal_ip(bare) or self.opt.is_tenant_ip(bare):
                masked_host = self._url_host(host)
        elif self.vault.lookup_original("fqdn", bare.lower()) \
                or (self.client_rx and self.client_rx.search(bare)):
            masked_host = self._url_host(host)

        if slash:
            tail = "/" + tail
        path, query, fragment = tail, "", ""
        if "#" in path:
            path, _, fragment = path.partition("#")
        if "?" in path:
            path, _, query = path.partition("?")
        if query:
            query = "?" + self._url_params(query, ioc=True)
        if fragment:
            fragment = "#" + fragment
        self.counts["url_ioc"] += 1
        return scheme + "://" + creds + masked_host + port + path + query + fragment + trail

    def _url_keep(self, url: str) -> str:
        """url_mode='none': l'URL resta com'e'. Solo credenziali userinfo e
        valori di query dichiaratamente sensibili (token=, password=, ...)
        vengono trattati: sono segreti, non indirizzi, e la policy URL non e'
        un permesso a farli uscire."""
        trail = ""
        m = URL_TRAIL_RX.search(url)
        if m:
            trail = m.group(0)
            url = url[:m.start()]
        scheme, sep, rest = url.partition("://")
        if not sep:
            return url + trail
        authority, slash, tail = rest.partition("/")
        if not slash:
            for cut in ("?", "#"):
                if cut in authority:
                    authority, _, extra = authority.partition(cut)
                    tail = cut + extra
                    break
        creds = ""
        if "@" in authority:
            _, _, authority = authority.rpartition("@")
            creds = ELIDED + "@"
            self.dlp_actions["redact"] += 1
        if slash:
            tail = "/" + tail
        path, query, fragment = tail, "", ""
        if "#" in path:
            path, _, fragment = path.partition("#")
            fragment = "#" + fragment
        if "?" in path:
            path, _, query = path.partition("?")
            out_params = []
            for param in query.split("&"):
                key, eq, value = param.partition("=")
                if eq and key.lower() in URL_SENSITIVE_KEYS and value not in ("", ELIDED):
                    self.counts["url_query_elided"] += 1
                    self.dlp_actions["redact"] += 1
                    out_params.append(key + "=" + ELIDED)
                else:
                    out_params.append(param)
            query = "?" + "&".join(out_params)
        self.counts["url_kept"] += 1
        return scheme + "://" + creds + authority + path + query + fragment + trail

    def _anonymize_url(self, url: str) -> str:
        # v0.24.0: il campo IOC (Malicious URL, Indicator) vince sulla policy
        # globale: quel valore e' contenuto di detection e resta leggibile.
        if getattr(self, "_url_ioc", False):
            return self._anonymize_url_ioc(url)
        mode = getattr(self.opt, "url_mode", "all")
        if mode == "none":
            return self._url_keep(url)
        if mode == "internal":
            return self._anonymize_url_ioc(url)
        trail = ""
        m = URL_TRAIL_RX.search(url)
        if m:
            trail = m.group(0)
            url = url[:m.start()]
        scheme, sep, rest = url.partition("://")
        if not sep:
            return url + trail
        # authority [userinfo@]host[:port]
        authority, slash, tail = rest.partition("/")
        if not slash:
            for cut in ("?", "#"):
                if cut in authority:
                    authority, _, extra = authority.partition(cut)
                    tail = cut + extra
                    break
        creds = ""
        if "@" in authority:
            _, _, authority = authority.rpartition("@")
            creds = ELIDED + "@"
            self.dlp_actions["redact"] += 1
        host, port = authority, ""
        if authority.startswith("["):                        # [v6]:port
            if "]" in authority:
                host, _, port_part = authority.partition("]")
                host += "]"
                port = port_part
        elif authority.count(":") == 1:
            host, _, port_part = authority.partition(":")
            port = ":" + port_part if port_part else ""
        masked_host = self._url_host(host)

        path, query, fragment = "", "", ""
        if slash:
            tail = "/" + tail
        if "#" in tail:
            tail, _, fragment = tail.partition("#")
        if "?" in tail:
            path, _, query = tail.partition("?")
        else:
            path = tail

        if path:
            path = "/".join(self._url_segment(seg) for seg in path.split("/"))
        if query:
            query = "?" + self._url_params(query)
        if fragment:
            # SPA routes (#/app/workbench/alerts/WB-...?ref=x) behave like a
            # nested URL: route segments keep their shape with identifiers
            # vaulted, the fragment's own query part is elided fail-closed.
            frag_path, frag_qmark, frag_query = fragment.partition("?")
            if "/" in frag_path:
                frag_path = "/".join(self._url_segment(seg) for seg in frag_path.split("/"))
            elif "=" in frag_path:
                frag_path = self._url_params(frag_path)
            elif frag_path:
                frag_path = self._url_value(frag_path)
            fragment = "#" + frag_path
            if frag_qmark:
                fragment += "?" + self._url_params(frag_query)

        self.counts["url"] += 1
        return scheme + "://" + creds + masked_host + port + path + query + fragment + trail

    def _sub(self, m: re.Match) -> str:
        gd = m.groupdict()

        if gd.get("url"):
            return self._anonymize_url(gd["url"])

        if gd.get("email"):
            return self._map("email", gd["email"])

        if gd.get("upn"):
            return self._map_upn(gd["upn"])

        if gd.get("ipv4"):
            v = gd["ipv4"]
            if not valid_ipv4(v):
                self.skipped["ipv4"] += 1
                return v
            if not self.opt.should_anonymize_ip(v):
                self._keep_ip_by_policy("ipv4")
                return v
            if self.opt.preserve_subnet:
                self.counts["ipv4"] += 1
                return pseudo_ipv4_subnet(self.vault, v, self.opt)
            return self._map("ipv4", v)

        if gd.get("ipv6"):
            v = gd["ipv6"]
            if v == "::" or not valid_ipv6(v):
                self.skipped["ipv6"] += 1
                return v
            if not self.opt.should_anonymize_ip(v):
                self._keep_ip_by_policy("ipv6")
                return v
            return self._map("ipv6", v)

        if gd.get("mac"):
            v = gd["mac"]
            return self._map("mac", v, norm=v.replace("-", ":").lower())

        if gd.get("sid"):
            return self.map_sid(gd["sid"])

        if gd.get("opaqueid"):
            return self._map("opaque", gd["opaqueid"])

        if gd.get("wskv"):
            return gd["wkey"] + gd["wsep"] + self._map("opaque", gd["wval"])

        if gd.get("userpath"):
            return gd["ppre"] + self.map_user(gd["pusr"])

        if gd.get("winuser"):
            if gd["wdom"].lower() in NOT_DOMAINS:
                self.skipped["winuser"] += 1
                return gd["winuser"]
            return f"{self.map_windomain(gd['wdom'])}\\{self.map_user(gd['wusr'])}"

        if gd.get("userkv"):
            return gd["ukey"] + gd["usep"] + self.map_user(gd["uval"])

        if gd.get("hostkv"):
            val = gd["hval"]
            if not re.search(r"[\d\-]", val) or PSEUDO_RX.fullmatch(val) \
                    or val.lower() in RESERVED_HOSTS:
                self.skipped["hostkv"] += 1
                return gd["hostkv"]
            return gd["hkey"] + self._map("fqdn", val)

        if gd.get("cn"):
            val = gd["cnval"]
            if val.strip().lower() in WELL_KNOWN_CN:
                self.skipped["cn"] += 1
                return gd["cn"]
            return "CN=" + self.map_user(val)

        if gd.get("fqdn"):
            v = gd["fqdn"]
            tld = v.rsplit(".", 1)[-1].lower()
            if v.lower() in RESERVED_HOSTS or tld not in TLDS:
                self.skipped["fqdn"] += 1
                return v
            return self._map("fqdn", v)

        return m.group(0)

    def process_dlp(self, text: str) -> str:
        result = apply_dlp(
            text,
            self.opt.dlp_policy,
            lambda kind, value: self._map(kind, value),
            is_pseudonym=lambda value: bool(PSEUDO_RX.fullmatch(value)),
            elided_token=ELIDED,
        )
        self.dlp_counts.update(result.counts)
        self.dlp_actions.update(result.actions)
        for finding in result.blocked:
            self.dlp_blocked.append({
                "kind": finding.category,
                "start": finding.start,
                "end": finding.end,
                "value": finding.value,
                "detector": finding.detector,
            })
        for sample in result.samples:
            if len(self.dlp_samples) < 10 and sample not in self.dlp_samples:
                self.dlp_samples.append(sample)
        return result.output

    def process_dlp_field(self, field_name: str, value: str) -> str:
        key = (field_name, value)
        if key in self._pt_keep:
            return value
        before_blocked = len(self.dlp_blocked)
        result = apply_dlp_field(
            field_name,
            value,
            self.opt.dlp_policy,
            lambda kind, raw: self._map(kind, raw),
            is_pseudonym=lambda raw: bool(PSEUDO_RX.fullmatch(raw)),
            elided_token=ELIDED,
        )
        self.dlp_counts.update(result.counts)
        self.dlp_actions.update(result.actions)
        for finding in result.blocked:
            self.dlp_blocked.append({
                "kind": finding.category,
                "start": finding.start,
                "end": finding.end,
                "value": finding.value,
                "detector": finding.detector,
                "field": field_name,
            })
        for sample in result.samples:
            if len(self.dlp_samples) < 10 and sample not in self.dlp_samples:
                self.dlp_samples.append(sample)
        # A field kept in clear still gets the operator denylists: configured
        # tenant host naming conventions (reversible host pseudonym) and client
        # names (generic token). Text/free-text fields get these via process().
        out = self._sweep_emails(result.output)
        out = self._sweep_host_terms(out)
        out = self._mask_client_terms(out)
        if out == value and len(self.dlp_blocked) == before_blocked \
                and len(self._pt_keep) < 200000:
            self._pt_keep.add(key)
        return out

    def _sweep_emails(self, text: str) -> str:
        """Mask e-mail addresses and UPNs (user@COMPANY) inside a value kept in
        clear, so an identity column classified 'keep' does not leak them."""
        if "@" not in text:
            return text
        def _hit(m: re.Match) -> str:
            if m.group("email"):
                return self._map("email", m.group("email"))
            return self._map_upn(m.group("upn"))
        return EMAIL_UPN_RX.sub(_hit, text)

    def _upn_domain(self, dom: str) -> str:
        """Mask the domain label of a UPN (single label, no TLD): a configured
        client name becomes its generic token, any other label a masked host."""
        if self.client_rx is not None:
            m = self.client_rx.fullmatch(dom)
            if m is not None and m.lastgroup:
                term = self.client_group_terms.get(m.lastgroup, dom)
                return self._client_token(term)
        return self._map("fqdn", dom)

    def _map_upn(self, value: str) -> str:
        """user@single-label (UPN without a public TLD, e.g. user@COMPANY): the
        local part is masked as a user and the domain per _upn_domain, so the
        value is fully pseudonymized instead of leaking the local part or being
        elided in Safe mode."""
        local, _, dom = value.partition("@")
        return f"{self.map_user(local)}@{self._upn_domain(dom)}"

    def _client_token(self, term: str) -> str:
        """Deterministic, tenant-keyed, IRREVERSIBLE generic token for a client
        name. Same client -> same token within a tenant; different tenants get
        different tokens; never vaulted, so the real name cannot be recovered
        and the known-name list cannot be brute-forced without the tenant key."""
        seed = prf(self.vault.master, "client", term.strip().lower())
        return f"CLIENT-{_tag(seed, 6)}"

    def _mask_client_terms(self, text: str) -> str:
        """Final sweep: configured customer names never leak from free text,
        whatever survived the pattern and DLP passes. By default each name is
        replaced with a generic pseudonym (CLIENT-xxxxxx) so the text stays
        readable and clients stay distinguishable but unidentifiable; modes
        'elide' ([ELIDED]) and 'label' (a single fixed label) are also
        available. Always irreversible (the vault never stores the name)."""
        if not self.client_rx:
            return text
        mode = getattr(self.opt, "client_term_mode", "pseudonymize")

        def _hit(match: re.Match) -> str:
            self.counts["client_term"] += 1
            if mode == "elide":
                self.dlp_actions["redact"] += 1
                repl = ELIDED
            elif mode == "label":
                repl = self.opt.client_term_label
            else:
                term = self.client_group_terms.get(match.lastgroup, match.group(0))
                repl = self._client_token(term)
            tag = f"CLIENT:{mode}"
            if tag not in self.dlp_samples and len(self.dlp_samples) < 10:
                self.dlp_samples.append(tag)
            return repl

        return self.client_rx.sub(_hit, text)

    # backward-compatible alias (previous name)
    _elide_client_terms = _mask_client_terms

    def _sweep_host_terms(self, text: str) -> str:
        """Apply the operator tenant host naming conventions (host_terms):
        matching bare machine names are masked reversibly. Unlike the
        infra-vocabulary heuristic this is explicit configuration, so it runs
        on every value -- free text AND fields kept in clear."""
        if not self.host_rx:
            return text

        def _hit(m: re.Match) -> str:
            tok = m.group(0)
            if tok.lower() in RESERVED_HOSTS or self._own_pseudo(tok) \
                    or looks_like_ioc_hex(tok) \
                    or inside_opaque_blob(m.string, m.start(), m.end()):
                return tok
            self.counts["host_term"] += 1
            return self._map("fqdn", tok)

        return self.host_rx.sub(_hit, text)

    def _mask_sharepoint_identities(self, text: str) -> str:
        """v0.22.2: negli URL SharePoint/OneDrive l'identita' e' nel percorso.

        "https://azienda-my.sharepoint.com/personal/sara_virgili_azienda_it/..."
        contiene l'indirizzo e-mail con "_" al posto di "@" e ".". Il segmento
        non veniva toccato perche' fa parte di un URL: qui viene mascherato
        come identita', mantenendo il resto del percorso leggibile.
        """
        def _hit(m: "re.Match") -> str:
            segment = m.group("who")
            if not segment or self._own_pseudo(segment):
                return m.group(0)
            self.counts["sharepoint_identity"] += 1
            return m.group(0).replace(segment, self._map("user", segment), 1)

        return SHAREPOINT_IDENTITY_RX.sub(_hit, text)

    def _mask_person_names(self, text: str) -> str:
        """v0.19.0: coppie "Nome Cognome" -> un solo pseudonimo person-*.

        Richiede ENTRAMBI i token: il primo in lista nomi, il secondo in lista
        cognomi (o il contrario, per gli export "Cognome Nome"). Il requisito
        della coppia e' cio' che rende la regola sicura: due parole comuni
        consecutive e capitalizzate che siano una nome e l'altra cognome
        praticamente non capitano nei log.
        """
        # 1) persone REALI del tenant (person_terms): qui il token singolo si
        #    puo' mascherare, perche' e' un nome che esiste in quel cliente.
        singles = getattr(self.opt, "_person_set", frozenset())
        if singles:
            # "mrossi" / "m.rossi" / "m_rossi": iniziale + cognome. Ammesso solo
            # con person_terms, mai dalle liste generiche: senza sapere che quel
            # cognome esiste nel cliente si spezzerebbero parole comuni
            # ("scosta" = s+costa, "amare" = a+mare).
            def _initial(m: "re.Match") -> str:
                if m.group(2).lower() in singles:
                    self.counts["person_name"] += 1
                    return self._map("person", m.group(0))
                return m.group(0)

            def _initial_ctx(m: "re.Match") -> str:
                if m.group(2).lower() not in singles:
                    return m.group(0)
                self.counts["person_name"] += 1
                token = m.group(1) + m.group(2)
                return m.group(0)[:m.start(1) - m.start(0)] + self._map("person", token)

            text = PERSON_INITIAL_SEP_RX.sub(_initial, text)
            text = PERSON_INITIAL_CTX_RX.sub(_initial_ctx, text)
            def _single(m: "re.Match") -> str:
                tok = m.group(0)
                if tok.lower() in singles:
                    self.counts["person_name"] += 1
                    return self._map("person", tok)
                return tok
            text = PERSON_TOKEN_RX.sub(_single, text)

        # 2) liste generiche: SOLO coppie Nome+Cognome.
        given, family = load_person_lists()
        if not given or not family:
            return text

        words = [(m.start(), m.end(), m.group(0))
                 for m in PERSON_WORD_RX.finditer(text)]
        if len(words) < 2:
            return text
        chunks: list[str] = []
        last = 0
        i = 0
        while i < len(words) - 1:
            start, end, first = words[i]
            nxt_start, nxt_end, second = words[i + 1]
            sep = text[end:nxt_start]
            # "Cognome, Nome" e' il formato AD/LDAP, ma la virgola e' anche il
            # separatore degli ELENCHI ("Costa, Monti, Riva"): se subito dopo la
            # coppia c'e' un'altra virgola siamo in una lista, non davanti a una
            # persona.
            in_list = "," in sep and (text[nxt_end:nxt_end + 1] == ","
                                      or "," in text[max(0, start - 2):start])
            if _person_sep_ok(sep) and not in_list \
                    and _person_boundary_ok(text, start, nxt_end):
                a, b = first.lower(), second.lower()
                if a not in PERSON_STOPWORDS and b not in PERSON_STOPWORDS \
                        and ((a in given and b in family)
                             or (a in family and b in given)):
                    chunks.append(text[last:start])
                    chunks.append(self._map("person", text[start:nxt_end]))
                    self.counts["person_name"] += 1
                    last = nxt_end
                    i += 2                          # coppia consumata
                    continue
            i += 1                                  # riprova dalla successiva
        chunks.append(text[last:])
        return "".join(chunks)

    def _mask_bare_hostnames(self, text: str) -> str:
        """Machine names without a labeling key (evidence tables): masked
        reversibly. Two layers: configured tenant naming conventions, then a
        conservative infra-vocabulary heuristic ("server-sso", "dc01")."""
        text = self._sweep_host_terms(text)

        def _heur_hit(m: re.Match) -> str:
            tok = m.group("htok")
            if tok.lower() in RESERVED_HOSTS or self._own_pseudo(tok) \
                    or looks_like_ioc_hex(tok) \
                    or inside_opaque_blob(m.string, m.start("htok"), m.end("htok")) \
                    or not looks_like_bare_hostname(tok):
                return tok
            self.counts["host_token"] += 1
            return self._map("fqdn", tok)

        return HOST_TOKEN_RX.sub(_heur_hit, text)

    def _mask_identity_kv(self, text: str) -> str:
        """Maschera le identita' dichiarate come "chiave: valore" nel testo.

        Copre i messaggi degli Event Log Windows e i JSON serializzati dentro
        una cella, dove l'identita' e' esplicita ma priva della sintassi che il
        motore riconosce altrove.
        """
        for rx, kind, counter in ((IDENTITY_KV_USER_RX, "user", "kv_user"),
                                  (IDENTITY_KV_DOMAIN_RX, "windomain", "kv_domain"),
                                  (IDENTITY_KV_HOST_RX, "fqdn", "kv_host")):
            def _hit(match: "re.Match", kind=kind, counter=counter, rx=rx) -> str:
                raw = match.group("value")
                quote = raw[0] if raw[:1] in ("\"", "'") else ""
                token = raw.strip("\"'")
                if not _identity_kv_value_ok(token):
                    return match.group(0)
                if rx is IDENTITY_PROSE_RX and token.lower() in IDENTITY_PROSE_STOPWORDS:
                    return match.group(0)
                self.counts[counter] += 1
                masked = self._map(kind, token)
                return match.group(0)[:match.start("value") - match.start()] + \
                    quote + masked + quote
            text = rx.sub(_hit, text)
        return text

    def _mask_identity_prose(self, text: str) -> str:
        """"User mrossi logged on": l'identita' segue la parola user/account.

        Gira DOPO il riconoscimento dei nomi di persona, non prima: su "utente
        Mario Rossi" deve vincere il rilevatore di nomi, che maschera la coppia
        intera. Anticipandolo si mascherava solo "Mario" lasciando "Rossi" in
        chiaro - una mezza mascheratura e' peggio di nessuna.
        """
        def _hit(match: "re.Match") -> str:
            raw = match.group("value")
            quote = raw[0] if raw[:1] in ("\"", "'") else ""
            token = raw.strip("\"'")
            if not _identity_kv_value_ok(token):
                return match.group(0)
            if token.lower() in IDENTITY_PROSE_STOPWORDS:
                return match.group(0)
            # Se il valore non ha forma di identificatore, deve esserci il
            # contesto di autenticazione: senza l'uno ne' l'altro si rischia di
            # mascherare una parola comune (la lookahead lo garantisce, ma il
            # doppio controllo tiene la regola onesta anche se cambia).
            tail = text[match.end("value"):match.end("value") + 60]
            if (not _PROSE_IDENTIFIER_SHAPE.search(token)
                    and not re.search(r"(?i)\b" + _AUTH_VERB + r"\b", tail)):
                return match.group(0)
            self.counts["prose_user"] += 1
            return match.group(0)[:match.start("value") - match.start()] + \
                quote + self._map("user", token) + quote

        return IDENTITY_PROSE_RX.sub(_hit, text)

    def process(self, text: str, *, url_ioc: bool = False) -> str:
        if not url_ioc and text in self._pt_text:
            return text
        before_blocked = len(self.dlp_blocked)
        self._url_ioc = url_ioc
        try:
            out = self.rx.sub(self._sub, text)
            out = self._mask_identity_kv(out)            # v0.25.1
            out = self._mask_bare_hostnames(out)
            out = self._mask_sharepoint_identities(out)  # v0.22.2
            out = self._mask_person_names(out)          # v0.19.0
            out = self._mask_identity_prose(out)        # v0.25.2 (dopo i nomi)
            out = self._mask_client_terms(self.process_dlp(out))
            if not url_ioc and out == text \
                    and len(self.dlp_blocked) == before_blocked \
                    and len(self._pt_text) < 200000:
                self._pt_text.add(text)
            return out
        finally:
            self._url_ioc = False


# Pseudonym shapes we emit -> used to find tokens to reverse.
PSEUDO_RX = re.compile(
    # v0.21.2: confine iniziale "non lettera-non cifra" invece di \b, cosi' uno
    # pseudonimo incastonato in un token (es. cf-... dentro un path
    # "...\\tmpxq_cf-xxxx\\") viene ripristinato in deanonimizzazione,
    # simmetricamente al masking che ora lo riconosce nella stessa posizione.
    # v0.23.0: il local part di un'e-mail mascherata puo' essere usr-* oppure
    # person-* (quando il valore era riconosciuto come nome di persona). Senza
    # person-* qui, "person-xxxx@yyyy.masked" non risultava un NOSTRO
    # pseudonimo: veniva riconosciuto come e-mail residua e ri-mascherato,
    # rompendo il ripristino.
    r"(?<![A-Za-z0-9])(?:(?:usr|person)-[a-z2-7]{4,16}@[A-Za-z0-9.\-]+"   # email
    r"|host-[a-z2-7]{4,10}\.[A-Za-z0-9.\-]+"            # fqdn
    r"|usr-[a-z2-7]{4,10}"                              # user
    r"|host-[a-z2-7]{4,10}"                             # short hostname
    r"|id-[a-z2-7]{8,16}"                              # opaque identifier
    r"|(?:cf|iban|tel|person|addr|cloud|secret|vat)-[a-z2-7]{8,16}" # DLP/PII
    r"|DOM(?:\d{2}|-[a-z2-7]{8})"                      # win domain (legacy + v0.3)
    r"|S-1-5-21-\d+-\d+-\d+-\d+"                        # SID
    r"|(?:198\.(?:18|19)\.\d{1,3}\.\d{1,3}|(?:10|100)\.\d{1,3}\.\d{1,3}\.\d{1,3})" # ipv4 new + legacy
    r"|fd00(?::[0-9a-f]{0,4}){1,6}::?1"                 # ipv6
    r"|02(?::[0-9a-f]{2}){5})"                          # mac
)


class Deanonymizer:
    def __init__(self, vault: Vault, opt: Options):
        self.vault = vault
        self.opt = opt
        self.hits = Counter()
        self.misses = Counter()

    def _sub(self, m: re.Match) -> str:
        tok = m.group(0)
        orig = self.vault.reverse(tok)
        if orig:
            self.hits["resolved"] += 1
            return orig
        # truncated pseudonym: bare stem of a masked FQDN or e-mail
        if re.fullmatch(r"(?:host|usr)-[a-z2-7]{4,10}", tok):
            like = tok + (".%" if tok.startswith("host-") else "@%")
            rows = self.vault.db.execute(
                "SELECT orig_enc FROM mappings WHERE pseudonym LIKE ? LIMIT 2",
                (like,)).fetchall()
            if len(rows) == 1:
                self.hits["resolved"] += 1
                return decrypt(self.vault.master, rows[0][0])

        # split UPN (usr-xxxx@CLIENT-yyy / usr-xxxx@host-yyy): the user local
        # part is a reversible pseudonym; the domain (irreversible client token
        # or masked host) stays as-is.
        m_upn = re.fullmatch(r"(usr-[a-z2-7]{4,10})@(.+)", tok)
        if m_upn:
            local = self.vault.reverse(m_upn.group(1))
            if local:
                dom = m_upn.group(2)
                self.hits["resolved"] += 1
                # host-* domains reverse; the irreversible CLIENT-* token stays.
                return f"{local}@{self.vault.reverse(dom) or dom}"

        # SID: domain part is vaulted, RID travels in clear
        m2 = re.fullmatch(r"(S-1-5-21-\d+-\d+-\d+)-(\d+)", tok)
        if m2:
            oprefix = self.vault.reverse(m2.group(1))
            if oprefix:
                self.hits["resolved"] += 1
                return f"{oprefix}-{m2.group(2)}"
        # subnet mode: pseudo-IP was assembled from two mappings
        if re.fullmatch(r"(?:198\.(?:18|19)\.\d{1,3}\.\d{1,3}|(?:10|100)\.\d{1,3}\.\d{1,3}\.\d{1,3})", tok):
            net, _, host = tok.rpartition(".")
            onet = self.vault.reverse(net)
            ohost = self.vault.reverse(host)
            if onet and ohost:
                self.hits["resolved"] += 1
                return f"{onet}.{ohost}"
        self.misses[tok] += 1
        return tok

    def process(self, text: str) -> str:
        return PSEUDO_RX.sub(self._sub, text)


# ------------------------------------------------- field catalog / inference

# Per-family column catalogs, matched against the normalized column name
# (lowercase, spaces -> underscore); winlogbeat/event_data prefixes are also
# stripped so ECS-shipped Windows events hit the "windows" catalog.
# kinds: ip, mac, email, user, fqdn, winuser, windomain, sid, endpoint, opaque, text

CATALOGS: dict[str, list[tuple[str, str]]] = {

    "ecs": [                                     # Elastic Common Schema
        (r".*\.(nat\.)?ip$", "ip"),
        (r"^related\.ip$", "ip"),
        (r".*\.mac$", "mac"),
        (r".*\.address$", "endpoint"),           # ECS: address = IP or name
        (r".*user\.(name|id|full_name)$", "user"),
        (r".*user\.email$", "email"),
        (r".*user\.domain$", "windomain"),
        (r"^related\.user$", "user"),
        (r"^related\.hosts$", "fqdn"),
        (r".*\.(hostname|fqdn)$", "fqdn"),
        (r"^(host\.name|winlog\.computer_name|observer\.name)$", "fqdn"),
        (r".*\.(domain|registered_domain)$", "fqdn"),
        (r"^dns\.question\.name$", "fqdn"),
        (r"^dns\.answers\.(name|data)$", "endpoint"),
        (r"^(url\.(full|original|path|query)|http\.request\.referrer)$", "text"),
        (r"^email\.(from|to|cc|bcc|sender|reply_to)\.address$", "email"),
        (r".*\.(command_line|args|executable|working_directory)$", "text"),
        (r"^(file\.(path|directory|target_path)|registry\.(key|path|value))$", "text"),
        (r"^(message|event\.original|error\.message)$", "text"),
    ],

    "xsiam": [                                   # Cortex XSIAM/XDR xdr_data + alerts
        (r"^(agent|host)_ip(_addresses)?(_v6)?$", "ip"),
        (r"^action_(local|remote)_ip(_v6)?$", "ip"),
        (r".*_ip(_v6)?$", "ip"),
        (r".*_ip_addresses(_v6)?$", "ip"),
        (r"^(agent_hostname|host_name|dst_host|src_host)$", "endpoint"),
        (r".*external_hostname$", "fqdn"),
        (r".*dns_query(_name)?$", "fqdn"),
        (r"^(actor|causality_actor|os_actor)_(effective|primary)_username$", "user"),
        (r"^user_name$", "user"),
        (r".*_username$", "user"),
        (r".*_domain$", "windomain"),
        (r".*_sid$", "sid"),
        (r".*command_line$", "text"),
        (r".*_(file|image)_path$", "text"),
        (r".*registry_(key_name|data|full_key)$", "text"),
        (r"^mac(_addresses)?$", "mac"),
    ],

    "windows": [               # Security/System EVTX exports + Sysmon EventData
        (r"^(target|subject|new_target|old_target)username$", "user"),
        (r"^(accountname|samaccountname|serviceaccountname|servicename)$", "user"),
        (r"^(user|parentuser)$", "user"),
        (r"^(target|subject|account|new_target|old_target)domain(name)?$", "windomain"),
        (r".*userprincipalname$", "email"),
        (r".*usersid$", "sid"),
        (r"^(ipaddress|clientaddress|clientipaddress|sourceip|destinationip"
         r"|sourceaddress|destinationaddress)$", "ip"),
        (r"^(workstation|workstationname|computer|computername|targetservername"
         r"|sourcecomputername|sourcehostname|destinationhostname|remotehost)$", "endpoint"),
        (r"^queryname$", "fqdn"),
        (r"^(commandline|parentcommandline|processcommandline|scriptblocktext"
         r"|image|parentimage|newprocessname|parentprocessname|processname"
         r"|currentdirectory|targetfilename|objectname|sharename|sharelocalpath"
         r"|relativetargetname|queryresults|servicefilename|taskcontent"
         r"|membername)$", "text"),
    ],

    "fortinet": [                                # FortiGate/FortiOS
        (r"^(srcip|dstip|remip|locip|tunnelip|assignip|natsrcip|natdstip)$", "ip"),
        (r"^(srcmac|dstmac)$", "mac"),
        (r"^(user|unauthuser|xauthuser|srcuser|dstuser)$", "user"),
        (r"^(srcname|dstname|devname|unauthusersource)$", "endpoint"),
        (r"^hostname$", "fqdn"),
        (r"^(url|msg|logdesc|rawdata)$", "text"),
        (r"^(sender|recipient|from|to)$", "email"),
    ],

    "paloalto": [                                # PAN-OS traffic/threat
        (r"^(src|dst|natsrc|natdst|source_address|destination_address"
         r"|nat_source_ip|nat_destination_ip)$", "endpoint"),
        (r"^(srcuser|dstuser|source_user|destination_user)$", "user"),
        (r"^(device_name|dvc_name)$", "endpoint"),
        (r"^(misc|url|filename)$", "text"),
    ],

    "m365": [                                    # O365 UAL / Entra sign-in exports
        (r"^(userids?|userkey|user_id)$", "user"),
        (r".*userprincipalname$", "email"),
        (r"^(clientip|client_ip_address|actoripaddress|ip_address)$", "ip"),
        (r"^(auditdata|extendedproperties|parameters|modifiedproperties)$", "text"),
        (r"^(objectid|item)$", "text"),
    ],

    "cim": [                                     # Splunk CIM
        (r"^(src|dest|dvc)$", "endpoint"),
        (r"^(src_ip|dest_ip|dvc_ip)$", "ip"),
        (r"^(src_mac|dest_mac)$", "mac"),
        (r"^(user|src_user|dest_user)$", "user"),
        (r"^(src_nt_domain|dest_nt_domain|nt_domain)$", "windomain"),
        (r"^(src_host|dest_host|src_dns|dest_dns|host)$", "fqdn"),
        (r"^(url|uri_path|http_referrer)$", "text"),
    ],

    "crowdstrike": [
        (r"^(aip|localip|local_ip|externalip)$", "ip"),
        (r"^(computername|hostnames?)$", "endpoint"),
        (r"^(username|useraccount)$", "user"),
        (r"^(machinedomain|logondomain)$", "windomain"),
        (r"^usersid$", "sid"),
        (r"^(commandline|imagefilename|filepath)$", "text"),
    ],

    "cef": [                                     # ArcSight Common Event Format
        (r"^(src|dst|sourceaddress|destinationaddress)$", "endpoint"),
        (r"^(shost|dhost|dvchost|sourcehostname|destinationhostname)$", "endpoint"),
        (r"^(suser|duser|suid|duid|sourceusername|destinationusername)$", "user"),
        (r"^(smac|dmac|sourcemacaddress|destinationmacaddress)$", "mac"),
        (r"^(request|requesturl|filepath|filename|msg|message)$", "text"),
    ],

    "leef": [                                    # IBM Log Event Extended Format
        (r"^(src|dst|srcip|dstip|sourceaddress|destinationaddress)$", "endpoint"),
        (r"^(srchost|dsthost|hostname|devname)$", "endpoint"),
        (r"^(username|usrname|user|srcuser|dstuser)$", "user"),
        (r"^(srcmac|dstmac)$", "mac"),
        (r"^(url|uri|message|msg|commandline|filepath)$", "text"),
    ],

    "syslog": [                                  # Common key=value aliases
        (r"^(src|dst|src_ip|dst_ip|source|destination)$", "endpoint"),
        (r"^(host|hostname|device|devname|computer)$", "endpoint"),
        (r"^(user|username|account|srcuser|dstuser)$", "user"),
        (r"^(email|sender|recipient)$", "email"),
        (r"^(mac|srcmac|dstmac)$", "mac"),
        (r"^(msg|message|url|uri|path|command|cmd|commandline)$", "text"),
    ],

    "generic": [                                 # cross-vendor fallback
        (r".*\b(src|source|dst|destination|client|server|host|local|remote|nat"
         r"|forwarded|observer|relay|agent)[._]?ip(_?address(es)?)?$", "ip"),
        (r"^(ip|ipaddr|ip_address|ipv4|ipv6|clientip|c_ip|s_ip|cs_ip"
         r"|x_forwarded_for)$", "ip"),
        (r".*\b(mac|hwaddr|hardware_address|physical_address)$", "mac"),
        (r".*\b(e?mail|email_address|sender|recipient|from_address|to_address)$", "email"),
        (r".*\b(user|username|user_name|account|account_name|accountname"
         r"|samaccountname|sam_account_name|useraccount|user_account"
         r"|targetaccountname|subjectaccountname|accountdisplayname|accountupn"
         r"|upn|principal|login|logon_user|caller|initiator)$", "user"),
        (r".*\b(host|hostname|host_name|computer|computer_name|machine|endpoint"
         r"|device_name|fqdn|dns_name)$", "endpoint"),
        (r".*\b(domain|dns_query|query|url_domain|registered_domain)$", "fqdn"),
        (r".*\b(domain_?user|nt_?account)$", "winuser"),
        (r".*(guid|uuid|object_?id|tenant_?id|subscription_?id|device_?id|agent_?id|connector_?guid|machine_?id|customer_?id)$", "opaque"),
        (r".*\bsid$", "sid"),
    ],
}

# Canonical v0.7 vendor kits and compatibility aliases.
CATALOGS.update(kit_catalogs())

# Columns that hold free text in any source: run the regex engine inside them.
TEXT_CATALOG: list[str] = [
    r"^(message|_raw|raw|event\.original|original|description|details"
    r"|summary|reason|log|body|payload|event_?name|cef\.name)$",
    r".*(command_?line|cmdline|process_?args|args|arguments)$",
    r".*\b(url|uri|referrer|request|user_agent|path|file_?path"
    r"|target_process_cmd|action_process_image_command_line)$",
    # *_url / *_link and their plurals: \b does not fire between "_" and a
    # letter, so the underscore-suffixed forms need an explicit alternative.
    r".*(_url|_urls|_link|_links|_uri)$",
]

# Distinctive header fingerprints used to auto-detect the source family.
FINGERPRINTS: dict[str, set[str]] = {
    "xsiam": {"agent_hostname", "actor_effective_username", "action_local_ip",
              "action_remote_ip", "causality_actor_process_image_name", "agent_id"},
    "windows": {"targetusername", "subjectusername", "targetdomainname",
                "subjectdomainname", "ipaddress", "logontype", "eventid",
                "computer", "commandline", "parentimage", "queryname"},
    "ecs": {"@timestamp", "source.ip", "destination.ip", "event.action",
            "host.name", "user.name", "event.dataset", "message"},
    "fortinet": {"srcip", "dstip", "devname", "logid", "srcintf", "dstintf",
                 "policyid"},
    "paloalto": {"natsrc", "natdst", "srcuser", "dstuser", "device_name",
                 "sessionid"},
    "m365": {"userids", "auditdata", "creationdate", "recordtype", "operations"},
    "cim": {"src_ip", "dest_ip", "dest", "src_user", "dvc"},
    "crowdstrike": {"aip", "computername", "machinedomain", "event_simplename"},
}

# v0.16.1: "_source." and "fields." are pure Elasticsearch transport wrappers
# with no semantic meaning. They must be stripped BEFORE kit matching: otherwise
# the prefixed form is tried first and gets swallowed by a kit's catch-all
# `keep` rule, defeating every ^-anchored identity rule (host.name / agent.name
# leaked in clear from ES search hits). Unlike winlog.*, no kit rule targets them.
TRANSPORT_PREFIXES = ("_source.", "fields.")

PREFIX_STRIP = (
    "_source.", "fields.",
    "winlog.event_data.", "winlog.user_data.", "event_data.",
    "eventdata.", "winlog.",
)


def norm_col(column: str) -> str:
    return re.sub(r"\s+", "_", column.strip().lower())


def col_candidates(column: str) -> list[str]:
    """Return increasingly generic field-name variants for kit/catalog matching.

    Elastic alert documents commonly wrap product payloads under paths such as
    _source.*, fields.*, kibana.alert.original_* and signal.*.  Vendor rules are
    intentionally written for the logical field name; this helper strips the
    transport wrappers while preserving the original path for exact rules.
    """
    c = norm_col(column).replace("[]", "")
    while True:                                   # v0.16.1: drop ES transport wrappers
        for pre in TRANSPORT_PREFIXES:
            if c.startswith(pre):
                c = c[len(pre):]
                break
        else:
            break
    out: list[str] = []

    def add(value: str) -> None:
        value = value.strip(".")
        if value and value not in out:
            out.append(value)

    add(c)

    queue = [c]
    while queue:
        item = queue.pop(0)
        for pre in PREFIX_STRIP:
            if item.startswith(pre):
                stripped = item[len(pre):]
                if stripped not in queue:
                    queue.append(stripped)
                add(stripped)

        # Kibana/Elastic signal wrappers: expose the original ECS fields too.
        mappings = (
            ("kibana.alert.original_event.", "event."),
            ("kibana.alert.original_data_stream.", "data_stream."),
            ("signal.original_event.", "event."),
            ("signal.rule.", "kibana.alert.rule."),
            ("signal.", "kibana.alert."),
        )
        for pre, repl in mappings:
            if item.startswith(pre):
                mapped = repl + item[len(pre):]
                if mapped not in queue:
                    queue.append(mapped)
                add(mapped)

        # Trend Vision One nested in Elastic/Kibana wrappers.  Add both the
        # product-relative path and the leaf so the Trend kit can classify it.
        marker = "trend_micro_vision_one.alert."
        if marker in item:
            rel = item.split(marker, 1)[1]
            add(rel)
            if "." in rel:
                add(rel.rsplit(".", 1)[-1])

        if "." in item:
            leaf = item.rsplit(".", 1)[-1]
            add(leaf)

    return out

def detect_family(columns: list[str]) -> str | None:
    detected = detect_vendor_kit([norm_col(c) for c in columns])
    if detected.get("id"):
        return str(detected["id"])
    cols = {norm_col(c) for c in columns}
    best, score = None, 0
    for fam, fp in FINGERPRINTS.items():
        n = len(cols & fp)
        if n > score:
            best, score = fam, n
    return best if score >= 2 else None


def _path_specific_vendor(column: str) -> str | None:
    c = norm_col(column).replace("[]", "")
    if "trend_micro_vision_one.alert." in c:
        return "trend_vision_one"
    return None


@dataclass(frozen=True)
class FieldDecision:
    kind: str | None
    action: str
    inferred_by: str


EXTRA_KEEP_FIELDS: set[str] = set()

# v0.27.0 - override per campo, globali e indipendenti dal kit rilevato. I campi
# "non tracciati" compaiono spesso proprio quando NESSUN kit ha fatto match,
# quindi legare gli override al vendor sarebbe fragile. Mappa nome-campo
# normalizzato -> {"action": keep|mask|redact, "kind": <kind o None>}. Vince
# sui kit ma non su config:keep (che resta il canale storico). Popolata da
# app.load_field_overrides() a ogni richiesta.
FIELD_OVERRIDES: dict[str, dict] = {}
OVERRIDE_ACTIONS = frozenset({"keep", "mask", "redact"})


def looks_like_free_text(samples: "list[str] | None") -> bool:
    """La colonna contiene prosa o un blob strutturato?

    Serve a distinguere un messaggio di evento o un JSON serializzato - che
    vanno mascherati - da un identificativo opaco, un hash o un id base64, che
    non devono essere toccati. Il criterio e' volutamente stretto: piu' parole
    separate da spazi, oppure un JSON che parsifica davvero. Un hash o un
    "6bI/+VVDCxxx==" non hanno spazi e non sono JSON, quindi restano fuori.
    """
    values = [v for v in (samples or []) if v and v.strip()][:20]
    if not values:
        return False
    hits = 0
    for value in values:
        text = value.strip()
        if len(text) < 24:
            continue
        if text[0] in "{[" and text[-1] in "}]":
            try:
                json.loads(text)
                hits += 1
                continue
            except (ValueError, TypeError):
                pass
        if len(text.split()) >= 5:
            hits += 1
    return hits * 2 >= len(values)          # almeno meta' dei campioni


def resolve_field(column: str, samples: list[str], family: str | None = None) -> FieldDecision:
    canonical = canonical_kit_id(family)
    cands = col_candidates(column)

    if EXTRA_KEEP_FIELDS:
        for c in cands:
            if c in EXTRA_KEEP_FIELDS:
                return FieldDecision(None, "keep", "config:keep")

    # v0.27.0 - override espliciti scelti dall'utente sui campi non tracciati.
    # Vengono prima di kit, catalogo ed euristiche: sono una decisione manuale.
    if FIELD_OVERRIDES:
        for c in cands:
            ov = FIELD_OVERRIDES.get(c)
            if ov:
                action = ov.get("action", "redact")
                # v0.27.1: mask override -> SEMPRE opaque. Un kind tipizzato
                # (ipv4, iban...) restituisce il valore INVARIATO quando il
                # contenuto non e' conforme - una fuga. opaque maschera
                # qualsiasi valore senza condizioni.
                kind = "opaque" if action == "mask" else None
                return FieldDecision(kind, action, "config:override")

    # Product payloads embedded in an Elastic/Kibana signal should use their
    # own kit even when the outer wrapper is ECS.
    specific = _path_specific_vendor(column)
    if specific:
        for c in cands:
            rule, kit_id = match_rule(c, specific)
            if rule:
                return FieldDecision(rule.kind, rule.action, f"vendor:{kit_id}")

    if canonical:
        for c in cands:
            rule, kit_id = match_rule(c, canonical)
            if rule:
                return FieldDecision(rule.kind, rule.action, f"vendor:{kit_id}")
    for c in cands:
        for pat in TEXT_CATALOG:
            if re.match(pat, c, re.IGNORECASE):
                return FieldDecision(None, "text", "generic")
    order = []
    if family in CATALOGS and not canonical:
        order.append(family)
    order.append("generic")
    for fam in order:
        for c in cands:
            for pat, kind in CATALOGS[fam]:
                if re.match(pat, c, re.IGNORECASE):
                    return FieldDecision(None if kind == "text" else kind, "text" if kind == "text" else "mask", "generic" if fam == "generic" else f"catalog:{fam}")
    # Do not let value-only sniffing override explicitly operational fields.
    # Example: ECS event.dataset="windows.security" looks like an FQDN,
    # but it is product metadata and must stay readable.
    if is_safe_column(column, samples):
        return FieldDecision(None, "keep", "safe")
    kind = kind_from_values(samples)
    if kind:
        return FieldDecision(kind, "mask", "value")
    # v0.25.1: una colonna sconosciuta che contiene PROSA o un blob JSON non
    # puo' restare "keep". Un campo come action_evtlog_message o un
    # to_json_string(...) rinominato a piacere in query porta dentro nomi
    # utente, host e IP: tenerlo intatto e' una fuga completa. Mascherarlo come
    # testo libero pseudonimizza gli identificativi e lascia leggibile il resto.
    if looks_like_free_text(samples):
        return FieldDecision(None, "text", "heuristic:text")
    return FieldDecision(None, "keep", "")


def kind_from_name(column: str, family: str | None = None) -> str | None:
    decision = resolve_field(column, [], family)
    return "text" if decision.action == "text" else decision.kind


# Value sniffers: used when the column name tells us nothing.
SNIFFERS: list[tuple[str, re.Pattern]] = [
    ("sid", re.compile(r"^S-1-5-21(?:-\d+){3,}$")),
    ("email", re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")),
    ("mac", re.compile(r"^(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")),
    ("winuser", re.compile(r"^[A-Za-z][A-Za-z0-9\-]{1,20}\\[A-Za-z0-9._\-$]{1,32}$")),
    ("ipv4", re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")),
    ("ipv6", re.compile(r"^[0-9A-Fa-f:]{3,45}$")),
    ("opaque", re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$")),
    ("fqdn", re.compile(r"^(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}$")),
]

VALID = {"ipv4": valid_ipv4, "ipv6": valid_ipv6}


def kind_from_values(values: list[str]) -> str | None:
    """Sniff a kind from sampled cell values. Requires a clear majority."""
    votes: Counter = Counter()
    n = 0
    for v in values:
        v = v.strip().strip('"')
        if not v or v.lower() in {"-", "n/a", "null", "none"}:
            continue
        n += 1
        for kind, rx in SNIFFERS:
            if rx.match(v) and VALID.get(kind, lambda _: True)(v):
                votes[kind] += 1
                break
    if not n:
        return None
    kind, count = (votes.most_common(1) or [(None, 0)])[0]
    return kind if count / n >= 0.8 else None


def resolve_kind(column: str, samples: list[str],
                 family: str | None = None) -> tuple[str | None, str]:
    """Compatibility wrapper returning the inferred kind and origin."""
    decision = resolve_field(column, samples, family)
    if decision.action == "text":
        return "text", decision.inferred_by
    return decision.kind, decision.inferred_by


# ------------------------------------------------------------------- policy

ACTIONS = {"mask", "text", "keep", "drop", "redact"}
ELIDED = "[ELIDED]"

# column names whose content is operational, not identifying
SAFE_NAME_RX = re.compile(
    r"(time|date|stamp|^event$|severity|sev$|priority|facility|port|proto|action$|status|level"
    r"|^type$|subtype|category|cat$|signature|event_?id|event\.(code|id|kind|category|type|outcome|action|severity|risk_score|sequence|dataset|module|provider)$"
    r"|network\.(transport|protocol|direction|type|community_id)$|(?:source|destination)\.port$"
    r"|file\.(size|extension|type|hash(?:\..+)?)$|rule\.(id|name|category|ruleset|version)$"
    r"|threat\.(id|name|framework)$|record|version|seq|count|bytes|duration|offset|zone"
    r"|policyid|logid|pid$|process_?id|thread_?id|label$|vendor$|product$)",
    re.IGNORECASE,
)
SAFE_VALUE_RX = re.compile(r"^[\d\s.,:\-+TZzWw/]*$")   # numbers / timestamps


def is_safe_column(name: str, values: list[str]) -> bool:
    """Allow cleartext only when the column name has explicit operational semantics.

    Value-only inference is intentionally not used here: an unknown numeric
    column may contain a phone number, employee ID or customer identifier.
    Ambiguous columns therefore fail closed under safe mode.
    """
    return bool(SAFE_NAME_RX.search(norm_col(name)))


def apply_safe_policy(pol: dict, samples: dict[str, list[str]]) -> dict:
    """Unclassified columns with data are elided instead of passing in clear."""
    for c, spec in pol.get("columns", {}).items():
        vals = samples.get(c, [])
        inferred_by = str(spec.get("inferred_by") or "")
        if inferred_by.startswith("vendor:") or inferred_by in ("config:keep", "config:override"):
            continue
        if spec.get("action") == "keep" and any(v.strip() for v in vals) \
                and not is_safe_column(c, vals):
            spec["action"] = "redact"
            spec["inferred_by"] = "safe"
    return pol


def kit_dry_run(columns: list[str], samples: dict | None = None,
                family: str | None = None, safe: bool = True) -> dict:
    """Classify a column list against the kits WITHOUT masking: detection,
    per-field action/kind/inferred_by, and which fields would be elided in
    Safe mode. Powers the CLI/API kit test (dry-run)."""
    from vendor_kits import detect_vendor_kit, reload_kits_if_changed
    reload_kits_if_changed()
    cols = [c for c in columns if c and str(c).strip()]
    det = detect_vendor_kit(cols)
    fam = family or det.get("id")
    samp = {c: ((samples or {}).get(c) or ["x"]) for c in cols}
    pol = default_policy(cols, samp, fam)
    if safe:
        pol = apply_safe_policy(pol, samp)
    fields = []
    for c in cols:
        spec = pol["columns"].get(c, {})
        fields.append({"column": c, "action": spec.get("action", "keep"),
                       "kind": spec.get("kind"),
                       "inferred_by": str(spec.get("inferred_by") or "")})
    return {"detected": det, "family": fam, "fields": fields,
            "elided": [f["column"] for f in fields if f["action"] == "redact"]}


def default_policy(columns: list[str], samples: dict[str, list[str]],
                   family: str | None = None) -> dict:
    cols = {}
    for c in columns:
        decision = resolve_field(c, samples.get(c, []), family)
        cols[c] = {
            "action": decision.action,
            "kind": decision.kind,
            "inferred_by": decision.inferred_by,
        }
    return {"default": "keep", "catalog": family, "columns": cols}


def load_policy(path: Path | None) -> dict | None:
    if not path:
        return None
    if not Path(path).exists():
        sys.exit(f"[!] policy not found: {path} (run: logmask scan <file.csv>)")
    pol = json.loads(Path(path).read_text())
    for col, spec in pol.get("columns", {}).items():
        if spec.get("action") not in ACTIONS:
            sys.exit(f"[!] invalid action for column '{col}': {spec.get('action')}")
    return pol


# ------------------------------------------------- known-entity sweep (safe)

SWEEP_KINDS = {"user", "fqdn", "email", "windomain", "mac", "ipv4", "ipv6", "opaque"}

# Token "pieno" per lo sweep: stessa classe di caratteri dei confini usati in
# precedenza, cosi' tokenizzare equivale a cercare con quei lookaround.
SWEEP_TOKEN_RX = re.compile(r"[\w.@\-]+")


# v0.18.1: identita' che non devono MAI restare in chiaro, nemmeno nei campi
# descrittivi. Volutamente esclusi fqdn/opaque: una parola comune finita nel
# vault per un falso positivo storico corromperebbe il testo naturale.
IDENTITY_SWEEP_KINDS = frozenset({"user", "email"})

# v0.25.2 - colonne di TESTO di un export strutturato (message, raw_log,
# description). Qui si aggiunge fqdn, che nel testo incollato a mano era
# escluso: allora non esisteva alcun filtro sugli originali, oggi ce ne sono
# due - sweepable_host_original scarta le parole di prodotto e i nomi di
# processo, sweepable_prose_original pretende una cifra o un separatore. Un
# nome macchina come WKS0421 passa, "Windows" e "Sicurezza" no.
TEXT_COLUMN_SWEEP_KINDS = frozenset({"user", "email", "fqdn"})


_PROSE_IDENTIFIER_RX = re.compile(r"[0-9._\\/@$+:-]")


def sweepable_prose_original(value: str) -> bool:
    """v0.23.2: in un testo in LINGUAGGIO NATURALE, questo originale del vault
    merita di essere sostituito?

    Il vault di un cliente accumula, job dopo job, valori classificati male:
    "SOC", "Sicurezza", "Windows", "gruppo", "File" finiti sotto user o
    windomain perche' in QUEL log occupavano quella posizione. In un altro log
    strutturato la sostituzione non fa danno - quel campo contiene davvero
    un'identita'. In un oggetto di e-mail o in un paragrafo di documento si':
    "[SOC] Segnalazione di Sicurezza - Possible Masquerading Behavior" diventa
    "[usr-lry4sswj] Segnalazione di DOM-4wf4ihxo - id-v24z3wsg2g7m Masquerading
    Behavior" e l'oggetto non si legge piu'. Il danno e' retroattivo (vale per
    ogni job successivo) e silenzioso.

    Un identificatore vero porta quasi sempre una cifra o un separatore
    (m.rossi, srv-01, DOMINIO\\utente, tizio@dominio) oppure e' composto da piu'
    parole ("Mario Rossi"); una parola di prosa no. Si accetta di non
    sostituire un identificativo tutto-lettere isolato ("mrossi") in prosa:
    resta comunque mascherato ovunque compaia in un CAMPO, e distruggere il
    testo e' un danno peggiore che mancarne un'occorrenza descrittiva.
    """
    v = (value or "").strip()
    if len(v) < 3:
        return False
    if "@" in v or " " in v:
        return True
    return bool(_PROSE_IDENTIFIER_RX.search(v))


def _sweep_from_vault(vault: "Vault", text: str, opt: Options,
                      active: "set[str]", prose: bool = False) -> tuple[str, int]:
    """Strategia per testi grandi: si legge il vault una volta e si sostituisce
    con una singola passata di tokenizzazione (v0.18.2)."""
    rows = vault.db.execute(
        "SELECT kind, pseudonym FROM mappings WHERE kind IN (%s)"
        % ",".join("?" * len(active)), tuple(active)).fetchall()
    pairs: list[tuple[str, str]] = []
    for kind, pseudo in rows:
        orig = vault.reverse(pseudo)
        if kind in {"ipv4", "ipv6"} and orig and not opt.should_anonymize_ip(orig):
            continue
        if kind in {"fqdn", "endpoint"} and orig and not sweepable_host_original(orig):
            continue                          # v0.21.6: vedi sweepable_host_original
        if prose and orig and not sweepable_prose_original(orig):
            continue                          # v0.23.2: parola comune in prosa
        if orig and len(orig) >= 3 and orig.lower() != pseudo.lower():
            pairs.append((orig, pseudo))
    if not pairs:
        return text, 0
    pairs.sort(key=lambda t: len(t[0]), reverse=True)
    single: dict[str, str] = {}
    multi: list[tuple[str, str]] = []
    for orig, pseudo in pairs:
        (single.setdefault(orig.lower(), pseudo) if SWEEP_TOKEN_RX.fullmatch(orig)
         else multi.append((orig, pseudo)))
    hits = 0
    for orig, pseudo in multi:
        rx = re.compile(r"(?<![\w.@\-])" + re.escape(orig) + r"(?![\w.@\-])",
                        re.IGNORECASE)
        text, n = rx.subn(pseudo, text)
        hits += n
    if single:
        def _swap(m: "re.Match") -> str:
            nonlocal hits
            repl = single.get(m.group(0).lower())
            if repl is None:
                return m.group(0)
            hits += 1
            return repl
        text = SWEEP_TOKEN_RX.sub(_swap, text)
    return text, hits


def sweep_known(vault: "Vault", text: str, opt: Options | None = None,
                kinds: "frozenset[str] | set[str] | None" = None,
                *, prose: bool = False) -> tuple[str, int]:
    """Sostituisce nel testo gli originali che il vault gia' conosce.

    Il passaggio a regex ha bisogno di un contesto sintattico (user=...,
    DOMAIN\\x, @) per riconoscere un'identita'; un testo incollato puo'
    nominarla senza. Tutto cio' che il vault conosce viene sostituito col suo
    pseudonimo canonico: reversibile, correlazione preservata.

    v0.20.3 - la ricerca va DAL TESTO AL VAULT, non viceversa. Prima si
    leggeva l'intero vault e si decifrava OGNI originale per cercarlo nel
    testo: il costo cresceva col numero di identita' del cliente anche per un
    singolo evento (2,5 s con 20.000 identita'), e il vault cresce a ogni job.
    Ora si tokenizza il testo e per ogni token si calcola il blind index
    (deterministico) cercandolo nel vault: nessun decrypt, costo legato alla
    dimensione del TESTO. Vengono provate anche le coppie adiacenti, per gli
    originali che contengono uno spazio ("Mario Rossi").

    v0.23.2 - ``prose=True`` per testi in linguaggio naturale (documenti,
    oggetti e corpi di e-mail): sostituisce solo gli originali che non possono
    essere parole comuni. Vedi sweepable_prose_original.
    """
    active = SWEEP_KINDS if kinds is None else (SWEEP_KINDS & set(kinds))
    if not active:
        return text, 0
    tokens = SWEEP_TOKEN_RX.findall(text)
    if not tokens:
        return text, 0

    candidates: set[str] = set()
    for tok in tokens:
        if len(tok) >= 3:
            candidates.add(tok)
    for first, second in zip(tokens, tokens[1:]):        # originali con spazio
        if len(first) >= 2 and len(second) >= 2:
            candidates.add(f"{first} {second}")
    if not candidates:
        return text, 0

    effective_opt = opt or Options()
    order = [k for k in ("user", "email", "fqdn", "windomain", "opaque",
                         "mac", "ipv4", "ipv6") if k in active]

    # Le due strategie hanno costi opposti: cercare DAL TESTO costa quanto il
    # testo (token x kind), leggere il VAULT costa quanto il vault (un decrypt
    # per riga). Un evento singolo su un vault grande conviene dal testo; un
    # export da milioni di token su un vault piccolo conviene dal vault. Si
    # sceglie la piu' economica: il risultato e' identico.
    vault_rows = vault.db.execute(
        "SELECT COUNT(*) FROM mappings WHERE kind IN (%s)"
        % ",".join("?" * len(active)), tuple(active)).fetchone()[0]
    if not vault_rows:
        return text, 0
    if len(candidates) * max(1, len(order)) > vault_rows * 2:
        return _sweep_from_vault(vault, text, effective_opt, active, prose)

    lookup: dict[str, str] = {}
    for cand in candidates:
        norm = cand.lower()
        for kind in order:
            row = vault.db.execute(
                "SELECT pseudonym FROM mappings WHERE bidx=?",
                (blind_index(vault.master, kind, norm),)).fetchone()
            if not row:
                continue
            pseudo = row[0]
            if kind in {"ipv4", "ipv6"} and not effective_opt.should_anonymize_ip(cand):
                break
            if kind in {"fqdn", "endpoint"} and not sweepable_host_original(cand):
                break                        # v0.21.6: parola comune / nome file
            if prose and not sweepable_prose_original(cand):
                break                        # v0.23.2: parola comune in prosa
            if pseudo.lower() != norm:
                lookup[norm] = pseudo
            break

    if not lookup:
        return text, 0

    # Le coppie vanno tentate prima dei token singoli, altrimenti "Mario" verrebbe
    # sostituito da solo lasciando "Rossi" scollegato.
    multi = sorted((k for k in lookup if " " in k), key=len, reverse=True)
    hits = 0
    for key in multi:
        rx = re.compile(r"(?<![\w.@\-])" + re.escape(key) + r"(?![\w.@\-])",
                        re.IGNORECASE)
        text, n = rx.subn(lookup[key], text)
        hits += n

    single = {k: v for k, v in lookup.items() if " " not in k}
    if single:
        def _swap(m: "re.Match") -> str:
            nonlocal hits
            repl = single.get(m.group(0).lower())
            if repl is None:
                return m.group(0)
            hits += 1
            return repl
        text = SWEEP_TOKEN_RX.sub(_swap, text)
    return text, hits


# ------------------------------------------------- residual redaction (safe)

# file extensions that look like a TLD to the wide matcher but are not hosts
FILE_EXTS = {
    "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "js", "ts", "py",
    "sh", "txt", "log", "tmp", "dat", "ini", "cfg", "conf", "json", "xml",
    "yml", "yaml", "csv", "tsv", "zip", "rar", "gz", "tar", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "pdf", "msi", "lnk", "iso", "bin", "db",
    "bak", "old", "html", "htm", "css", "php", "aspx", "jar", "so", "ko",
}
RESIDUAL_EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\b")
RESIDUAL_FQDN_RX = re.compile(r"\b(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}\b")
UUID_RX = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
IBAN_RX = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.IGNORECASE)
# v0.21.2: il codice fiscale va riconosciuto anche quando e' incastonato in un
# token piu' grande separato da caratteri non alfanumerici, non solo isolato.
# Un CF in un segmento di path Windows ("...\\Temp\\tmpxq_VRGSRA76B55H501Z\\")
# sfuggiva perche' "_" e' un word-char e \b non scattava. I confini sono ora
# "non lettera-non cifra": abbracciano _ . - ~ / \\ (separatori di path/token).
# Il rischio di falso positivo resta nullo perche' ogni match e' validato col
# carattere di controllo del CF (_valid_codice_fiscale).
CF_RX = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z](?![A-Za-z0-9])",
    re.IGNORECASE)
# v0.25.1 - identita' dichiarate come coppia chiave/valore nel TESTO.
#
# Il messaggio di un evento Windows ("An account was successfully logged on.
# ... Account Name: mrossi ... Account Domain: CORP ... Workstation Name:
# WKS0421") e un to_json_string(...) serializzato dentro una cella
# ("SubjectUserName": "mrossi") contengono l'identita' in chiaro, ma senza la
# sintassi che il motore riconosce (user=..., DOMINIO\utente, @dominio): il
# nome utente restava intatto. E' la stessa fuga qualunque sia il prodotto -
# lo stesso testo compare in Elastic (message), Wazuh (full_log), Splunk
# (_raw) - quindi la regola vale ovunque, non solo per Cortex.
#
# Il valore e' delimitato in modo stretto (niente spazi, virgolette, virgole)
# e i segnaposto dei log Windows ("-", "N/A", "0x0", "%%1833") sono esclusi:
# mascherarli produrrebbe rumore senza proteggere nulla.
_IDENTITY_KV_VALUE = r"(?P<value>\"[^\"\r\n]{1,64}\"|'[^'\r\n]{1,64}'|[^\s\",;}\]]{1,64})"
_IDENTITY_KV_SEP = r"\s*\"?\s*[:=]\s*"
IDENTITY_KV_USER_RX = re.compile(
    r"(?i)(?<![\w.])(?P<key>(?:subject|target|caller|primary|client|logon|new|old)?"
    r"[ _]?(?:account|user|sam[ _]?account|member)[ _]?names?|upn|"
    r"user[ _]?principal[ _]?name)" + _IDENTITY_KV_SEP + _IDENTITY_KV_VALUE)
IDENTITY_KV_DOMAIN_RX = re.compile(
    r"(?i)(?<![\w.])(?P<key>(?:subject|target|caller|client|account)?"
    r"[ _]?domain(?:[ _]?names?)?|workgroup)" + _IDENTITY_KV_SEP + _IDENTITY_KV_VALUE)
IDENTITY_KV_HOST_RX = re.compile(
    r"(?i)(?<![\w.])(?P<key>(?:workstation|computer|machine|host|source[ _]?workstation|"
    r"client)[ _]?names?|dnshostname)" + _IDENTITY_KV_SEP + _IDENTITY_KV_VALUE)
# v0.26.2 - "User mrossi logged on to ...": l'identita' segue la parola
# "user"/"account" senza due punti, nei raw_log e nei messaggi di regola.
#
# La versione 0.25.2 accettava QUALSIASI parola dopo "user"/"account" tranne
# una lista di stopword. Era troppo larga: "user experience", "account
# balance", "user story", "account manager", "user input" - frasi
# comunissime in log e documenti - venivano corrotte. Un blocklist di parole
# comuni e' una battaglia persa in partenza.
#
# Ora servono DUE segnali, non uno. Il valore viene mascherato solo se:
#   a) ha forma di identificatore - contiene una cifra, un punto o un
#      underscore (m.bianchi, svc_backup, user01): quasi nessuna parola inglese
#      o italiana comune ce l'ha dopo "user"/"account"; OPPURE
#   b) e' seguito, entro poche parole, da un verbo di autenticazione (logged,
#      authenticated, accesso, effettuato...): e' cio' che distingue "User
#      mrossi logged on" da "user experience good".
# Cosi' "mrossi"/"gverdi" nudi passano solo dentro una frase di login vera.
_AUTH_VERB = (r"(?:logged|logon|logoff|log[ ]?in|log[ ]?out|signed|sign[ -]?in|"
              r"authenticated|accessed|connected|disconnected|impersonat\w*|"
              r"effettu[a-z]*|accesso|autenticat\w*|conness\w*|disconness\w*|"
              r"loggat\w*|entrat\w*)")
IDENTITY_PROSE_RX = re.compile(
    r"(?i)\b(?:logon[ ]user|by[ ]user|for[ ]user|user|username|utente|account)\s+"
    r"(?P<value>[A-Za-z][\w.\-]{2,63})(?![\w.@-])"
    r"(?=(?:[ ]+\S+){0,3}?[ ]+" + _AUTH_VERB + r"\b|.{0,40}$)")
# Forma di identificatore: cifra, punto o underscore (non il trattino, comune
# in parole tipo "well-known", "sign-in").
_PROSE_IDENTIFIER_SHAPE = re.compile(r"[0-9._]")
# Due filtri, non uno: la forma-identificatore / contesto-auth sopra scarta le
# parole comuni RARE ("experience", "balance"), questa lista scarta le parole
# di STRUTTURA e le funzioni grammaticali, che invece un verbo di auth vicino
# farebbe passare per errore ("account WAS successfully logged on").
IDENTITY_PROSE_STOPWORDS = frozenset({
    # struttura dei log
    "name", "names", "agent", "account", "accounts", "id", "ids", "sid", "dn",
    "session", "sessions", "group", "groups", "domain", "profile", "object",
    "activity", "action", "principal", "context", "data", "info", "information",
    "details", "type", "types", "list", "count", "access", "login", "logon",
    "logout", "logoff", "record", "event", "status", "result", "reason",
    # nomi comuni che seguono spesso "user"/"account" in prosa
    "request", "requests", "input", "output", "interface", "experience",
    "story", "balance", "manager", "guide", "guides", "settings", "permission",
    "permissions", "credentials", "role", "roles", "rights", "mode", "config",
    "configuration", "preference", "preferences", "error", "errors", "warning",
    "warnings", "feedback", "consent", "response", "number", "level", "story",
    "agent", "space", "story", "friendly", "defined", "provided", "based",
    # verbi/stati che possono seguire user/account
    "created", "deleted", "modified", "added", "removed", "enabled", "disabled",
    "locked", "unlocked", "logged", "signed", "authenticated", "connected",
    # funzioni grammaticali (EN)
    "was", "were", "is", "are", "be", "been", "has", "have", "had", "not",
    "with", "without", "from", "and", "or", "the", "a", "an", "this", "that",
    "successfully", "failed", "successful", "unsuccessful", "by", "for", "to",
    "of", "on", "in", "at", "as", "authentication", "authorization",
    # funzioni grammaticali (IT)
    "e", "ed", "di", "del", "della", "dei", "delle", "che", "non", "con",
    "per", "il", "lo", "la", "le", "un", "una", "ha", "ho", "hanno", "stato",
    "stata", "creato", "eliminato", "modificato", "abilitato", "disabilitato",
    "bloccato", "sbloccato", "connesso", "autenticato", "effettuato",
})


# Segnaposto dei log Windows: non sono identita'.
IDENTITY_KV_PLACEHOLDERS = frozenset({
    "-", "--", "n/a", "na", "null", "none", "nessuno", "0x0", "0", "",
    "unknown", "sconosciuto", "localhost", "localsystem", "system",
    "anonymous logon", "nt authority", "workgroup", "true", "false",
})


def _identity_kv_value_ok(value: str) -> bool:
    token = value.strip().strip("\"'")
    if not token or token.lower() in IDENTITY_KV_PLACEHOLDERS:
        return False
    if token.startswith("%%") or token.startswith("0x"):
        return False
    return not PSEUDO_RX.fullmatch(token)


SECRET_KV_RX = re.compile(
    r"(?i)\b(?P<key>password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|authorization|cookie|session(?:id|_id)?)\b"
    r"\s*(?:[:=]\s*|\s+)(?P<value>Bearer\s+[^\s,;]+|Basic\s+[^\s,;]+|"
    r"\"[^\"\r\n]{4,}\"|'[^'\r\n]{4,}'|[^\s,;]{6,})"
)

# v0.15.0: prose guard — "Login session opened." (PAM/Wazuh) is not a leaked
# session token. Applies ONLY to the bare key "session" with a whitespace
# separator and a plain lowercase word as value; password/secret/token keys
# and any ":"/"=" assignment stay aggressive (fail-closed).
SESSION_PROSE_RX = re.compile(r"[a-z]{3,12}\.?")
# v0.23.5: il separatore dopo l'etichetta era SOLO ":" o "=", quindi la forma
# piu' comune nelle firme e nei documenti italiani - "tel. +39 335 1234567",
# "Telefono +39 06 ..." - non veniva mai rilevata. Ora bastano un punto o uno
# spazio. Il valore richiede comunque almeno 8 caratteri di numero: "cell 42"
# non matcha.
PHONE_LABELED_RX = re.compile(
    r"(?i)\b(?:tel(?:efono)?|phone|mobile|cell(?:ulare)?)\b\.?\s*[:=]?\s*"
    r"(?P<value>\+?\d[\d .()/-]{6,}\d)"
)
# Numero internazionale nudo: prefisso +CC e gruppi separati da spazi, oppure
# +9..15 cifre attaccate. La forma col "+" e' abbastanza inequivocabile da non
# richiedere un'etichetta; i fusi orari (+0200) restano fuori perche' hanno 4
# cifre e nessun gruppo successivo.
PHONE_INTL_RX = re.compile(
    r"(?<![\w+])\+\d{1,3}(?:[ ]\d{1,7}){1,5}(?!\d)"
    r"|(?<![\w+])\+\d{9,15}(?!\d)"
)


# ------------------------------------------------------- v0.25.0: P.IVA e VAT
VAT_LABEL = (r"(?:p(?:artita)?\.?\s?iva|piva|vat(?:[ _-]?(?:id|no|number|reg(?:istration)?"
             r"(?:[ _-]?(?:no|number))?))?|tva|ust[ _-]?id|btw|nif|cif|abn|gst)")
VAT_LABELED_RX = re.compile(
    r"(?i)\b" + VAT_LABEL + r"\b\.?\s*[:=]?\s*"
    r"(?P<value>(?:[A-Z]{2}[ ]?)?[A-Z0-9][A-Z0-9.\-]{5,14})")
# Forme con prefisso paese: inequivocabili anche senza etichetta.
VAT_EU_RX = re.compile(
    r"(?<![A-Za-z0-9])("
    r"IT\d{11}|DE\d{9}|FR[A-Z0-9]{2}\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|"
    r"NL\d{9}B\d{2}|BE0\d{9}|ATU\d{8}|PT\d{9}|"
    r"GB(?:\d{9}(?:\d{3})?|GD\d{3}|HA\d{3})|CHE-?\d{3}\.?\d{3}\.?\d{3}"
    r")(?![A-Za-z0-9])")


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 != parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _valid_vat(value: str) -> bool:
    """Partita IVA formalmente valida.

    Le 11 cifre nude sono una forma comunissima anche fuori dalla fiscalita'
    (identificativi, timestamp, numeri di record): senza il controllo di Luhn
    una P.IVA nuda produrrebbe una valanga di falsi positivi nei log. Per gli
    altri paesi si richiede il prefisso nazionale, che e' gia' inequivocabile.
    """
    compact = re.sub(r"[ .\-]", "", value or "").upper()
    if not 8 <= len(compact) <= 14:
        return False
    if compact.startswith("IT") and len(compact) == 13 and compact[2:].isdigit():
        return _luhn_ok(compact[2:])
    if compact.isdigit():
        return len(compact) == 11 and _luhn_ok(compact)
    return bool(re.fullmatch(r"[A-Z]{2}[A-Z0-9]{6,12}", compact))


# -------------------------------------------- v0.25.0: indirizzi IT e inglesi
IT_STREET = (r"(?i:via|viale|v\.le|vicolo|piazz(?:a|ale)|p\.zza|corso|c\.so|largo|strada|"
             r"contrada|borgo|lungomare|salita|calle|fondamenta|traversa|circonvallazione|"
             r"localit[aà]|loc\.|frazione|fraz\.)")
# Suffissi FORTI: in inglese non compaiono quasi mai fuori da un indirizzo.
EN_SUFFIX_STRONG = (r"(?i:street|st\.|road|rd\.|avenue|ave\.?|boulevard|blvd\.?|lane|ln\.|"
                    r"highway|hwy\.?|parkway|pkwy\.?)")
# Nome proprio: iniziale maiuscola e resto minuscolo. Serve a distinguere
# "via Roma 12" da "via VPN 2" e "via proxy 8080": in un log SOC "via" e'
# quasi sempre la preposizione ("installazione via processo anomalo",
# "esfiltrazione via DNS"), e mascherarlo distruggerebbe la descrizione.
_ADDR_PROPER = r"[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ'’.\-]{1,}"
_ADDR_TOKEN = r"[A-Za-z0-9À-ÖØ-Ýà-öø-ÿ'’.\-]+"
_ADDR_NUM = r"\d{1,4}[/\-]?[A-Za-z]?"

ADDRESS_IT_RX = re.compile(
    r"(?<![\w/\\])" + IT_STREET + r"\s+(?P<name>" + _ADDR_PROPER +
    r"(?:\s+" + _ADDR_TOKEN + r"){0,4}),?\s*(?:n(?:um)?\.?|nr\.?)?\s*"
    r"(?P<num>" + _ADDR_NUM + r")(?![\w])")
ADDRESS_EN_RX = re.compile(
    r"(?<![\w/\\.])(?P<num>\d{1,5}[A-Za-z]?)\s+(?P<name>" + _ADDR_PROPER +
    r"(?:\s+" + _ADDR_TOKEN + r"){0,3})\s+" + EN_SUFFIX_STRONG + r"(?![\w])")
ADDRESS_LABEL = (r"(?:indirizzo|address|residenza|domicilio|sede(?:[ _-]?legale)?|"
                 r"street[ _-]?address|mailing[ _-]?address|billing[ _-]?address|"
                 r"shipping[ _-]?address|home[ _-]?address)")
ADDRESS_LABELED_RX = re.compile(
    r"(?i)\b" + ADDRESS_LABEL + r"\b\.?\s*[:=]?\s*"
    r"(?P<value>(?:" + IT_STREET + r"|\d{1,5}[A-Za-z]?)\s[^\r\n;|]{3,120}?)"
    r"(?=[\r\n;|]|$|\s{2,})")
ADDRESS_POBOX_RX = re.compile(
    r"(?i)(?<![\w/\\])(?:p\.?\s?o\.?\s?box|casella\s+postale|c\.p\.)\s*\d{1,7}(?![\w])")


def _iban_candidates(value: str):
    """v0.23.5: il match IBAN e i suoi prefissi ai confini di spazio.

    Lo spazio opzionale del pattern fa proseguire il match dentro le parole
    successive: "IT60...456 poi" diventa un unico candidato, il mod-97
    fallisce sul blob esteso e l'IBAN vero non viene MAI riesaminato, perche'
    la scansione riparte dopo il match. In prosa italiana ("bonifico su
    DE89... eseguito") il mascheramento falliva quasi sempre. Qui si riprova
    togliendo una parola alla volta da destra.
    """
    yield value
    while " " in value:
        value = value.rsplit(" ", 1)[0]
        yield value


def _valid_iban(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not (15 <= len(compact) <= 34) or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def _valid_codice_fiscale(value: str) -> bool:
    cf = value.upper()
    if not CF_RX.fullmatch(cf):
        return False
    odd = {
        "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15,
        "7": 17, "8": 19, "9": 21, "A": 1, "B": 0, "C": 5, "D": 7,
        "E": 9, "F": 13, "G": 15, "H": 17, "I": 19, "J": 21,
        "K": 2, "L": 4, "M": 18, "N": 20, "O": 11, "P": 3,
        "Q": 6, "R": 8, "S": 12, "T": 14, "U": 16, "V": 10,
        "W": 22, "X": 25, "Y": 24, "Z": 23,
    }
    even = {str(i): i for i in range(10)} | {chr(65 + i): i for i in range(26)}
    total = sum(odd[c] if i % 2 == 0 else even[c] for i, c in enumerate(cf[:15]))
    return cf[15] == chr(65 + total % 26)


def scan_sensitive_residuals(text: str, dlp_policy: dict[str, str] | None = None,
                             *, allow_url_hosts: bool = False) -> list[dict[str, object]]:
    """Return high-confidence sensitive tokens still present in output.

    This is deliberately independent from the main masking pass.  It is used
    as a final gate: safe mode redacts the findings; unsafe mode reports them
    and the web UI blocks the copy action.
    """
    candidates: list[tuple[int, int, int, str, str]] = []
    policy = normalize_dlp_policy(dlp_policy)
    residual_category = {
        "secret": "credentials", "jwt": "credentials", "uuid": "cloud_id",
        "iban": "iban", "codice_fiscale": "tax_id", "phone": "phone",
        "vat": "vat_id", "address": "address",
    }

    def add(kind: str, start: int, end: int, value: str, priority: int = 50):
        category = residual_category.get(kind)
        if category and policy.get(category) == "keep":
            return
        raw_token = value.strip()
        if ELIDED in raw_token:
            remainder = raw_token.replace(ELIDED, "").strip(" \t\r\n\"'},{")
            if not remainder:
                return
        token = raw_token.strip('\"\'')
        if not token or token == ELIDED or PSEUDO_RX.fullmatch(token):
            return
        candidates.append((start, end, priority, kind, value))

    for m in SECRET_KV_RX.finditer(text):
        key = (m.group("key") or "").lower()
        sep = text[m.end("key"):m.start("value")]
        if key == "session" and ":" not in sep and "=" not in sep \
                and SESSION_PROSE_RX.fullmatch(m.group("value")):
            continue          # "session opened." e simili: prosa, non token
        add("secret", m.start("value"), m.end("value"), m.group("value"), 100)
    for m in JWT_RX.finditer(text):
        add("jwt", m.start(), m.end(), m.group(0), 95)
    for m in RESIDUAL_EMAIL_RX.finditer(text):
        add("email", m.start(), m.end(), m.group(0), 90)
    for m in UUID_RX.finditer(text):
        if m.group(0).lower() in WELL_KNOWN_GUIDS:
            continue
        add("uuid", m.start(), m.end(), m.group(0), 70)
    for m in IBAN_RX.finditer(text):
        for cand in _iban_candidates(m.group(0)):
            if _valid_iban(cand):
                add("iban", m.start(), m.start() + len(cand), cand, 90)
                break
    for m in CF_RX.finditer(text):
        if _valid_codice_fiscale(m.group(0)):
            add("codice_fiscale", m.start(), m.end(), m.group(0), 90)
    for m in PHONE_LABELED_RX.finditer(text):
        add("phone", m.start("value"), m.end("value"), m.group("value"), 80)
    for m in PHONE_INTL_RX.finditer(text):
        # almeno 9 cifre totali: "+39 06 4952 1" passa, "+12 34" no.
        if sum(ch.isdigit() for ch in m.group(0)) >= 9:
            add("phone", m.start(), m.end(), m.group(0), 78)
    for m in VAT_LABELED_RX.finditer(text):
        value = m.group("value").rstrip(".-")
        if _valid_vat(value):
            add("vat", m.start("value"), m.start("value") + len(value), value, 92)
    for m in VAT_EU_RX.finditer(text):
        if _valid_vat(m.group(0)):
            add("vat", m.start(), m.end(), m.group(0), 90)
    for m in ADDRESS_LABELED_RX.finditer(text):
        add("address", m.start("value"), m.end("value"), m.group("value"), 84)
    for m in ADDRESS_IT_RX.finditer(text):
        add("address", m.start(), m.end(), m.group(0), 80)
    for m in ADDRESS_EN_RX.finditer(text):
        add("address", m.start(), m.end(), m.group(0), 80)
    for m in ADDRESS_POBOX_RX.finditer(text):
        add("address", m.start(), m.end(), m.group(0), 80)
    for m in RESIDUAL_FQDN_RX.finditer(text):
        tok = m.group(0)
        tld = tok.rsplit(".", 1)[-1].lower()
        if tok.lower() in RESERVED_HOSTS or tld in FILE_EXTS or ".masked" in tok:
            continue
        # v0.10.9: only real TLDs count as residual hosts. Dotted code
        # identifiers such as "$left.SubjectLogonId" in KQL are not leaks.
        if tld not in TLDS:
            continue
        # v0.10.10: in IOC fields the URL host is detection content — skip
        # tokens glued to a URL (preceded by "//", "/" or userinfo "@").
        if allow_url_hosts and text[max(0, m.start() - 2):m.start()].endswith(("/", "@")):
            continue
        add("fqdn", m.start(), m.end(), tok, 60)

    # Keep the highest-priority/longest non-overlapping finding for each span.
    candidates.sort(key=lambda x: (x[0], -x[2], -(x[1] - x[0])))
    selected: list[tuple[int, int, int, str, str]] = []
    for cand in candidates:
        start, end = cand[0], cand[1]
        if any(start < other[1] and end > other[0] for other in selected):
            continue
        selected.append(cand)
    selected.sort(key=lambda x: x[0])
    return [
        {"kind": kind, "start": start, "end": end, "value": value}
        for start, end, _priority, kind, value in selected
    ]


# v0.23.0: policy usata per documenti e archivi di posta. Le tre categorie che
# di serie diventano [ELIDED] passano a pseudonimo: in un .docx o in un .pst
# l'elisione distrugge il testo e rende impossibile il ripristino. I segreti
# restano comunque irreversibili, perche' _map("secret", ...) non li vaulta.
NO_ELISION_DLP_POLICY = {
    "credentials": "pseudonymize",
    "private_key": "pseudonymize",
    "sensitive_url": "pseudonymize",
}


# v0.23.0: kind del residuo -> kind del vault. Chi non compare qui non passa
# dal vault: vedi NON_VAULTED_RESIDUAL_KINDS.
RESIDUAL_KIND_TO_MAP = {
    "iban": "iban", "codice_fiscale": "taxid", "phone": "phone", "uuid": "cloud",
    "vat": "vat", "address": "address",
}
# Segreti: token deterministico ma MAI scritto nel vault.
NON_VAULTED_RESIDUAL_KINDS = frozenset({"secret", "jwt"})


def pseudonymize_residuals(text: str, anon, dlp_policy: dict[str, str] | None = None,
                           *, allow_url_hosts: bool = False) -> tuple[str, int, list[str]]:
    """Come redact_residuals, ma SOSTITUISCE invece di elidere.

    In un documento .docx o in un archivio .pst l'elisione e' un danno netto:
    il file restituito perde il testo e il ripristino non puo' ricostruirlo,
    perche' non c'e' niente da invertire. Qui ogni residuo diventa uno
    pseudonimo:

      - IBAN, codice fiscale, telefono e identificatori cloud passano dal vault
        del tenant e restano REVERSIBILI come tutto il resto;
      - credenziali, chiavi private e token restano deterministici ma non
        vengono MAI scritti nel vault: stesso segreto -> stesso token, quindi
        le occorrenze restano correlabili, ma il valore non e' recuperabile e
        lo strumento non finisce per custodire i segreti del cliente.

    I campioni restituiti sono i TIPI trovati, mai i valori: un campione di un
    segreto sarebbe esso stesso una fuga.
    """
    policy = normalize_dlp_policy(dlp_policy)
    findings = scan_sensitive_residuals(text, policy, allow_url_hosts=allow_url_hosts)
    if not findings:
        return text, 0, []
    out = text
    kinds: list[str] = []
    for finding in reversed(findings):
        kind = str(finding["kind"])
        value = str(finding["value"])
        token = value.strip()
        if anon.vault.owns(token):
            continue                       # gia' un nostro pseudonimo: non toccarlo
        if kind in NON_VAULTED_RESIDUAL_KINDS:
            repl = anon._secret_token(token)
        else:
            mapped = RESIDUAL_KIND_TO_MAP.get(kind) or (kind if kind in BUILDERS else "opaque")
            repl = anon._map(mapped, token)
        start, end = int(finding["start"]), int(finding["end"])
        out = out[:start] + repl + out[end:]
        kinds.append(kind)
    if not kinds:
        return text, 0, []
    samples = list(dict.fromkeys(reversed(kinds)))[:10]
    return out, len(kinds), samples


def redact_residuals(text: str, dlp_policy: dict[str, str] | None = None,
                     *, allow_url_hosts: bool = False) -> tuple[str, int, list[str]]:
    """Irreversibly elide high-confidence sensitive residuals."""
    policy = normalize_dlp_policy(dlp_policy)
    findings = scan_sensitive_residuals(text, policy, allow_url_hosts=allow_url_hosts)
    if not findings:
        return text, 0, []
    residual_category = {
        "secret": "credentials", "jwt": "credentials", "uuid": "cloud_id",
        "iban": "iban", "codice_fiscale": "tax_id", "phone": "phone",
        "vat": "vat_id", "address": "address",
    }
    redactable = [
        finding for finding in findings
        if policy.get(residual_category.get(str(finding["kind"]), "")) != "block"
    ]
    if not redactable:
        return text, 0, []
    out = text
    for finding in reversed(redactable):
        start, end = int(finding["start"]), int(finding["end"])
        out = out[:start] + ELIDED + out[end:]
    samples = list(dict.fromkeys(str(f["value"]) for f in redactable))[:10]
    return out, len(redactable), samples


# ---------------------------------------------------------------- CSV engine

# multi-value cells: Elastic often exports arrays, XSIAM pipes/commas
SPLIT_RX = re.compile(r'(\s*[,;|]\s*|\s+)')
# identity values legitimately contain spaces ("NT AUTHORITY", "Mario Rossi"):
# split them only on explicit delimiters, never on bare whitespace
SPLIT_RX_DELIM = re.compile(r'(\s*[,;|]\s*)')
IDENTITY_KINDS = {"user", "windomain", "winuser", "sid"}
ARRAY_RX = re.compile(r"^\[(.*)\]$", re.DOTALL)


def sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.get_dialect("excel")


def _nul_free(fh):
    """v0.23.3: righe senza byte NUL.

    Il modulo csv di Python solleva "line contains NUL" e si ferma. Gli export
    Elastic Discover di eventi Windows contengono spesso NUL - residui di
    stringhe UTF-16 dentro winlog.event_data - quindi un export perfettamente
    normale faceva fallire l'intera anonimizzazione con un errore che non
    diceva nulla. Il NUL non ha alcun valore analitico: si toglie e si prosegue.
    """
    for line in fh:
        yield line.replace("\x00", "") if "\x00" in line else line


def read_samples(path: Path, n: int = 200) -> tuple[list[str], dict[str, list[str]], csv.Dialect]:
    csv.field_size_limit(10_000_000)
    with open(path, newline="", errors="replace") as raw:
        head = raw.read(64_000).replace("\x00", "")
        raw.seek(0)
        dialect = sniff_dialect(head)
        reader = csv.DictReader(_nul_free(raw), dialect=dialect)
        columns = reader.fieldnames or []
        samples: dict[str, list[str]] = {c: [] for c in columns}
        for i, row in enumerate(reader):
            if i >= n:
                break
            for c in columns:
                v = (row.get(c) or "").strip()
                if v:
                    samples[c].append(v)
    return columns, samples, dialect


class CsvAnonymizer:
    """Field-aware CSV masking driven by a policy; text columns use final DLP checks."""

    def __init__(self, anon: Anonymizer, policy: dict, source: str,
                 safe: bool = False):
        self.anon = anon
        self.policy = policy
        self.source = source
        self.safe = safe
        self.stats_rows = 0
        self.elided = 0
        self.elided_samples: list[str] = []
        self.failed = 0
        self.failed_samples: list[str] = []
        # col -> [nonempty, masked, elided, failed]
        self.per_col: dict[str, list[int]] = {}  # nonempty, masked, elided, failed, policy_kept

    @staticmethod
    def _placeholder(value: str) -> bool:
        return not value or value.lower() in {"-", "n/a", "null", "none"}

    def _mask_scalar(self, kind: str, value: str) -> tuple[str, bool]:
        """Return (output, handled).

        handled=False means a field declared sensitive could not be safely
        transformed. The caller either elides the whole cell (safe mode) or
        marks the output as blocked.
        """
        v = value.strip()
        if self._placeholder(v):
            return value, True
        if kind == "endpoint":
            if valid_ipv4(v):
                kind = "ipv4"
            elif ":" in v and valid_ipv6(v):
                kind = "ipv6"
            else:
                kind = "fqdn"
        if kind == "ip_strict":
            # Tenant-identifying address fields (e.g. lastExternalIpAddress):
            # always pseudonymized, whatever the ip_mode policy says.
            if valid_ipv4(v):
                return self.anon._map("ipv4", v), True
            if valid_ipv6(v):
                return self.anon._map("ipv6", v), True
            return value, False
        if kind == "ip":
            if valid_ipv4(v):
                kind = "ipv4"
            elif valid_ipv6(v):
                kind = "ipv6"
            else:
                return value, False
        if kind == "ipv4":
            if not valid_ipv4(v):
                return value, False
            if not self.anon.opt.should_anonymize_ip(v):
                self.anon._keep_ip_by_policy("ipv4")
                return value, True
            if self.anon.opt.preserve_subnet:
                self.anon.counts["ipv4"] += 1
                return pseudo_ipv4_subnet(self.anon.vault, v, self.anon.opt), True
            return self.anon._map("ipv4", v), True
        if kind == "ipv6":
            if not valid_ipv6(v):
                return value, False
            if not self.anon.opt.should_anonymize_ip(v):
                self.anon._keep_ip_by_policy("ipv6")
                return value, True
            return self.anon._map("ipv6", v), True
        if kind == "mac":
            if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", v):
                return value, False
            return self.anon._map("mac", v, norm=v.replace("-", ":").lower()), True
        if kind == "sid":
            if not re.fullmatch(r"S-1-(?:\d+-){1,14}\d+", v, re.IGNORECASE):
                return value, False
            return self.anon.map_sid(v), True
        if kind == "windomain":
            return self.anon.map_windomain(v), True
        if kind == "winuser":
            if "\\" not in v:
                return value, False
            dom, _, usr = v.partition("\\")
            if not dom or not usr:
                return value, False
            return f"{self.anon.map_windomain(dom)}\\{self.anon.map_user(usr)}", True
        if kind == "user":
            if "\\" in v:
                dom, _, usr = v.partition("\\")
                if not usr:
                    return value, False
                if dom.lower() in NOT_DOMAINS:
                    return self.anon.map_user(usr), True
                return f"{self.anon.map_windomain(dom)}\\{self.anon.map_user(usr)}", True
            if "@" in v:
                if re.fullmatch(PATTERNS["email"], v, re.IGNORECASE):
                    return self.anon._map("email", v), True
                if UPN_RX.fullmatch(v):
                    return self.anon._map_upn(v), True
                return value, False
            return self.anon.map_user(v), True
        if kind == "email":
            if re.fullmatch(PATTERNS["email"], v, re.IGNORECASE):
                return self.anon._map("email", v), True
            if UPN_RX.fullmatch(v):
                return self.anon._map_upn(v), True
            return value, False
        if kind == "fqdn":
            return self.anon._map("fqdn", v), True
        if kind == "opaque":
            return self.anon._map("opaque", v), True
        return value, False

    def _mask_cell(self, kind: str, cell: str) -> tuple[str, list[str]]:
        """Handle scalars, JSON arrays and delimiter-separated multi-values."""
        if not cell.strip():
            return cell, []
        m = ARRAY_RX.match(cell.strip())
        if m:
            inner = m.group(1)
            try:
                items = json.loads(cell)
                if isinstance(items, list):
                    output, failures = [], []
                    for item in items:
                        masked, handled = self._mask_scalar(kind, str(item))
                        output.append(masked)
                        if not handled:
                            failures.append(str(item))
                    return json.dumps(output, separators=(",", ":")), failures
            except (json.JSONDecodeError, TypeError):
                pass
            masked, failures = self._mask_cell(kind, inner)
            return "[" + masked + "]", failures
        rx = SPLIT_RX_DELIM if kind in IDENTITY_KINDS else SPLIT_RX
        parts = rx.split(cell)
        if len(parts) > 1:
            output, failures = [], []
            for part in parts:
                if rx.fullmatch(part):
                    output.append(part)
                else:
                    masked, handled = self._mask_scalar(kind, part)
                    output.append(masked)
                    if not handled and part.strip():
                        failures.append(part.strip())
            return "".join(output), failures
        masked, handled = self._mask_scalar(kind, cell)
        return masked, ([] if handled else [cell.strip()])

    def _remember(self, collection: list[str], values: list[str]):
        for value in values:
            if len(collection) < 10 and value not in collection:
                collection.append(value)

    def process(self, inp: Path, out, dialect, columns: list[str]):
        cols_pol = self.policy.get("columns", {})
        default = self.policy.get("default", "keep")
        csv.field_size_limit(10_000_000)

        with open(inp, newline="", errors="replace") as raw:
            fh = _nul_free(raw)
            reader = csv.DictReader(fh, dialect=dialect)
            writer = csv.DictWriter(out, fieldnames=columns,
                                    delimiter=dialect.delimiter,
                                    quoting=csv.QUOTE_MINIMAL,
                                    extrasaction="ignore")
            writer.writeheader()
            for row in reader:
                self.stats_rows += 1
                newrow = {}
                for c in columns:
                    cell = row.get(c) or ""
                    spec = cols_pol.get(c, {"action": default, "kind": None})
                    action = spec.get("action", default)
                    st = self.per_col.setdefault(c, [0, 0, 0, 0, 0])
                    if cell.strip():
                        st[0] += 1
                    if action == "drop":
                        newrow[c] = ""
                    elif action == "redact":
                        if cell.strip():
                            newrow[c] = ELIDED
                            st[2] += 1
                            self.elided += 1
                            self._remember(self.elided_samples, [cell])
                        else:
                            newrow[c] = cell
                    elif action == "mask" and cell.strip():
                        before = sum(self.anon.counts.values())
                        before_policy_kept = sum(self.anon.policy_kept.values())
                        masked_cell, failures = self._mask_cell(spec.get("kind") or "ip", cell)
                        st[4] += sum(self.anon.policy_kept.values()) - before_policy_kept
                        if failures:
                            if self.safe:
                                newrow[c] = ELIDED
                                st[2] += 1
                                self.elided += 1
                                self._remember(self.elided_samples, failures)
                            else:
                                newrow[c] = masked_cell
                                st[3] += len(failures)
                                self.failed += len(failures)
                                self._remember(self.failed_samples, failures)
                        else:
                            newrow[c] = masked_cell
                        if sum(self.anon.counts.values()) > before and newrow[c] != ELIDED:
                            st[1] += 1
                    elif action == "text" and cell.strip():
                        before = sum(self.anon.counts.values())
                        before_redacted = self.anon.dlp_actions.get("redact", 0)
                        before_blocked = len(self.anon.dlp_blocked)
                        url_ioc = spec.get("kind") == "ioc"
                        out_cell = self.anon.process(cell, url_ioc=url_ioc)
                        # v0.25.2: una colonna di testo (message, raw_log,
                        # description) nomina spesso identita' che la riga
                        # stessa ha gia' mascherato nella colonna dedicata.
                        # Le si sostituisce con lo pseudonimo gia' assegnato,
                        # cosi' la correlazione resta e il valore sparisce.
                        # Solo user/email e solo forme non ambigue: in una
                        # colonna di testo una parola comune finita nel vault
                        # per un falso positivo storico rovinerebbe la frase.
                        if not url_ioc:
                            out_cell, _swept = sweep_known(
                                self.anon.vault, out_cell, self.anon.opt,
                                kinds=TEXT_COLUMN_SWEEP_KINDS, prose=True)
                        dlp_redacted = self.anon.dlp_actions.get("redact", 0) - before_redacted
                        if dlp_redacted:
                            st[2] += dlp_redacted
                            self.elided += dlp_redacted
                            self._remember(self.elided_samples, [cell])
                        new_blocked = self.anon.dlp_blocked[before_blocked:]
                        if new_blocked:
                            st[3] += len(new_blocked)
                            self.failed += len(new_blocked)
                            self._remember(self.failed_samples, [f"DLP:block:{item.get('kind', 'unknown')}" for item in new_blocked])
                        if self.safe:
                            out_cell, n, smp = redact_residuals(out_cell, self.anon.opt.dlp_policy,
                                                                allow_url_hosts=url_ioc)
                            if n:
                                st[2] += n
                                self.elided += n
                                self._remember(self.elided_samples, smp)
                        else:
                            findings = scan_sensitive_residuals(out_cell, self.anon.opt.dlp_policy,
                                                                allow_url_hosts=url_ioc)
                            if findings:
                                st[3] += len(findings)
                                self.failed += len(findings)
                                self._remember(
                                    self.failed_samples,
                                    [str(f["value"]) for f in findings],
                                )
                        newrow[c] = out_cell
                        if sum(self.anon.counts.values()) > before:
                            st[1] += 1
                    else:
                        if cell.strip():
                            before = sum(self.anon.counts.values())
                            before_redacted = self.anon.dlp_actions.get("redact", 0)
                            before_blocked = len(self.anon.dlp_blocked)
                            processed = self.anon.process_dlp_field(c, cell)
                            if sum(self.anon.counts.values()) > before:
                                st[1] += 1
                            redacted_delta = self.anon.dlp_actions.get("redact", 0) - before_redacted
                            if redacted_delta:
                                st[2] += redacted_delta
                                self.elided += redacted_delta
                                self._remember(self.elided_samples, [cell])
                            new_blocked = self.anon.dlp_blocked[before_blocked:]
                            if new_blocked:
                                st[3] += len(new_blocked)
                                self.failed += len(new_blocked)
                                self._remember(self.failed_samples, [f"DLP:block:{item.get('kind', 'unknown')}" for item in new_blocked])
                            newrow[c] = processed
                        else:
                            newrow[c] = cell
                writer.writerow(newrow)

        for c in columns:
            spec = cols_pol.get(c, {"action": default, "kind": None})
            ne, mk, el, failed, _policy_kept = self.per_col.get(c, [0, 0, 0, 0, 0])
            self.anon.vault.register_field(
                self.source, c, spec.get("kind"), spec.get("action", default),
                self.stats_rows, ne, mk, el, failed,
            )


def csv_deanonymize(inp: Path, out, deanon: Deanonymizer):
    csv.field_size_limit(10_000_000)
    with open(inp, newline="", errors="replace") as raw:
        head = raw.read(64_000).replace("\x00", "")
        raw.seek(0)
        dialect = sniff_dialect(head)
        reader = csv.reader(_nul_free(raw), dialect=dialect)
        writer = csv.writer(out, delimiter=dialect.delimiter,
                            quoting=csv.QUOTE_MINIMAL)
        # v0.21.4: reversa OGNI riga, header compreso. Prima la prima riga
        # veniva copiata invariata (presunta header di nomi colonna): un file
        # SENZA header - una singola cella o una lista di pseudonimi, come lo
        # spesso e' un export di un solo valore - non veniva mai ripristinato
        # ("risolti 0"). Il reverse e' mirato: sostituisce solo i valori
        # presenti nel vault del tenant, quindi i veri nomi colonna (che non
        # sono pseudonimi) restano intatti comunque.
        for row in reader:
            writer.writerow([deanon.process(c) for c in row])


# ---------------------------------------------------------------------- CLI


def cli_vault(args) -> tuple[str, Path, Vault]:
    """Open the tenant-isolated vault selected on the command line."""
    try:
        tenant = normalize_tenant_id(args.tenant)
    except ValueError as exc:
        raise SystemExit(f"[!] invalid tenant: {exc}") from exc
    master = load_key(Path(args.key))
    path = tenant_vault_path(Path(args.vault), tenant)
    return tenant, path, Vault(path, derive_tenant_master(master, tenant))


def load_dlp_cli_policy(args) -> dict[str, str] | None:
    overrides: dict[str, str] = {}
    path = getattr(args, "dlp_policy", None)
    if path:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"[!] invalid DLP policy file: {exc}") from exc
        if isinstance(payload, dict) and isinstance(payload.get("categories"), dict):
            payload = payload["categories"]
        if not isinstance(payload, dict):
            raise SystemExit("[!] DLP policy must be a JSON object")
        overrides.update({str(key): str(value) for key, value in payload.items()})
    for item in getattr(args, "dlp", None) or []:
        category, sep, action = item.partition("=")
        if not sep:
            raise SystemExit(f"[!] invalid --dlp value: {item} (expected category=action)")
        overrides[category.strip()] = action.strip()
    try:
        return normalize_dlp_policy(overrides)
    except ValueError as exc:
        raise SystemExit(f"[!] {exc}") from exc


def add_tenant_arg(parser):
    parser.add_argument(
        "--tenant", required=True,
        help="client/tenant identifier; use 'legacy' for a pre-v0.3 vault",
    )


def cmd_init(args):
    key_path = Path(args.key)
    if key_path.exists() and not args.force:
        sys.exit(f"[!] key already exists: {key_path} (use --force to overwrite)")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(base64.b64encode(os.urandom(32)).decode())
    os.chmod(key_path, 0o600)
    print(f"[+] master key generated: {key_path} (mode 600)")
    print("[!] lose this key and the vault becomes irreversible. back it up.")


def cmd_scan(args):
    """Register every column of a CSV export and emit an editable policy."""
    tenant, vault_path, vault = cli_vault(args)
    source = args.source or Path(args.input).stem

    columns, samples, _ = read_samples(Path(args.input), args.sample_rows)
    if not columns:
        sys.exit("[!] no header row found")
    family = canonical_kit_id(args.catalog) or args.catalog or detect_family(columns)
    pol = default_policy(columns, samples, family)

    # side effects first: a broken stdout pipe (e.g. `scan ... | head`)
    # must not kill the run before registry and policy are persisted
    for c in columns:
        spec = pol["columns"][c]
        vault.register_field(source, c, spec["kind"], spec["action"], 0, 0, 0)
    vault.commit()
    out = Path(args.policy or f"{source}.policy.json")
    policy_kept = out.exists() and not args.force
    if not policy_kept:
        out.write_text(json.dumps(pol, indent=2))

    print(f"source: {source}   catalog: {family or 'generic'}"
          f"{' (auto)' if family and not args.catalog else ''}   "
          f"columns: {len(columns)}   sampled rows: {args.sample_rows}\n")
    print(f"  {'COLUMN':<42} {'KIND':<9} {'ACTION':<7} {'BY':<6} SAMPLE VALUES")
    print("  " + "-" * 100)
    for c in columns:
        spec = pol["columns"][c]
        ex = ", ".join(samples.get(c, [])[:2])[:34]
        flag = " " if spec["action"] != "keep" else ("?" if samples.get(c) else " ")
        print(f"{flag} {c[:42]:<42} {str(spec['kind'] or '-'):<9} "
              f"{spec['action']:<7} {spec['inferred_by'] or '-':<6} {ex}")

    masked = sum(1 for s in pol["columns"].values() if s["action"] != "keep")
    print(f"\n  {masked}/{len(columns)} columns will be touched; "
          f"{len(columns) - masked} kept as-is (marked '?' = review these).")

    if policy_kept:
        print(f"\n[!] {out} already exists, not overwritten (use --force)")
    else:
        print(f"\n[+] policy written: {out}  — edit it, then run anonymize --policy {out}")


def cmd_fields(args):
    tenant, vault_path, vault = cli_vault(args)
    rows = vault.fields_report(args.source)
    if not rows:
        print("[-] no fields registered yet (run: logmask scan <file.csv>)")
        return
    print(f"  {'SOURCE':<14} {'COLUMN':<38} {'KIND':<9} {'ACTION':<7} "
          f"{'ROWS':>6} {'NONEMPTY':>9} {'MASKED':>7} {'ELIDED':>7} {'FAILED':>7}")
    print("  " + "-" * 113)
    for src, col, kind, action, rows_seen, ne, mk, el, failed in rows:
        print(f"  {src[:14]:<14} {col[:38]:<38} {str(kind or '-'):<9} "
              f"{action:<7} {rows_seen:>6} {ne:>9} {mk:>7} {el:>7} {failed:>7}")


def cmd_anonymize(args):
    from structured import STRUCTURED_FORMATS, anonymize_structured, detect_structured_format

    tenant, vault_path, vault = cli_vault(args)
    enabled = set(args.types.split(",")) if args.types else set(ORDER)
    opt = Options(
        preserve_subnet=args.preserve_subnet,
        keep_domain=args.keep_domain,
        keep_scope=not args.no_scope,
        ip_mode=args.ip_mode,
        dlp_policy=load_dlp_cli_policy(args),
        client_terms=tuple(
            term.strip()
            for term in os.environ.get("LOGMASK_CLIENT_TERMS", "").split(",")
            if term.strip()
        ),
        client_term_mode=os.environ.get("LOGMASK_CLIENT_TERM_MODE", "pseudonymize"),
        client_term_label=os.environ.get("LOGMASK_CLIENT_TERM_LABEL", "[CLIENTE]"),
        tenant_networks=tuple(
            net.strip()
            for net in os.environ.get("LOGMASK_TENANT_NETWORKS", "").split(",")
            if net.strip()
        ),
        host_terms=tuple(
            term.strip()
            for term in os.environ.get("LOGMASK_HOST_TERMS", "").split(",")
            if term.strip()
        ),
    )
    anon = Anonymizer(vault, enabled, opt)
    inp = Path(args.input)
    text_cache: str | None = None
    fmt = args.format
    if args.csv:
        fmt = "csv"
    if fmt == "auto":
        suffix_map = {
            ".csv": "csv", ".tsv": "csv", ".json": "json",
            ".jsonl": "ndjson", ".ndjson": "ndjson",
            ".cef": "cef", ".leef": "leef",
        }
        fmt = suffix_map.get(inp.suffix.lower(), "")
        if not fmt:
            text_cache = inp.read_text(errors="replace")
            fmt = detect_structured_format(text_cache) or "text"

    if fmt == "csv":
        columns, samples, dialect = read_samples(inp, 200)
        policy = load_policy(Path(args.policy) if args.policy else None)
        family = (policy or {}).get("catalog") or canonical_kit_id(args.catalog) or args.catalog or detect_family(columns)
        if policy is None:
            policy = default_policy(columns, samples, family)
            print("[i] no --policy given: using inferred policy "
                  "(run 'scan' first to review it)", file=sys.stderr)
        if args.safe:
            policy = apply_safe_policy(policy, samples)
        source = args.source or inp.stem
        cp = CsvAnonymizer(anon, policy, source, safe=args.safe)
        with tempfile.NamedTemporaryFile("w+", newline="", delete=False) as tf:
            staged = Path(tf.name)
            cp.process(inp, tf, dialect, columns)
        exposed = 0
        for c in columns:
            spec = policy.get("columns", {}).get(c, {"action": "keep"})
            ne = cp.per_col.get(c, [0, 0, 0, 0])[0]
            inferred_by = str(spec.get("inferred_by") or "")
            vendor_keep = inferred_by.startswith("vendor:")
            if spec.get("action", "keep") == "keep" and ne and not vendor_keep \
                    and not is_safe_column(c, samples.get(c, [])):
                exposed += ne
        blocked = cp.failed + exposed
        if blocked:
            vault.db.rollback()
            staged.unlink(missing_ok=True)
            print(f"[!] output blocked: {cp.failed} failed transformations, "
                  f"{exposed} clear ambiguous values", file=sys.stderr)
            if cp.failed_samples:
                print("    samples: " + ", ".join(cp.failed_samples[:5]), file=sys.stderr)
            raise SystemExit(2)
        vault.commit()
        try:
            if args.output:
                shutil.copyfile(staged, args.output)
            else:
                with staged.open() as src:
                    shutil.copyfileobj(src, sys.stdout)
        finally:
            staged.unlink(missing_ok=True)
        print(f"[+] {inp} -> {args.output or 'stdout'}  ({cp.stats_rows} rows)", file=sys.stderr)
        print(f"    {'vendor':<10} {family or 'generic'}", file=sys.stderr)
        unknown = [c for c in columns if policy.get("columns", {}).get(c, {}).get("action") == "redact"]
        if unknown:
            print(f"    {'unknown':<10} {len(unknown):>6} fields: {', '.join(unknown[:8])}", file=sys.stderr)

    elif fmt in STRUCTURED_FORMATS:
        text = text_cache if text_cache is not None else inp.read_text(errors="replace")
        try:
            result = anonymize_structured(
                fmt, text, anon, vault, safe=args.safe,
                source=args.source or inp.stem, family=canonical_kit_id(args.catalog) or args.catalog,
            )
        except ValueError as exc:
            vault.db.rollback()
            print(f"[!] {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        findings: list[dict] = []
        if result.failed or result.exposed:
            vault.db.rollback()
            print(f"[!] output blocked: {result.failed} failed transformations, "
                  f"{result.exposed} clear ambiguous values", file=sys.stderr)
            samples = result.failed_samples
            if samples:
                print("    samples: " + ", ".join(samples[:5]), file=sys.stderr)
            raise SystemExit(2)
        vault.commit()
        if args.output:
            Path(args.output).write_text(result.output, encoding="utf-8")
            print(f"[+] {inp} -> {args.output} ({fmt}, {result.records} record)", file=sys.stderr)
        else:
            sys.stdout.write(result.output)
        print(f"    {'vendor':<10} {result.catalog or 'generic'}", file=sys.stderr)
        unknown = [path for path, stat in result.fields.items() if stat.action == "redact"]
        if unknown:
            print(f"    {'unknown':<10} {len(unknown):>6} fields: {', '.join(unknown[:8])}", file=sys.stderr)

    else:
        text = text_cache if text_cache is not None else inp.read_text(errors="replace")
        out = anon.process(text)
        if args.safe:
            out, n_swept = sweep_known(vault, out, anon.opt)
            if n_swept:
                print(f"    {'swept':<10} {n_swept:>6} vault-known (safe mode)", file=sys.stderr)
            out, n_elided, _ = redact_residuals(out, anon.opt.dlp_policy)
            if n_elided:
                print(f"    {'elided':<10} {n_elided:>6} redacted (safe mode)", file=sys.stderr)
        findings = scan_sensitive_residuals(out, anon.opt.dlp_policy)
        dlp_blocked = len(anon.dlp_blocked)
        if findings or dlp_blocked:
            vault.db.rollback()
            print(f"[!] output blocked: {len(findings)} sensitive residuals, {dlp_blocked} DLP blocks", file=sys.stderr)
            samples = [str(f["value"]) for f in findings[:5]]
            samples.extend(f"DLP:block:{item.get('kind', 'unknown')}" for item in anon.dlp_blocked[:5])
            if samples:
                print("    samples: " + ", ".join(samples[:5]), file=sys.stderr)
            raise SystemExit(2)
        vault.commit()
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"[+] {inp} -> {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(out)

    if anon.dlp_counts:
        summary = ", ".join(f"{key}={value}" for key, value in sorted(anon.dlp_counts.items()))
        print(f"    {'DLP':<10} {summary}", file=sys.stderr)
    for k, v in anon.counts.most_common():
        print(f"    {k:<10} {v:>6} replaced", file=sys.stderr)
    for k, v in anon.skipped.items():
        print(f"    {k:<10} {v:>6} skipped (invalid/reserved)", file=sys.stderr)


def cmd_test_kit(args):
    import json as _json, csv as _csv
    cols = [c.strip() for c in (args.columns or "").split(",") if c.strip()]
    if args.header_file:
        delim = "\t" if args.header_file.endswith((".tsv", ".tab")) else ","
        with open(args.header_file, newline="", encoding="utf-8", errors="replace") as fh:
            cols = next(_csv.reader(fh, delimiter=delim), [])
    if not cols:
        raise SystemExit("[!] provide columns (comma-separated) or --header-file")
    print(_json.dumps(kit_dry_run(cols, family=args.catalog), indent=2, ensure_ascii=False))


def cmd_anonymize_pst(args):
    import pst_anon
    if not pst_anon.readpst_available():
        raise SystemExit("[!] readpst not found: install pst-utils "
                         "(Debian/Ubuntu: apt-get install -y pst-utils)")
    tenant, _vault_path, vault = cli_vault(args)
    opt = Options(
        ip_mode=args.ip_mode,
        client_terms=tuple(
            t.strip() for t in os.environ.get("LOGMASK_CLIENT_TERMS", "").split(",") if t.strip()),
        client_term_mode=os.environ.get("LOGMASK_CLIENT_TERM_MODE", "pseudonymize"),
        client_term_label=os.environ.get("LOGMASK_CLIENT_TERM_LABEL", "[CLIENTE]"),
        tenant_networks=tuple(
            n.strip() for n in os.environ.get("LOGMASK_TENANT_NETWORKS", "").split(",") if n.strip()),
        host_terms=tuple(
            t.strip() for t in os.environ.get("LOGMASK_HOST_TERMS", "").split(",") if t.strip()),
    )
    anon = Anonymizer(vault, set(ORDER), opt)
    body, count = pst_anon.anonymize_pst(args.input, anon, fmt=args.format)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    vault.commit()
    print(f"[+] {count} messages anonymized -> {args.output or 'stdout'} ({args.format})",
          file=sys.stderr)


def cmd_deanonymize(args):
    from structured import STRUCTURED_FORMATS, deanonymize_structured, detect_structured_format

    tenant, vault_path, vault = cli_vault(args)
    deanon = Deanonymizer(vault, Options())
    inp = Path(args.input)
    text_cache: str | None = None
    fmt = args.format
    if args.csv:
        fmt = "csv"
    if fmt == "auto":
        suffix_map = {
            ".csv": "csv", ".tsv": "csv", ".json": "json",
            ".jsonl": "ndjson", ".ndjson": "ndjson",
            ".cef": "cef", ".leef": "leef",
        }
        fmt = suffix_map.get(inp.suffix.lower(), "")
        if not fmt:
            text_cache = inp.read_text(errors="replace")
            fmt = detect_structured_format(text_cache) or "text"

    if fmt == "csv":
        fh = open(args.output, "w", newline="") if args.output else sys.stdout
        try:
            csv_deanonymize(inp, fh, deanon)
        finally:
            if args.output:
                fh.close()
    elif fmt in STRUCTURED_FORMATS:
        text = text_cache if text_cache is not None else inp.read_text(errors="replace")
        try:
            out = deanonymize_structured(fmt, text, deanon)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
        else:
            sys.stdout.write(out)
    else:
        out = deanon.process(text_cache if text_cache is not None else inp.read_text(errors="replace"))
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
        else:
            sys.stdout.write(out)

    if args.output:
        print(f"[+] {inp} -> {args.output}", file=sys.stderr)
    print(f"    resolved   {deanon.hits['resolved']:>6}", file=sys.stderr)
    if deanon.misses:
        print(f"    unresolved {sum(deanon.misses.values()):>6} "
              f"({', '.join(list(deanon.misses)[:5])})", file=sys.stderr)


def cmd_lookup(args):
    tenant, vault_path, vault = cli_vault(args)
    orig = vault.reverse(args.value)
    if orig:
        print(f"pseudonym -> original : {args.value} = {orig}")
        return
    if re.fullmatch(r"(?:10|100)\.\d{1,3}\.\d{1,3}\.\d{1,3}", args.value):
        net, _, host = args.value.rpartition(".")
        onet, ohost = vault.reverse(net), vault.reverse(host)
        if onet and ohost:
            print(f"pseudonym -> original : {args.value} = {onet}.{ohost}")
            return
    m2 = re.fullmatch(r"(S-1-5-21-\d+-\d+-\d+)-(\d+)", args.value)
    if m2:
        op = vault.reverse(m2.group(1))
        if op:
            print(f"pseudonym -> original : {args.value} = {op}-{m2.group(2)}")
            return
    for kind in BUILDERS:
        p = vault.lookup_original(kind, args.value.lower())
        if p:
            print(f"original -> pseudonym : {args.value} [{kind}] = {p}")
            return
    print("[-] not found in vault")


def cmd_stats(args):
    tenant, vault_path, vault = cli_vault(args)
    print(f"tenant: {tenant}")
    print(f"vault: {vault_path}")
    total = 0
    for kind, uniq, hits in vault.stats():
        print(f"  {kind:<10} {uniq:>6} unique  {hits or 0:>7} occurrences")
        total += uniq
    print(f"  {'TOTAL':<10} {total:>6} unique values")


def main():
    p = argparse.ArgumentParser(prog="logmask", description=__doc__.split("\n")[1])
    p.add_argument("--key", default=str(DEFAULT_KEY))
    p.add_argument("--vault", default=str(DEFAULT_VAULT))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="generate master key")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("scan", help="register CSV columns and generate a policy")
    add_tenant_arg(s)
    s.add_argument("input")
    s.add_argument("--policy", help="output policy file (default: <source>.policy.json)")
    s.add_argument("--source", help="logical source label, e.g. elastic / xsiam")
    s.add_argument("--catalog", choices=sorted(CATALOGS),
                   help="force a source family instead of auto-detecting")
    s.add_argument("--sample-rows", type=int, default=200)
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("anonymize", help="pseudonymize a log file (txt or csv)")
    add_tenant_arg(s)
    s.add_argument("input")
    s.add_argument("-o", "--output")
    s.add_argument("--csv", action="store_true", help="deprecated alias for --format csv")
    s.add_argument("--format", choices=["auto", "text", "csv", "json", "ndjson", "syslog", "cef", "leef"], default="auto", help="input format; auto detects structured logs")
    s.add_argument("--policy", help="policy file from 'scan'")
    s.add_argument("--source", help="logical source label for the field registry")
    s.add_argument("--catalog", choices=sorted(CATALOGS))
    s.add_argument("--types", help=f"txt mode only, comma list: {','.join(ORDER)}")
    s.add_argument("--preserve-subnet", action="store_true",
                   help="same /24 maps to same pseudo /24 for anonymized IPv4")
    s.add_argument("--ip-mode", choices=sorted(IP_MODES), default="all",
                   help="IP policy: none=keep all IPs, internal=mask only internal/private IPs, all=mask all IPs")
    s.add_argument("--dlp-policy", help="JSON file with DLP category actions")
    s.add_argument("--dlp", action="append", default=[], metavar="CATEGORY=ACTION",
                   help="override one DLP category; repeatable (pseudonymize|redact|block|keep)")
    s.add_argument("--keep-domain", action="store_true",
                   help="keep real email/host domain, mask only the local part")
    s.add_argument("--no-scope", action="store_true",
                   help="do not preserve private/public IP distinction")
    s.add_argument("--safe", action="store_true",
                   help="elide unclassified columns and residual identifiers")
    s.set_defaults(func=cmd_anonymize)

    s = sub.add_parser("test-kit",
                       help="dry-run: classify a column list against the kits (no masking)")
    s.add_argument("columns", nargs="?", help="comma-separated column names")
    s.add_argument("--header-file", help="read the header row from a CSV/TSV file")
    s.add_argument("--catalog", help="force a specific kit id")
    s.set_defaults(func=cmd_test_kit)

    s = sub.add_parser("anonymize-pst",
                       help="extract + anonymize an Outlook .pst to NDJSON/CSV (needs pst-utils)")
    add_tenant_arg(s)
    s.add_argument("input", help="path to the .pst file")
    s.add_argument("-o", "--output", help="output file (default: stdout)")
    s.add_argument("--format", choices=["ndjson", "csv"], default="ndjson")
    s.add_argument("--ip-mode", choices=sorted(IP_MODES), default="all")
    s.set_defaults(func=cmd_anonymize_pst)

    s = sub.add_parser("deanonymize", help="restore original values (txt or csv)")
    add_tenant_arg(s)
    s.add_argument("input")
    s.add_argument("-o", "--output")
    s.add_argument("--csv", action="store_true", help="deprecated alias for --format csv")
    s.add_argument("--format", choices=["auto", "text", "csv", "json", "ndjson", "syslog", "cef", "leef"], default="auto")
    s.set_defaults(func=cmd_deanonymize)

    s = sub.add_parser("fields", help="show the registry of all columns ever seen")
    add_tenant_arg(s)
    s.add_argument("--source")
    s.set_defaults(func=cmd_fields)

    s = sub.add_parser("lookup", help="resolve a single value in either direction")
    add_tenant_arg(s)
    s.add_argument("value")
    s.set_defaults(func=cmd_lookup)

    s = sub.add_parser("stats", help="vault statistics")
    add_tenant_arg(s)
    s.set_defaults(func=cmd_stats)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
