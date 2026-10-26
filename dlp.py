"""High-confidence DLP/PII detection and policy execution for LogMask.

The detector intentionally favors precision over recall.  Broad entities such as
person names, telephone numbers and street addresses are detected only when a
field/label provides context.  Secrets and structured identifiers use stricter
syntax and validation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Mapping

DLP_ACTIONS = {"pseudonymize", "redact", "block", "keep"}

# Publicly documented Active Directory schema/control-access GUIDs: they are
# detection content (extended rights, object classes), not tenant identifiers.
# Masking them destroys the analytical value of KQL/detection rules (v0.10.9).
WELL_KNOWN_GUIDS = frozenset({
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Synchronize
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Manage-Topology
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Monitor-Topology
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Repl-Get-Changes-In-Filtered-Set
    "00299570-246d-11d0-a768-00aa006e0529",  # User-Force-Change-Password
    "ab721a53-1e2f-11d0-9819-00aa0040529b",  # User-Change-Password
    "bf967aba-0de6-11d0-a285-00aa003049e2",  # user object class
    "bf967a86-0de6-11d0-a285-00aa003049e2",  # computer object class
    "bf967a9c-0de6-11d0-a285-00aa003049e2",  # group object class
    "19195a5b-6da0-11d0-afd3-00c04fd930c9",  # domainDNS object class
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1",  # GP-Link
    "f30e3bbf-9ff0-11d1-b603-0000f80367c1",  # GP-Options
})

DLP_CATEGORIES: dict[str, dict[str, str]] = {
    "credentials": {
        "label": "Password, token, API key e cookie",
        "description": "Credenziali, bearer/basic auth, JWT, API key, cookie e session token.",
        "default": "redact",
        "kind": "secret",
    },
    "private_key": {
        "label": "Chiavi private e materiale PEM",
        "description": "Blocchi PEM di chiavi private e certificati incorporati.",
        "default": "redact",
        "kind": "secret",
    },
    "tax_id": {
        "label": "Codice fiscale italiano",
        "description": "Codici fiscali formalmente validi, incluso controllo del carattere finale.",
        "default": "pseudonymize",
        "kind": "taxid",
    },
    "iban": {
        "label": "IBAN",
        "description": "IBAN formalmente validi tramite controllo MOD-97.",
        "default": "pseudonymize",
        "kind": "iban",
    },
    "phone": {
        "label": "Numeri telefonici",
        "description": "Numeri con etichetta telefono/mobile/cellulare.",
        "default": "pseudonymize",
        "kind": "phone",
    },
    "person_name": {
        "label": "Nomi e cognomi",
        "description": "Nominativi in campi o testo esplicitamente etichettati.",
        "default": "pseudonymize",
        "kind": "person",
    },
    "address": {
        "label": "Indirizzi fisici",
        "description": "Indirizzi italiani e inglesi, etichettati o riconosciuti nel testo.",
        "default": "pseudonymize",
        "kind": "address",
    },
    "vat_id": {
        "label": "Partita IVA / VAT",
        "description": "Partite IVA italiane (controllo di Luhn) e numeri VAT europei.",
        "default": "pseudonymize",
        "kind": "vat",
    },
    "cloud_id": {
        "label": "Identificativi cloud e UUID",
        "description": "UUID/GUID, Azure resource ID, AWS ARN/account ID e identificativi cloud etichettati.",
        "default": "pseudonymize",
        "kind": "cloud",
    },
    "sensitive_url": {
        "label": "Parametri URL sensibili",
        "description": "Valori di token, key, password, code e sessione nelle query string.",
        "default": "redact",
        "kind": "secret",
    },
}


def default_dlp_policy() -> dict[str, str]:
    return {key: value["default"] for key, value in DLP_CATEGORIES.items()}


class _NormalizedPolicy(dict):
    """Marcatore: policy gia' validata da normalize_dlp_policy.

    v0.17.0: la normalizzazione veniva rifatta per OGNI valore e per ogni testo
    scrubbato (4 volte per record), pur dipendendo solo dalla policy del job.
    Il marcatore consente un fast-path O(1) senza toccare la validazione degli
    input esterni (API/CLI), che restano validati come prima.
    """
    __slots__ = ()


def normalize_dlp_policy(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    if type(overrides) is _NormalizedPolicy:      # gia' validata: nessuno la muta
        return overrides
    result = default_dlp_policy()
    for category, action in (overrides or {}).items():
        if category not in DLP_CATEGORIES:
            raise ValueError(f"unknown DLP category: {category}")
        normalized = str(action).strip().lower()
        if normalized not in DLP_ACTIONS:
            raise ValueError(f"invalid DLP action for {category}: {action}")
        result[category] = normalized
    return _NormalizedPolicy(result)


def dlp_metadata() -> list[dict[str, str]]:
    return [
        {
            "id": category,
            "label": meta["label"],
            "description": meta["description"],
            "default": meta["default"],
        }
        for category, meta in DLP_CATEGORIES.items()
    ]


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int
    value: str
    confidence: str = "high"
    detector: str = "pattern"
    priority: int = 50


@dataclass
class DlpResult:
    output: str
    counts: dict[str, int] = field(default_factory=dict)
    actions: dict[str, int] = field(default_factory=dict)
    blocked: list[Finding] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)

    @property
    def redacted(self) -> int:
        return self.actions.get("redact", 0)

    @property
    def pseudonymized(self) -> int:
        return self.actions.get("pseudonymize", 0)


UUID_RX = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
IBAN_RX = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.IGNORECASE)
# v0.21.2: vedi logmask.CF_RX - riconosce il CF anche dentro un token (path,
# nome file), non solo isolato. Confini "non lettera-non cifra" (abbracciano
# _ . - ~ / \\). Il carattere di controllo del CF esclude i falsi positivi.
CF_RX = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z](?![A-Za-z0-9])",
    re.IGNORECASE)
JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY_RX = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
GITHUB_TOKEN_RX = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b")
AWS_ARN_RX = re.compile(r"\barn:(?:aws|aws-us-gov|aws-cn):[A-Za-z0-9_-]+:[A-Za-z0-9_-]*:\d{12}:[^\s,;]+")
AWS_ACCOUNT_RX = re.compile(
    r"(?i)\b(?:aws[_ .-]?account(?:[_ .-]?id)?|account[_ .-]?id)\b\s*[:=]\s*(?P<value>\d{12})\b"
)
AZURE_RESOURCE_RX = re.compile(
    r"(?i)(?P<value>/subscriptions/[0-9a-f-]{36}(?:/resourceGroups/[^\s/?#]+)?(?:/providers/[^\s?#]+)?)"
)
CREDENTIAL_KV_RX = re.compile(
    r"(?i)\b(?P<key>password|passwd|pwd|client[_-]?secret|secret|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|proxy[_-]?authorization|"
    r"cookie|set-cookie|session(?:id|_id)?|private[_-]?token)\b"
    r"\s*(?:[:=]\s*|\s+)(?P<value>Bearer\s+[^\s,;]+|Basic\s+[^\s,;]+|"
    r"\"[^\"\r\n]{4,}\"|'[^'\r\n]{4,}'|[^\s,;]{6,})"
)

# v0.15.0: stesso guard-prosa di logmask.SECRET_KV_RX — "Login session opened."
# non e' un session token. Solo chiave nuda "session", separatore a spazio,
# valore parola minuscola; tutto il resto resta aggressivo.
SESSION_PROSE_RX = re.compile(r"[a-z]{3,12}\.?")
BEARER_RX = re.compile(r"(?i)(?<=\bBearer\s)[A-Za-z0-9._~+\-/=]{8,}")
PRIVATE_KEY_RX = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)
CERTIFICATE_RX = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
# v0.23.5: vedi logmask.PHONE_LABELED_RX - "tel." e "Telefono " senza i due
# punti non venivano mai rilevati.
PHONE_INTL_RX = re.compile(
    r"(?<![\w+])\+\d{1,3}(?:[ ]\d{1,7}){1,5}(?!\d)"
    r"|(?<![\w+])\+\d{9,15}(?!\d)"
)
PHONE_LABELED_RX = re.compile(
    r"(?i)\b(?:tel(?:efono)?|phone|mobile|cell(?:ulare)?|recapito)\b\.?\s*[:=]?\s*"
    r"(?P<value>\+?\d[\d .()/-]{6,}\d)"
)
PERSON_LABELED_RX = re.compile(
    r"(?i)\b(?:nome(?:[ _-]?completo)?|full[_ -]?name|display[_ -]?name|"
    r"nome[_ -]?cognome|cognome|persona|contatto|contact[_ -]?name)\b\s*[:=]\s*"
    r"(?P<value>[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]{1,40}(?:[ \t]+[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]{1,40}){0,4})"
)
# v0.25.0: vedi logmask per il ragionamento completo. In sintesi: l'etichetta
# accetta anche punto o spazio come separatore, i tipi di strada coprono
# italiano e inglese, e le forme non etichettate esigono un nome proprio piu'
# un numero civico - altrimenti "via proxy 8080" e "installazione via processo
# anomalo" verrebbero scambiati per indirizzi in ogni log SOC.
IT_STREET = (r"(?i:via|viale|v\.le|vicolo|piazz(?:a|ale)|p\.zza|corso|c\.so|largo|strada|"
             r"contrada|borgo|lungomare|salita|calle|fondamenta|traversa|circonvallazione|"
             r"localit[aà]|loc\.|frazione|fraz\.)")
EN_SUFFIX_STRONG = (r"(?i:street|st\.|road|rd\.|avenue|ave\.?|boulevard|blvd\.?|lane|ln\.|"
                    r"highway|hwy\.?|parkway|pkwy\.?)")
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

VAT_LABEL = (r"(?:p(?:artita)?\.?\s?iva|piva|vat(?:[ _-]?(?:id|no|number|reg(?:istration)?"
             r"(?:[ _-]?(?:no|number))?))?|tva|ust[ _-]?id|btw|nif|cif|abn|gst)")
VAT_LABELED_RX = re.compile(
    r"(?i)\b" + VAT_LABEL + r"\b\.?\s*[:=]?\s*"
    r"(?P<value>(?:[A-Z]{2}[ ]?)?[A-Z0-9][A-Z0-9.\-]{5,14})")
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


def valid_vat(value: str) -> bool:
    """Le 11 cifre nude sono una forma comunissima anche fuori dalla fiscalita'
    (identificativi, numeri di record, epoch): senza Luhn una P.IVA nuda
    produrrebbe una valanga di falsi positivi nei log."""
    compact = re.sub(r"[ .\-]", "", value or "").upper()
    if not 8 <= len(compact) <= 14:
        return False
    if compact.startswith("IT") and len(compact) == 13 and compact[2:].isdigit():
        return _luhn_ok(compact[2:])
    if compact.isdigit():
        return len(compact) == 11 and _luhn_ok(compact)
    return bool(re.fullmatch(r"[A-Z]{2}[A-Z0-9]{6,12}", compact))
SENSITIVE_URL_PARAM_RX = re.compile(
    r"(?i)(?<=[?&])(?:access_token|token|api[_-]?key|key|password|passwd|pwd|"
    r"client_secret|code|ref|session(?:id|_id)?)=(?P<value>[^&#\s]{4,})"
)


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


def valid_iban(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not (15 <= len(compact) <= 34) or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


def valid_codice_fiscale(value: str) -> bool:
    cf = re.sub(r"\s+", "", value).upper()
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


def _clean_credential(value: str) -> tuple[int, int, str]:
    leading = 1 if value[:1] in {'"', "'"} else 0
    trailing = 1 if value[-1:] in {'"', "'"} and value[-1:] == value[:1] else 0
    return leading, len(value) - trailing, value[leading:len(value)-trailing if trailing else None]


def detect(text: str, *, is_pseudonym: Callable[[str], bool] | None = None) -> list[Finding]:
    candidates: list[Finding] = []

    def add(category: str, start: int, end: int, value: str, priority: int, detector: str):
        token = value.strip()
        if not token or token == "[ELIDED]" or (is_pseudonym and is_pseudonym(token)):
            return
        candidates.append(Finding(category, start, end, value, "high", detector, priority))

    for rx, detector in ((PRIVATE_KEY_RX, "private-key"), (CERTIFICATE_RX, "certificate")):
        for match in rx.finditer(text):
            add("private_key", match.start(), match.end(), match.group(0), 130, detector)

    for match in CREDENTIAL_KV_RX.finditer(text):
        raw = match.group("value")
        key = (match.group("key") or "").lower()
        sep = text[match.end("key"):match.start("value")]
        if key == "session" and ":" not in sep and "=" not in sep \
                and SESSION_PROSE_RX.fullmatch(raw):
            continue          # prosa ("session opened."), non credenziale
        left, right, clean = _clean_credential(raw)
        add("credentials", match.start("value") + left, match.start("value") + right, clean, 120, "credential-label")
    for match in JWT_RX.finditer(text):
        add("credentials", match.start(), match.end(), match.group(0), 118, "jwt")
    for match in AWS_ACCESS_KEY_RX.finditer(text):
        add("credentials", match.start(), match.end(), match.group(0), 117, "aws-access-key")
    for match in GITHUB_TOKEN_RX.finditer(text):
        add("credentials", match.start(), match.end(), match.group(0), 117, "github-token")
    for match in BEARER_RX.finditer(text):
        add("credentials", match.start(), match.end(), match.group(0), 116, "bearer")
    for match in SENSITIVE_URL_PARAM_RX.finditer(text):
        add("sensitive_url", match.start("value"), match.end("value"), match.group("value"), 125, "url-query")

    for match in IBAN_RX.finditer(text):
        for cand in _iban_candidates(match.group(0)):
            if valid_iban(cand):
                add("iban", match.start(), match.start() + len(cand), cand, 100,
                    "iban-mod97")
                break
    for match in CF_RX.finditer(text):
        if valid_codice_fiscale(match.group(0)):
            add("tax_id", match.start(), match.end(), match.group(0), 100, "italian-tax-id")
    for match in PHONE_LABELED_RX.finditer(text):
        add("phone", match.start("value"), match.end("value"), match.group("value"), 90, "phone-label")
    for match in PHONE_INTL_RX.finditer(text):
        if sum(ch.isdigit() for ch in match.group(0)) >= 9:
            add("phone", match.start(), match.end(), match.group(0), 85, "phone-intl")
    for match in PERSON_LABELED_RX.finditer(text):
        add("person_name", match.start("value"), match.end("value"), match.group("value"), 82, "person-label")
    for match in ADDRESS_LABELED_RX.finditer(text):
        add("address", match.start("value"), match.end("value"), match.group("value"), 84, "address-label")
    for match in ADDRESS_IT_RX.finditer(text):
        add("address", match.start(), match.end(), match.group(0), 80, "address-it")
    for match in ADDRESS_EN_RX.finditer(text):
        add("address", match.start(), match.end(), match.group(0), 80, "address-en")
    for match in ADDRESS_POBOX_RX.finditer(text):
        add("address", match.start(), match.end(), match.group(0), 80, "address-pobox")
    for match in VAT_LABELED_RX.finditer(text):
        value = match.group("value").rstrip(".-")
        if valid_vat(value):
            add("vat_id", match.start("value"), match.start("value") + len(value),
                value, 92, "vat-label")
    for match in VAT_EU_RX.finditer(text):
        if valid_vat(match.group(0)):
            add("vat_id", match.start(), match.end(), match.group(0), 90, "vat-eu")

    for match in AZURE_RESOURCE_RX.finditer(text):
        add("cloud_id", match.start("value"), match.end("value"), match.group("value"), 96, "azure-resource-id")
    for match in AWS_ARN_RX.finditer(text):
        add("cloud_id", match.start(), match.end(), match.group(0), 95, "aws-arn")
    for match in AWS_ACCOUNT_RX.finditer(text):
        add("cloud_id", match.start("value"), match.end("value"), match.group("value"), 94, "aws-account")
    for match in UUID_RX.finditer(text):
        if match.group(0).lower() in WELL_KNOWN_GUIDS:
            continue
        add("cloud_id", match.start(), match.end(), match.group(0), 75, "uuid")

    # Resolve overlaps by priority, then by longest span.  PEM/credentials win
    # over identifiers embedded inside them.
    candidates.sort(key=lambda item: (-item.priority, -(item.end - item.start), item.start))
    selected: list[Finding] = []
    for candidate in candidates:
        if any(candidate.start < other.end and candidate.end > other.start for other in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: item.start)


FIELD_CATEGORY_RX: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(?:^|[._-])(?:password|passwd|pwd|client_secret|secret|api_key|apikey|access_token|refresh_token|id_token|authorization|cookie|set_cookie|session_id|sessionid|private_token)$"), "credentials"),
    (re.compile(r"(?i)(?:^|[._-])(?:phone|mobile|cellulare|telefono|telephone|recapito)$"), "phone"),
    (re.compile(r"(?i)(?:^|[._-])(?:full_name|display_name|first_name|last_name|nome|cognome|nome_cognome|contact_name|persona)$"), "person_name"),
    (re.compile(r"(?i)(?:^|[._-])(?:address|indirizzo|residenza|domicilio|sede_legale|street_address|mailing_address|billing_address|shipping_address|home_address|address_line1|address_line2)$"), "address"),
    (re.compile(r"(?i)(?:^|[._-])(?:vat|vat_id|vat_number|vatnumber|piva|p_iva|partita_iva|vat_reg_no|tva|ust_id)$"), "vat_id"),
    (re.compile(r"(?i)(?:^|[._-])(?:codice_fiscale|tax_id|fiscal_code|cf)$"), "tax_id"),
    (re.compile(r"(?i)(?:^|[._-])iban$"), "iban"),
    (re.compile(r"(?i)(?:^|[._-])(?:tenant_id|tenant_uuid|subscription_id|object_id|resource_id|account_id|aws_account_id|guid|uuid|cloud_id)$"), "cloud_id"),
]


def category_for_field(field_name: str, value: str) -> str | None:
    normalized = re.sub(r"\[\d+\]", "[]", field_name.strip()).replace("-", "_")
    for pattern, category in FIELD_CATEGORY_RX:
        if not pattern.search(normalized):
            continue
        compact = value.strip().strip('"\'')
        if not compact:
            return None
        if category == "tax_id" and not valid_codice_fiscale(compact):
            return None
        if category == "iban" and not valid_iban(compact):
            return None
        if category == "phone" and not re.fullmatch(r"\+?\d[\d .()/-]{6,}\d", compact):
            return None
        if category == "person_name" and not re.fullmatch(r"[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]{1,40}(?:[ \t]+[A-ZÀ-ÖØ-Ý][A-Za-zÀ-ÖØ-öø-ÿ'’-]{1,40}){0,4}", compact):
            return None
        return category
    return None


def apply_field(
    field_name: str,
    value: str,
    policy: Mapping[str, str] | None,
    mapper: Callable[[str, str], str],
    *,
    is_pseudonym: Callable[[str], bool] | None = None,
    elided_token: str = "[ELIDED]",
) -> DlpResult:
    normalized = normalize_dlp_policy(policy)
    category = category_for_field(field_name, value)
    output = value
    counts: dict[str, int] = {}
    actions: dict[str, int] = {}
    blocked: list[Finding] = []
    samples: list[str] = []
    if category and not (is_pseudonym and is_pseudonym(value.strip())):
        action = normalized[category]
        counts[category] = 1
        actions[action] = 1
        samples.append(value)
        finding = Finding(category, 0, len(value), value, "high", "field-name", 140)
        if action == "redact":
            output = elided_token
        elif action == "pseudonymize":
            output = mapper(DLP_CATEGORIES[category]["kind"], value)
        elif action == "block":
            blocked.append(finding)
    # Inspect embedded values too (for example URL query parameters in a url field).
    embedded = apply(output, normalized, mapper, is_pseudonym=is_pseudonym, elided_token=elided_token)
    for key, count in embedded.counts.items():
        counts[key] = counts.get(key, 0) + count
    for key, count in embedded.actions.items():
        actions[key] = actions.get(key, 0) + count
    blocked.extend(embedded.blocked)
    for sample in embedded.samples:
        if len(samples) < 10 and sample not in samples:
            samples.append(sample)
    return DlpResult(embedded.output, counts, actions, blocked, samples)


def apply(
    text: str,
    policy: Mapping[str, str] | None,
    mapper: Callable[[str, str], str],
    *,
    is_pseudonym: Callable[[str], bool] | None = None,
    elided_token: str = "[ELIDED]",
) -> DlpResult:
    normalized = normalize_dlp_policy(policy)
    findings = detect(text, is_pseudonym=is_pseudonym)
    if not findings:
        return DlpResult(output=text)

    output = text
    counts: dict[str, int] = {}
    actions: dict[str, int] = {}
    blocked: list[Finding] = []
    samples: list[str] = []
    replacements: list[tuple[int, int, str]] = []

    for finding in findings:
        action = normalized[finding.category]
        counts[finding.category] = counts.get(finding.category, 0) + 1
        actions[action] = actions.get(action, 0) + 1
        if len(samples) < 10 and finding.value not in samples:
            samples.append(finding.value)
        if action == "keep":
            continue
        if action == "block":
            blocked.append(finding)
            continue
        replacement = elided_token if action == "redact" else mapper(DLP_CATEGORIES[finding.category]["kind"], finding.value)
        replacements.append((finding.start, finding.end, replacement))

    for start, end, replacement in reversed(replacements):
        output = output[:start] + replacement + output[end:]
    return DlpResult(output=output, counts=counts, actions=actions, blocked=blocked, samples=samples)
