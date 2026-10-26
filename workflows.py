"""SOC workflow profiles for LogMask."""
from __future__ import annotations

from copy import deepcopy

COMMON_SECRET_REDACT = {
    "credentials": "redact",
    "private_key": "redact",
    "sensitive_url": "redact",
}
COMMON_REVERSIBLE = {
    "tax_id": "pseudonymize",
    "iban": "pseudonymize",
    "phone": "pseudonymize",
    "person_name": "pseudonymize",
    "address": "pseudonymize",
    "cloud_id": "pseudonymize",
}

_PROFILES = [
    {
        "id": "customer-ticket",
        "label": "Ticket cliente",
        "description": "Segnalazione cliente: contesto tecnico utile, dati interni e PII protetti. IP e URL mascherati per intero.",
        "settings": {
            "format": "auto", "catalog": "", "safe_mode": True,
            "ip_mode": "all", "url_mode": "all", "preserve_subnet": False,
            "dlp_policy": {**COMMON_SECRET_REDACT, **COMMON_REVERSIBLE},
        },
        "template": "ticket",
    },
    {
        "id": "ai-analysis",
        "label": "Analisi AI esterna",
        "description": "Preset prudente per LLM esterni: IP e URL mascherati per intero, segreti e dati minimizzati.",
        "settings": {
            "format": "auto", "catalog": "", "safe_mode": True,
            "ip_mode": "all", "url_mode": "all", "preserve_subnet": False,
            "dlp_policy": {**COMMON_SECRET_REDACT, **COMMON_REVERSIBLE, "iban": "redact", "address": "redact"},
        },
        "template": "ai",
    },

    {
        "id": "field-quality",
        "label": "Valutazione campi",
        "description": "Audit della qualità di anonimizzazione: non analizza FP/TP, valuta copertura, elisioni e tuning campi.",
        "settings": {
            "format": "auto", "catalog": "", "safe_mode": True,
            "ip_mode": "all", "url_mode": "all", "preserve_subnet": False,
            "dlp_policy": {**COMMON_SECRET_REDACT, **COMMON_REVERSIBLE, "iban": "redact", "address": "redact"},
        },
        "template": "field_quality",
    },
    {
        "id": "threat-hunting",
        "label": "Threat hunting interno",
        "description": "Mantiene gli indicatori tecnici leggibili per correlazione interna; blocca comunque segreti e PII.",
        "settings": {
            "format": "auto", "catalog": "", "safe_mode": True,
            # Unico profilo che NON maschera tutto: il suo scopo dichiarato e'
            # tenere leggibili gli indicatori tecnici per la correlazione
            # interna. Mascherarli lo renderebbe inutile.
            "ip_mode": "none", "url_mode": "internal", "preserve_subnet": True,
            "dlp_policy": {**COMMON_SECRET_REDACT, **COMMON_REVERSIBLE},
        },
        "template": "hunting",
    },
    {
        "id": "report",
        "label": "Report / allegato",
        "description": "Output ad alta minimizzazione per allegati, evidenze e report non strettamente operativi.",
        "settings": {
            "format": "auto", "catalog": "", "safe_mode": True,
            "ip_mode": "all", "url_mode": "all", "preserve_subnet": False,
            "dlp_policy": {**COMMON_SECRET_REDACT, **COMMON_REVERSIBLE, "iban": "redact", "address": "redact"},
        },
        "template": "report",
    },
]


def workflow_profiles() -> list[dict]:
    return deepcopy(_PROFILES)


def workflow_profile(profile_id: str) -> dict | None:
    for profile in _PROFILES:
        if profile["id"] == profile_id:
            return deepcopy(profile)
    return None
