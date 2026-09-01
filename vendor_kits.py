"""Versioned vendor field kits for LogMask.

A vendor kit is deliberately data-only: it describes field-name patterns,
positive fingerprints and safe operational fields. The masking engine remains
fail-closed; a kit can reduce ambiguity, but it can never force an unknown
populated field to pass in clear.
"""
from __future__ import annotations

import os
import re
import glob
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml


@dataclass(frozen=True)
class Rule:
    pattern: str
    action: str  # mask | text | keep
    kind: str | None = None


@dataclass(frozen=True)
class VendorKit:
    id: str
    label: str
    version: str
    aliases: tuple[str, ...]
    fingerprints: tuple[tuple[str, int], ...]
    rules: tuple[Rule, ...]
    header_hints: tuple[str, ...] = ()
    notes: str = ""


# Kinds accepted by logmask: ip, mac, email, user, fqdn, winuser,
# windomain, sid, endpoint, text. "keep" rules are limited to operational
# metadata that is useful for SOC analysis and not identifying by itself.
BUNDLED_KITS_DIR = Path(__file__).resolve().parent / "kits"
USER_KITS_DIR = Path(os.environ.get(
    "LOGMASK_KITS_DIR", os.path.join(os.environ.get("LOGMASK_DATA", "data"), "kits")))

_ACTIONS = {"mask", "text", "keep", "drop", "redact"}
_KINDS = {None, "ip", "ipv4", "ipv6", "ip_strict", "mac", "email", "user",
          "fqdn", "winuser", "windomain", "sid", "endpoint", "opaque", "ioc"}


def _pattern_ok(pat: object) -> bool:
    """A kit pattern must compile and not be an obvious ReDoS (best effort)."""
    if not isinstance(pat, str) or not pat or len(pat) > 4000:
        return False
    try:
        re.compile(pat)
    except re.error:
        return False
    # reject a group whose body has an unbounded quantifier and is itself
    # unbounded-quantified: (a+)+  (a*)*  (.+)*  -> classic catastrophic cases.
    if re.search(r"\([^)]*[+*][^)]*\)\s*[+*]", pat):
        return False
    return True


def _kit_from_dict(doc: dict) -> "VendorKit | None":
    try:
        kid = str(doc["id"]).strip().lower()
        if not kid:
            return None
        fps = tuple(
            (f["pattern"], int(f["weight"]))
            for f in (doc.get("fingerprints") or [])
            if isinstance(f, dict) and _pattern_ok(f.get("pattern")) and "weight" in f)
        rules = []
        for r in (doc.get("rules") or []):
            if not isinstance(r, dict):
                continue
            act, kind = r.get("action"), r.get("kind")
            if act in _ACTIONS and kind in _KINDS and _pattern_ok(r.get("pattern")):
                rules.append(Rule(r["pattern"], act, kind))
        return VendorKit(
            id=kid, label=str(doc.get("label", kid)), version=str(doc.get("version", "")),
            aliases=tuple(str(a).strip().lower() for a in (doc.get("aliases") or ())),
            fingerprints=fps, rules=tuple(rules),
            header_hints=tuple(str(h) for h in (doc.get("header_hints") or ())),
            notes=str(doc.get("notes", "")))
    except Exception:
        return None


def _read_dir(directory: Path) -> list[dict]:
    out: list[dict] = []
    if not Path(directory).is_dir():
        return out
    for path in sorted(list(Path(directory).glob("*.yaml")) + list(Path(directory).glob("*.yml"))):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("id"):
            out.append(doc)
    return out


def _extend(base: "VendorKit", extra: dict) -> "VendorKit":
    add = _kit_from_dict({**extra, "id": base.id})
    if add is None:
        return base
    return VendorKit(
        id=base.id, label=extra.get("label", base.label),
        version=extra.get("version", base.version),
        aliases=base.aliases + tuple(a for a in add.aliases if a not in base.aliases),
        fingerprints=base.fingerprints + add.fingerprints,
        rules=add.rules + base.rules,          # user rules take precedence
        header_hints=base.header_hints + tuple(h for h in add.header_hints if h not in base.header_hints),
        notes=extra.get("notes", base.notes))


def _build_registry() -> "tuple[dict, dict]":
    kits: dict[str, VendorKit] = {}
    for doc in _read_dir(BUNDLED_KITS_DIR):
        k = _kit_from_dict(doc)
        if k:
            kits[k.id] = k
    for doc in _read_dir(USER_KITS_DIR):        # user kits: add or extend/replace
        kid = str(doc.get("id", "")).strip().lower()
        if not kid:
            continue
        if kid in kits and str(doc.get("mode", "")).lower() != "replace":
            kits[kid] = _extend(kits[kid], doc)
        else:
            k = _kit_from_dict(doc)
            if k:
                kits[k.id] = k
    aliases: dict[str, str] = {}
    for kid, kit in kits.items():
        aliases[kid] = kid
        for a in kit.aliases:
            aliases.setdefault(a, kid)
    return kits, aliases


KITS, ALIASES = _build_registry()
_KITS_MTIME: float | None = None


def _user_kits_mtime() -> float:
    d = Path(USER_KITS_DIR)
    try:
        times = [d.stat().st_mtime] if d.is_dir() else []
        times += [p.stat().st_mtime for p in list(d.glob("*.yaml")) + list(d.glob("*.yml"))]
        return max(times) if times else 0.0
    except OSError:
        return 0.0


def reload_kits_if_changed() -> dict:
    """Rebuild the registry when user kits (data/kits) change on disk. Bundled
    kits are read once at import; call this before detection to pick up edits."""
    global KITS, ALIASES, _KITS_MTIME
    m = _user_kits_mtime()
    if m != _KITS_MTIME:
        _KITS_MTIME = m
        KITS, ALIASES = _build_registry()
    return KITS


def force_reload() -> None:
    """Rebuild the registry now (used by the kit studio after write/delete)."""
    global KITS, ALIASES, _KITS_MTIME
    _KITS_MTIME = _user_kits_mtime()
    KITS, ALIASES = _build_registry()


_KIT_ID_RX = re.compile(r"^[a-z0-9][a-z0-9_]{1,63}$")


def validate_kit_yaml(text: str) -> dict:
    """Parse and validate a user kit YAML without writing anything.

    Returns {ok, errors, warnings, kit}. `errors` block saving (fail-closed);
    `warnings` list rules/fingerprints that the loader would silently drop."""
    errors: list[str] = []
    warnings: list[str] = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {"ok": False, "errors": [f"YAML non valido: {exc}"], "warnings": [], "kit": None}
    if not isinstance(doc, dict):
        return {"ok": False, "errors": ["il documento deve essere una mappa YAML (id:, rules: ...)"],
                "warnings": [], "kit": None}
    kid = str(doc.get("id") or "").strip().lower()
    if not _KIT_ID_RX.fullmatch(kid):
        errors.append("campo 'id' mancante o non valido (2-64 caratteri: a-z 0-9 _)")
    mode = str(doc.get("mode") or "").strip().lower()
    if mode and mode not in {"extend", "replace"}:
        warnings.append(f"mode '{mode}' ignorato (ammessi: extend, replace)")
        mode = ""
    bundled_ids = {k.get("id") for k in _read_dir(BUNDLED_KITS_DIR) if isinstance(k, dict)}
    effective_mode = mode or ("extend" if kid in bundled_ids else "new")
    rules = doc.get("rules")
    if rules is not None and not isinstance(rules, list):
        errors.append("'rules' deve essere una lista")
        rules = []
    kept = 0
    kinds_ok = {str(k) for k in _KINDS if k is not None}
    for i, r in enumerate(rules or []):
        if not isinstance(r, dict):
            warnings.append(f"regola {i+1} scartata: non e' una mappa {{pattern, action, kind}}")
            continue
        problems = []
        pat = r.get("pattern")
        act = str(r.get("action") or "").strip().lower()
        kind = r.get("kind")
        if act not in _ACTIONS:
            problems.append(f"action '{act or '?'}' non valida (mask|text|keep|drop)")
        if kind is not None and str(kind) not in kinds_ok:
            problems.append(f"kind '{kind}' non valido")
        if not isinstance(pat, str) or not pat.strip():
            problems.append("pattern mancante")
        elif not _pattern_ok(pat):
            problems.append("pattern regex non valido, troppo lungo o non sicuro (ReDoS)")
        if problems:
            warnings.append(f"regola {i+1} scartata ({'; '.join(problems)}): {pat!r}")
        else:
            kept += 1
    fps = doc.get("fingerprints")
    fp_kept = 0
    if fps is not None and not isinstance(fps, list):
        errors.append("'fingerprints' deve essere una lista")
        fps = []
    for i, f in enumerate(fps or []):
        if not isinstance(f, dict) or not isinstance(f.get("pattern"), str)                 or not _pattern_ok(f["pattern"]) or not isinstance(f.get("weight"), int):
            warnings.append(f"fingerprint {i+1} scartata: serve {{pattern: regex, weight: intero}}")
        else:
            fp_kept += 1
    if kept == 0 and effective_mode != "replace":
        warnings.append("nessuna regola valida: il kit non avra' effetto sulle colonne")
    if effective_mode == "new" and fp_kept == 0:
        warnings.append("kit nuovo senza fingerprint valide: non verra' mai rilevato automaticamente")
    return {"ok": not errors, "errors": errors, "warnings": warnings,
            "kit": {"id": kid, "label": str(doc.get("label") or kid), "mode": effective_mode,
                    "rules_kept": kept, "fingerprints_kept": fp_kept}}


def canonical_kit_id(value: str | None) -> str | None:
    if value is None:
        return None
    return ALIASES.get(value.strip().lower())


def kit_choices() -> list[str]:
    return sorted(KITS)


def kit_catalogs() -> dict[str, list[tuple[str, str]]]:
    """Compatibility mapping consumed by the legacy kind-only resolver."""
    output: dict[str, list[tuple[str, str]]] = {}
    for kit_id, kit in KITS.items():
        output[kit_id] = [
            (rule.pattern, "text" if rule.action == "text" else rule.kind)
            for rule in kit.rules
            if rule.action in {"mask", "text"}
        ]
    for alias, canonical in ALIASES.items():
        output.setdefault(alias, output[canonical])
    return output


def match_rule(field: str, kit_id: str | None) -> tuple[Rule | None, str | None]:
    canonical = canonical_kit_id(kit_id)
    if not canonical:
        return None, None
    for rule in KITS[canonical].rules:
        if re.match(rule.pattern, field, re.IGNORECASE):
            return rule, canonical
    return None, canonical


def _field_variants_for_detection(field: str) -> set[str]:
    raw = str(field).strip().lower().replace("[]", "")
    out = {raw} if raw else set()
    # Display-name exports ("Issue Id", "Host FQDN"): expose the snake_case
    # variant so fingerprints written for normalized names also match.
    if " " in raw:
        out.add(re.sub(r"\s+", "_", raw))
    for pre in ("_source.", "fields."):
        if raw.startswith(pre):
            out.add(raw[len(pre):])
    for item in list(out):
        for pre, repl in (("kibana.alert.original_event.", "event."), ("kibana.alert.original_data_stream.", "data_stream."), ("signal.original_event.", "event."), ("signal.rule.", "kibana.alert.rule."), ("signal.", "kibana.alert.")):
            if item.startswith(pre):
                out.add(repl + item[len(pre):])
        if "trend_micro_vision_one.alert." in item:
            out.add(item.split("trend_micro_vision_one.alert.", 1)[1])
    return out


def detect_vendor_kit(fields: Iterable[str], header_text: str = "") -> dict[str, object]:
    reload_kits_if_changed()   # pick up user kits (data/kits) edited on disk
    normalized: set[str] = set()
    for field in fields:
        if str(field).strip():
            normalized.update(_field_variants_for_detection(str(field)))
    header = header_text.lower()
    scored: list[tuple[int, int, str, list[str]]] = []
    for kit_id, kit in KITS.items():
        score = 0
        matches: list[str] = []
        for pattern, weight in kit.fingerprints:
            hit = next((field for field in normalized if re.match(pattern, field, re.IGNORECASE)), None)
            if hit is not None:
                score += weight
                matches.append(hit)
        for hint in kit.header_hints:
            if hint in header:
                score += 5
                matches.append(f"header:{hint}")
        scored.append((score, len(matches), kit_id, matches))
    scored.sort(reverse=True)
    best_score, match_count, best_id, matches = scored[0]
    second_score = scored[1][0] if len(scored) > 1 else 0
    # Require either two independent fingerprints or one very distinctive hit.
    detected = best_id if (match_count >= 2 and best_score >= 5) or best_score >= 8 else None
    if not detected:
        return {"id": None, "label": "Generic", "score": best_score, "confidence": 0.0, "matches": matches}
    margin = max(0, best_score - second_score)
    confidence = min(1.0, 0.35 + best_score / 24 + margin / 20)
    kit = KITS[detected]
    return {
        "id": detected,
        "label": kit.label,
        "version": kit.version,
        "score": best_score,
        "confidence": round(confidence, 3),
        "matches": matches[:12],
    }


def kit_metadata() -> list[dict[str, object]]:
    return [
        {
            "id": kit.id,
            "label": kit.label,
            "version": kit.version,
            "aliases": list(kit.aliases),
            "notes": kit.notes,
            "rules": len(kit.rules),
            "fingerprints": len(kit.fingerprints),
        }
        for kit in KITS.values()
    ]


def kit_info(value: str | None, *, forced: bool = False) -> dict[str, object]:
    canonical = canonical_kit_id(value)
    if not canonical:
        return {"id": None, "label": "Generic", "version": None, "score": 0, "confidence": 0.0, "matches": [], "forced": forced}
    kit = KITS[canonical]
    return {
        "id": canonical,
        "label": kit.label,
        "version": kit.version,
        "score": None if forced else 0,
        "confidence": 1.0 if forced else 0.0,
        "matches": [],
        "forced": forced,
    }
