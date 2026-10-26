"""Structured log parsers for LogMask.

Supported formats:
- JSON documents (objects, arrays and scalar roots)
- NDJSON / JSON Lines
- CEF
- LEEF
- Syslog messages carrying key=value fields

The module preserves the logical structure and applies field-aware masking to
nested values. Unknown populated fields are fail-closed: safe mode elides them;
without safe mode they are reported as failed transformations.
"""

from __future__ import annotations

import json
import re
import io
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from vendor_kits import canonical_kit_id, detect_vendor_kit, kit_info

from logmask import (
    build_host_label_index,
    ELIDED,
    Anonymizer,
    CsvAnonymizer,
    Deanonymizer,
    Vault,
    is_safe_column,
    redact_residuals,
    resolve_field,
    col_candidates,
    scan_sensitive_residuals,
    sweep_known,
    IDENTITY_SWEEP_KINDS,
)

STRUCTURED_FORMATS = ("json", "ndjson", "cef", "leef", "syslog")

DESCRIPTIVE_TEXT_RX = re.compile(
    r"(?:^|\.)(?:description|message|reason|reason\.text|model|rule\.name|matched_rule.*\.name|filter.*\.name)(?:$|\.)",
    re.IGNORECASE,
)
AI_NAMESPACE_FIELDS = {
    "data_stream.namespace",
    "kibana.alert.original_data_stream.namespace",
}

def _is_descriptive_text_path(path: str) -> bool:
    normalized = path.replace("[]", "")
    if DESCRIPTIVE_TEXT_RX.search(normalized):
        return True
    # Product rule/model labels are useful natural-language context. Avoid
    # vault sweeps here, because a previous bad mapping could turn ordinary
    # words like "behavior" into host pseudonyms.
    return any(cand in {"name", "model"} for cand in col_candidates(normalized))

def _is_ai_external_source(source: str) -> bool:
    return str(source or "").startswith("ai-analysis:")

def _workflow_field_decision(path: str, source: str) -> tuple[str | None, str | None, str | None]:
    if not _is_ai_external_source(source):
        return None, None, None
    candidates = set(col_candidates(path))
    if candidates & AI_NAMESPACE_FIELDS:
        return "opaque", "mask", "workflow:ai-analysis"
    return None, None, None


def _reject_constant(value: str):
    raise ValueError(f"non-standard JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting is too deep") from exc


@dataclass
class FieldStat:
    kind: str | None = None
    action: str = "keep"
    inferred_by: str = ""
    nonempty: int = 0
    masked: int = 0
    elided: int = 0
    failed: int = 0
    policy_kept: int = 0
    safe_keep: bool = False


@dataclass
class StructuredResult:
    format: str
    output: str
    records: int = 1
    catalog: str | None = None
    vendor_detection: dict[str, Any] = field(default_factory=dict)
    fields: OrderedDict[str, FieldStat] = field(default_factory=OrderedDict)
    elided_samples: list[str] = field(default_factory=list)
    failed_samples: list[str] = field(default_factory=list)
    swept: int = 0

    @property
    def elided(self) -> int:
        return sum(item.elided for item in self.fields.values())

    @property
    def failed(self) -> int:
        return sum(item.failed for item in self.fields.values())

    @property
    def policy_kept(self) -> int:
        return sum(item.policy_kept for item in self.fields.values())

    @property
    def exposed(self) -> int:
        return sum(item.nonempty for item in self.fields.values() if item.action == "keep" and not item.safe_keep)

    @property
    def blocked(self) -> bool:
        # Every scalar and structured prefix is validated during traversal.
        # Re-scanning the serialized document would misclassify safe operational
        # values such as ECS event.dataset="windows.security" as FQDNs.
        return self.failed > 0 or self.exposed > 0

    def fields_payload(self) -> list[dict[str, Any]]:
        return [
            {
                "column": path,
                "kind": stat.kind,
                "action": stat.action,
                "inferred_by": stat.inferred_by,
                "nonempty": stat.nonempty,
                "masked": stat.masked,
                "elided": stat.elided,
                "failed": stat.failed,
                "policy_kept": stat.policy_kept,
                "safe_keep": stat.safe_keep,
                "exposed": stat.action == "keep" and stat.nonempty > 0 and not stat.safe_keep,
            }
            for path, stat in self.fields.items()
        ]


class StructuredAnonymizer:
    """Field-aware anonymizer shared by all structured parsers."""

    def __init__(
        self,
        anon: Anonymizer,
        vault: Vault,
        *,
        safe: bool,
        source: str = "paste",
        family: str | None = None,
    ):
        self.anon = anon
        self.vault = vault
        self.safe = safe
        self.source = source
        self.family = family
        self.result: StructuredResult | None = None
        self._scalar = CsvAnonymizer(anon, {"columns": {}}, source, safe=safe)
        self._decision_cache: dict = {}   # per-column classification (perf)

    @staticmethod
    def _display(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _has_value(value: Any) -> bool:
        return value is not None and value != ""

    def _sample(self, collection: list[str], value: Any) -> None:
        rendered = self._display(value)
        if rendered not in collection and len(collection) < 10:
            collection.append(rendered)

    def _stat(self, path: str, *, kind: str | None, action: str, inferred_by: str) -> FieldStat:
        assert self.result is not None
        stat = self.result.fields.get(path)
        if stat is None:
            stat = FieldStat(kind=kind, action=action, inferred_by=inferred_by)
            self.result.fields[path] = stat
        elif stat.kind is None and kind is not None:
            stat.kind = kind
            stat.action = action
            stat.inferred_by = inferred_by
        return stat

    def _safe_text(self, value: str, *, sweep: bool = True,
                   sweep_kinds=None, url_ioc: bool = False) -> tuple[str, int, int, list[str]]:
        before_redacted = self.anon.dlp_actions.get("redact", 0)
        out = self.anon.process(value, url_ioc=url_ioc)
        swept = 0
        elided = self.anon.dlp_actions.get("redact", 0) - before_redacted
        samples: list[str] = ["DLP:redacted"] if elided else []
        if self.safe:
            if sweep:
                out, swept = sweep_known(self.vault, out, self.anon.opt, kinds=sweep_kinds)
            out, residual_elided, residual_samples = redact_residuals(
                out, self.anon.opt.dlp_policy, allow_url_hosts=url_ioc)
            elided += residual_elided
            for sample in residual_samples:
                if sample not in samples:
                    samples.append(sample)
        return out, swept, elided, samples

    def transform_scalar(self, path: str, value: Any) -> Any:
        if value is None or isinstance(value, bool):
            return value

        raw = value if isinstance(value, str) else str(value)
        classify_path = path.replace("[]", "")
        decision = self._decision_cache.get(classify_path)
        if decision is None:
            wk_kind, wk_action, wk_by = _workflow_field_decision(classify_path, self.source)
            if wk_action:
                from logmask import FieldDecision
                decision = FieldDecision(wk_kind, wk_action, wk_by or "workflow")
            else:
                decision = resolve_field(classify_path, [raw], self.family)
                if not decision.inferred_by and self.result and self.result.format in {"cef", "leef", "syslog"}:
                    decision = resolve_field(classify_path, [raw], self.result.format)
            self._decision_cache[classify_path] = decision
        kind, inferred_by = decision.kind, decision.inferred_by

        if decision.action == "text":
            url_ioc = decision.kind == "ioc"
            stat = self._stat(path, kind=None, action="text", inferred_by=inferred_by)
            stat.nonempty += int(self._has_value(value))
            before_masked = sum(self.anon.counts.values())
            before_blocked = len(self.anon.dlp_blocked)
            # v0.18.1: sui campi descrittivi lo sweep per-campo resta spento
            # (una parola comune finita nel vault corromperebbe il testo
            # naturale). Le identita' vengono recuperate dallo sweep finale in
            # anonymize_structured: una sola passata per job invece di una per
            # record, quindi copre gli stessi casi senza il costo quadratico.
            out, swept, elided, samples = self._safe_text(
                raw, sweep=not _is_descriptive_text_path(classify_path),
                url_ioc=url_ioc)
            assert self.result is not None
            new_blocked = self.anon.dlp_blocked[before_blocked:]
            if new_blocked:
                stat.failed += len(new_blocked)
                for finding in new_blocked:
                    self._sample(self.result.failed_samples, f"DLP:block:{finding.get('kind', 'unknown')}")
            self.result.swept += swept
            if sum(self.anon.counts.values()) > before_masked:
                stat.masked += 1
            if elided:
                stat.elided += elided
                for sample in samples:
                    self._sample(self.result.elided_samples, sample)
            findings = scan_sensitive_residuals(out, self.anon.opt.dlp_policy,
                                                allow_url_hosts=url_ioc)
            if findings:
                if self.safe:
                    stat.elided += 1
                    self._sample(self.result.elided_samples, value)
                    return ELIDED
                stat.failed += 1
                self._sample(self.result.failed_samples, value)
                return value
            return out

        if decision.action == "keep" and inferred_by:
            stat = self._stat(path, kind=None, action="keep", inferred_by=inferred_by)
            stat.nonempty += int(self._has_value(value))
            stat.safe_keep = True
            if not self._has_value(value):
                return value
            before_masked = sum(self.anon.counts.values())
            before_redacted = self.anon.dlp_actions.get("redact", 0)
            before_blocked = len(self.anon.dlp_blocked)
            out = self.anon.process_dlp_field(path, raw)
            masked_delta = sum(self.anon.counts.values()) - before_masked
            redacted_delta = self.anon.dlp_actions.get("redact", 0) - before_redacted
            new_blocked = self.anon.dlp_blocked[before_blocked:]
            if masked_delta:
                stat.masked += 1
                stat.action = "mask"
                stat.kind = "dlp"
            if redacted_delta:
                stat.elided += redacted_delta
                stat.action = "redact"
                assert self.result is not None
                self._sample(self.result.elided_samples, value)
            if new_blocked:
                stat.failed += len(new_blocked)
                assert self.result is not None
                for finding in new_blocked:
                    self._sample(self.result.failed_samples, f"DLP:block:{finding.get('kind', 'unknown')}")
            return out if out != raw else value

        if kind:
            stat = self._stat(path, kind=kind, action="mask", inferred_by=inferred_by)
            stat.nonempty += int(self._has_value(value))
            before_masked = sum(self.anon.counts.values())
            before_policy_kept = sum(self.anon.policy_kept.values())
            out, failures = self._scalar._mask_cell(kind, raw)
            masked_delta = sum(self.anon.counts.values()) - before_masked
            policy_kept_delta = sum(self.anon.policy_kept.values()) - before_policy_kept
            if policy_kept_delta:
                stat.policy_kept += policy_kept_delta
                stat.safe_keep = True
                if masked_delta == 0 and out == raw:
                    stat.action = "keep"
                    stat.inferred_by = "ip-policy"
            if failures:
                assert self.result is not None
                if self.safe:
                    stat.elided += 1
                    self._sample(self.result.elided_samples, value)
                    return ELIDED
                stat.failed += len(failures)
                for failure in failures:
                    self._sample(self.result.failed_samples, failure)
                return out
            if out != raw or masked_delta > 0:
                stat.masked += 1
                return out
            stat.safe_keep = True
            return value

        # Unknown fields still receive field-context DLP classification before
        # the generic fail-closed fallback (for example customer_phone or iban).
        before_masked = sum(self.anon.counts.values())
        before_redacted = self.anon.dlp_actions.get("redact", 0)
        before_blocked = len(self.anon.dlp_blocked)
        dlp_out = self.anon.process_dlp_field(path, raw)
        masked_delta = sum(self.anon.counts.values()) - before_masked
        redacted_delta = self.anon.dlp_actions.get("redact", 0) - before_redacted
        new_blocked = self.anon.dlp_blocked[before_blocked:]
        if dlp_out != raw or masked_delta or redacted_delta or new_blocked:
            action = "redact" if redacted_delta else ("mask" if masked_delta else "keep")
            stat = self._stat(path, kind="dlp" if masked_delta else None, action=action, inferred_by="dlp:field")
            stat.nonempty += int(self._has_value(value))
            if masked_delta:
                stat.masked += 1
            if redacted_delta:
                stat.elided += redacted_delta
                assert self.result is not None
                self._sample(self.result.elided_samples, "DLP:redacted")
            if new_blocked:
                stat.failed += len(new_blocked)
                assert self.result is not None
                for finding in new_blocked:
                    self._sample(self.result.failed_samples, f"DLP:block:{finding.get('kind', 'unknown')}")
            return dlp_out

        safe_keep = is_safe_column(path, [raw])
        action = "keep" if safe_keep else ("redact" if self.safe else "keep")
        stat = self._stat(path, kind=None, action=action, inferred_by="safe" if self.safe and not safe_keep else "")
        stat.nonempty += int(self._has_value(value))
        stat.safe_keep = stat.safe_keep or safe_keep
        if not self._has_value(value):
            return value
        if safe_keep:
            before_masked = sum(self.anon.counts.values())
            before_redacted = self.anon.dlp_actions.get("redact", 0)
            before_blocked = len(self.anon.dlp_blocked)
            out = self.anon.process_dlp_field(path, raw)
            if sum(self.anon.counts.values()) > before_masked:
                stat.masked += 1
                stat.action = "mask"
                stat.kind = "dlp"
            redacted_delta = self.anon.dlp_actions.get("redact", 0) - before_redacted
            if redacted_delta:
                stat.elided += redacted_delta
                stat.action = "redact"
                assert self.result is not None
                self._sample(self.result.elided_samples, value)
            new_blocked = self.anon.dlp_blocked[before_blocked:]
            if new_blocked:
                stat.failed += len(new_blocked)
                assert self.result is not None
                for finding in new_blocked:
                    self._sample(self.result.failed_samples, f"DLP:block:{finding.get('kind', 'unknown')}")
            return out if out != raw else value
        assert self.result is not None
        if self.safe:
            stat.elided += 1
            self._sample(self.result.elided_samples, value)
            return ELIDED
        stat.failed += 1
        self._sample(self.result.failed_samples, value)
        return value

    def transform_node(self, value: Any, path: str = "$") -> Any:
        if isinstance(value, dict):
            return {
                key: self.transform_node(child, f"{path}.{key}" if path != "$" else str(key))
                for key, child in value.items()
            }
        if isinstance(value, list):
            child_path = f"{path}[]"
            return [self.transform_node(child, child_path) for child in value]
        return self.transform_scalar(path, value)

    def register_fields(self) -> None:
        assert self.result is not None
        for path, stat in self.result.fields.items():
            self.vault.register_field(
                self.source,
                path,
                stat.kind,
                stat.action,
                self.result.records,
                stat.nonempty,
                stat.masked,
                stat.elided,
                stat.failed,
            )

    def process_json(self, text: str) -> StructuredResult:
        data = strict_json_loads(text)
        self.result = StructuredResult(format="json", output="")
        transformed = self.transform_node(data)
        indent = 2 if "\n" in text else None
        self.result.output = json.dumps(
            transformed,
            ensure_ascii=False,
            indent=indent,
            separators=None if indent else (",", ":"),
        ) + ("\n" if text.endswith("\n") else "")
        self.register_fields()
        return self.result

    def process_ndjson(self, text: str) -> StructuredResult:
        self.result = StructuredResult(format="ndjson", output="", records=0)
        out_lines: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                out_lines.append(line)
                continue
            try:
                data = strict_json_loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid NDJSON at line {line_no}: {exc.msg}") from exc
            transformed = self.transform_node(data)
            out_lines.append(json.dumps(transformed, ensure_ascii=False, separators=(",", ":")))
            self.result.records += 1
        self.result.output = "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")
        self.register_fields()
        return self.result

    def _process_pairs(
        self,
        fmt: str,
        prefix: str,
        pairs: list[tuple[str, str, bool]],
        renderer: Callable[[str, list[tuple[str, str, bool]]], str],
        *,
        prefix_as_text: bool = True,
    ) -> StructuredResult:
        self.result = StructuredResult(format=fmt, output="")
        transformed_prefix = prefix
        if prefix_as_text and prefix:
            transformed_prefix, swept, elided, samples = self._safe_text(prefix)
            self.result.swept += swept
            if elided:
                stat = self._stat("@prefix", kind=None, action="text", inferred_by="name")
                stat.nonempty += 1
                stat.elided += elided
                for sample in samples:
                    self._sample(self.result.elided_samples, sample)
            findings = scan_sensitive_residuals(transformed_prefix, self.anon.opt.dlp_policy)
            if findings and self.safe:
                transformed_prefix = ELIDED
                stat = self._stat("@prefix", kind=None, action="redact", inferred_by="safe")
                stat.nonempty += 1
                stat.elided += 1
                self._sample(self.result.elided_samples, prefix)
            elif findings:
                stat = self._stat("@prefix", kind=None, action="keep", inferred_by="")
                stat.nonempty += 1
                stat.failed += 1
                self._sample(self.result.failed_samples, prefix)
        new_pairs = [(key, str(self.transform_scalar(key, value)), quoted) for key, value, quoted in pairs]
        self.result.output = renderer(transformed_prefix, new_pairs)
        self.register_fields()
        return self.result

    def process_cef(self, text: str) -> StructuredResult:
        self.result = StructuredResult(format="cef", output="", records=0)
        output_lines: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                output_lines.append(line)
                continue
            try:
                header, pairs = parse_cef(line)
            except ValueError as exc:
                raise ValueError(f"invalid CEF at line {line_no}: {exc}") from exc
            new_header = list(header)
            stat = self._stat("cef.name", kind=None, action="text", inferred_by="name")
            stat.nonempty += int(bool(new_header[5]))
            before_masked = sum(self.anon.counts.values())
            processed, swept, elided, samples = self._safe_text(new_header[5])
            self.result.swept += swept
            if sum(self.anon.counts.values()) > before_masked:
                stat.masked += 1
            if elided:
                stat.elided += elided
                for sample in samples:
                    self._sample(self.result.elided_samples, sample)
            findings = scan_sensitive_residuals(processed, self.anon.opt.dlp_policy)
            if findings and self.safe:
                stat.elided += 1
                self._sample(self.result.elided_samples, new_header[5])
                processed = ELIDED
            elif findings:
                stat.failed += len(findings)
                self._sample(self.result.failed_samples, new_header[5])
            new_header[5] = processed
            new_pairs = [(key, str(self.transform_scalar(key, value)), quoted) for key, value, quoted in pairs]
            output_lines.append(render_cef(new_header, new_pairs))
            self.result.records += 1
        self.result.output = "\n".join(output_lines) + ("\n" if text.endswith("\n") else "")
        self.register_fields()
        return self.result

    def process_leef(self, text: str) -> StructuredResult:
        self.result = StructuredResult(format="leef", output="", records=0)
        output_lines: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                output_lines.append(line)
                continue
            try:
                header, pairs, delimiter = parse_leef(line)
            except ValueError as exc:
                raise ValueError(f"invalid LEEF at line {line_no}: {exc}") from exc
            new_pairs = [(key, str(self.transform_scalar(key, value)), quoted) for key, value, quoted in pairs]
            output_lines.append(render_leef(header, new_pairs, delimiter))
            self.result.records += 1
        self.result.output = "\n".join(output_lines) + ("\n" if text.endswith("\n") else "")
        self.register_fields()
        return self.result

    def process_syslog(self, text: str) -> StructuredResult:
        self.result = StructuredResult(format="syslog", output="", records=0)
        output_lines: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                output_lines.append(line)
                continue
            try:
                prefix, pairs = parse_syslog_kv(line)
            except ValueError as exc:
                raise ValueError(f"invalid Syslog at line {line_no}: {exc}") from exc
            header, hostname, remainder = split_syslog_prefix(prefix)
            if hostname is not None:
                hostname = str(self.transform_scalar("syslog.hostname", hostname))
            transformed_remainder = remainder
            if remainder:
                transformed_remainder, swept, elided, samples = self._safe_text(remainder)
                self.result.swept += swept
                if elided:
                    stat = self._stat("syslog.message_prefix", kind=None, action="text", inferred_by="name")
                    stat.nonempty += 1
                    stat.elided += elided
                    for sample in samples:
                        self._sample(self.result.elided_samples, sample)
                findings = scan_sensitive_residuals(transformed_remainder, self.anon.opt.dlp_policy)
                if findings and self.safe:
                    transformed_remainder = ELIDED
                    stat = self._stat("syslog.message_prefix", kind=None, action="redact", inferred_by="safe")
                    stat.nonempty += 1
                    stat.elided += 1
                    self._sample(self.result.elided_samples, remainder)
                elif findings:
                    stat = self._stat("syslog.message_prefix", kind=None, action="keep", inferred_by="")
                    stat.nonempty += 1
                    stat.failed += 1
                    self._sample(self.result.failed_samples, remainder)
            transformed_prefix = join_syslog_prefix(header, hostname, transformed_remainder)
            new_pairs = [(key, str(self.transform_scalar(key, value)), quoted) for key, value, quoted in pairs]
            output_lines.append(render_syslog(transformed_prefix, new_pairs))
            self.result.records += 1
        self.result.output = "\n".join(output_lines) + ("\n" if text.endswith("\n") else "")
        self.register_fields()
        return self.result



class StructuredDeanonymizer:
    def __init__(self, deanon: Deanonymizer):
        self.deanon = deanon

    def transform_node(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.transform_node(child) for key, child in value.items()}
        if isinstance(value, list):
            return [self.transform_node(child) for child in value]
        if isinstance(value, str):
            return self.deanon.process(value)
        return value

    def process_json(self, text: str) -> str:
        data = strict_json_loads(text)
        transformed = self.transform_node(data)
        indent = 2 if "\n" in text else None
        return json.dumps(transformed, ensure_ascii=False, indent=indent, separators=None if indent else (",", ":")) + ("\n" if text.endswith("\n") else "")

    def process_ndjson(self, text: str) -> str:
        out: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                out.append(line)
                continue
            try:
                out.append(json.dumps(self.transform_node(strict_json_loads(line)), ensure_ascii=False, separators=(",", ":")))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid NDJSON at line {line_no}: {exc.msg}") from exc
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    def process_cef(self, text: str) -> str:
        out: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                out.append(line)
                continue
            try:
                header, pairs = parse_cef(line)
            except ValueError as exc:
                raise ValueError(f"invalid CEF at line {line_no}: {exc}") from exc
            header = [self.deanon.process(value) for value in header]
            pairs = [(key, self.deanon.process(value), quoted) for key, value, quoted in pairs]
            out.append(render_cef(header, pairs))
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    def process_leef(self, text: str) -> str:
        out: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                out.append(line)
                continue
            try:
                header, pairs, delimiter = parse_leef(line)
            except ValueError as exc:
                raise ValueError(f"invalid LEEF at line {line_no}: {exc}") from exc
            header = [self.deanon.process(value) for value in header]
            pairs = [(key, self.deanon.process(value), quoted) for key, value, quoted in pairs]
            out.append(render_leef(header, pairs, delimiter))
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    def process_syslog(self, text: str) -> str:
        out: list[str] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                out.append(line)
                continue
            try:
                prefix, pairs = parse_syslog_kv(line)
            except ValueError as exc:
                raise ValueError(f"invalid Syslog at line {line_no}: {exc}") from exc
            prefix = self.deanon.process(prefix)
            pairs = [(key, self.deanon.process(value), quoted) for key, value, quoted in pairs]
            out.append(render_syslog(prefix, pairs))
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")



# ---------------------------------------------------------------- vendor detection


def _collect_json_fields(value: Any, path: str = "$") -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            full = key if path == "$" else f"{path}.{key}"
            fields.add(str(key))
            fields.add(full)
            fields.update(_collect_json_fields(child, full))
    elif isinstance(value, list):
        for child in value[:50]:
            fields.update(_collect_json_fields(child, path + "[]"))
    return fields


def detect_structured_vendor(fmt: str, text: str) -> dict[str, Any]:
    fields: set[str] = set()
    header_parts: list[str] = []
    try:
        if fmt == "json":
            fields = _collect_json_fields(strict_json_loads(text))
        elif fmt == "ndjson":
            for line in [ln for ln in text.splitlines() if ln.strip()][:50]:
                fields.update(_collect_json_fields(strict_json_loads(line)))
        elif fmt == "cef":
            for line in [ln for ln in text.splitlines() if ln.strip()][:50]:
                header, pairs = parse_cef(line)
                header_parts.extend(header[:3])
                fields.update(key for key, _value, _quoted in pairs)
        elif fmt == "leef":
            for line in [ln for ln in text.splitlines() if ln.strip()][:50]:
                header, pairs, _delimiter = parse_leef(line)
                header_parts.extend(header[:3])
                fields.update(key for key, _value, _quoted in pairs)
        elif fmt == "syslog":
            for line in [ln for ln in text.splitlines() if ln.strip()][:50]:
                prefix, pairs = parse_syslog_kv(line)
                header_parts.append(prefix)
                fields.update(key for key, _value, _quoted in pairs)
    except (ValueError, json.JSONDecodeError):
        return kit_info(None)
    return detect_vendor_kit(fields, " ".join(header_parts))


# ---------------------------------------------------------------- detection


def transpose_keyvalue_csv(text: str) -> "str | None":
    """Riconosce un export VERTICALE "campo -> valore" e lo ribalta in orizzontale.

    Un singolo alert esportato da molte console (Cortex XSIAM/XDR fra le altre)
    e' una tabella a due colonne: nome_campo <TAB> valore, un campo per riga.
    Letto come CSV normale, l'header diventa la prima riga ("action",
    "DETECTED") e i nomi campo veri finiscono fra i VALORI, quindi il kit non
    viene rilevato e l'intera colonna dei valori viene elisa.

    Qui la prima colonna viene usata come header: se quei nomi identificano un
    kit vendor (segnale forte e specifico) si costruisce l'equivalente
    orizzontale, cosi' ogni campo riceve la classificazione giusta. Se NON si
    rileva un kit non si tocca nulla e il flusso resta invariato (fail-closed:
    la sicurezza non cambia, cambia solo l'utilita').

    Ritorna il CSV orizzontale (una riga di header + una di valori) oppure None.
    """
    import csv as _csv
    from vendor_kits import detect_vendor_kit
    raw = text.strip("\n")
    if not raw or "\n" not in raw:
        return None
    delim = "\t" if raw.count("\t") >= raw.count(",") and "\t" in raw else ","
    try:
        rows = list(_csv.reader(raw.splitlines(), delimiter=delim))
    except _csv.Error:
        return None
    pairs = [r for r in rows if len(r) == 2]
    if len(pairs) < 6 or len(pairs) < 0.8 * len(rows):     # dev'essere quasi tutto 2-col
        return None

    fields: list[str] = []
    values: dict[str, list[str]] = {}
    last = None
    for key, value in pairs:
        key = key.strip()
        if not key:
            continue
        if key.isdigit() and last is not None:             # elemento di un array
            values[last].append(value)
            continue
        if key not in values:
            fields.append(key)
            values[key] = []
        if value != "":
            values[key].append(value)
        last = key

    names = [f for f in fields if not f.isdigit()]
    if len(names) < 6:
        return None
    det = detect_vendor_kit(names)
    if not det.get("id") or det.get("score", 0) < 8:       # niente kit -> non ribaltare
        return None

    out = io.StringIO()
    writer = _csv.writer(out, delimiter=",", lineterminator="\n")
    writer.writerow(fields)
    writer.writerow([", ".join(values[f]) for f in fields])
    return out.getvalue()


def detect_structured_format(text: str) -> str | None:
    stripped = text.lstrip("\ufeff\r\n\t ")
    if stripped.startswith("CEF:"):
        return "cef"
    if stripped.startswith("LEEF:"):
        return "leef"
    lines = [line for line in text.splitlines() if line.strip()]
    if stripped.startswith(("{", "[")):
        try:
            strict_json_loads(stripped)
            return "json"
        except (json.JSONDecodeError, ValueError):
            if len(lines) >= 2 and all(line.lstrip().startswith(("{", "[")) for line in lines):
                return "ndjson"
            # JSON-looking input is parsed as JSON and rejected explicitly rather
            # than silently falling back to free text.
            return "json"
    if lines:
        try:
            parsed = [parse_syslog_kv(line) for line in lines]
            if all(len(pairs) >= 2 for _prefix, pairs in parsed):
                return "syslog"
        except ValueError:
            pass
    return None


# ------------------------------------------------------------- CEF utilities


def _split_escaped(text: str, delimiter: str, maxsplit: int = -1) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    splits = 0
    for char in text:
        if escaped:
            buf.append("\\" + char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == delimiter and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(buf))
            buf = []
            splits += 1
        else:
            buf.append(char)
    if escaped:
        buf.append("\\")
    parts.append("".join(buf))
    return parts


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _escape(value: str, chars: str) -> str:
    value = value.replace("\\", "\\\\")
    for char in chars:
        value = value.replace(char, "\\" + char)
    return value


KV_KEY_RX = re.compile(r"(?:(?<=^)|(?<=\s))([A-Za-z][A-Za-z0-9_.-]{0,127})=")


def _parse_space_pairs(text: str) -> list[tuple[str, str, bool]]:
    matches = list(KV_KEY_RX.finditer(text))
    if not matches:
        return []
    pairs: list[tuple[str, str, bool]] = []
    for idx, match in enumerate(matches):
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        raw = text[start:end].strip()
        quoted = len(raw) >= 2 and raw[0] == raw[-1] == '"'
        value = raw[1:-1] if quoted else raw
        value = _unescape(value)
        pairs.append((match.group(1), value, quoted))
    return pairs


def _render_space_pairs(pairs: list[tuple[str, str, bool]], *, cef: bool = False) -> str:
    rendered: list[str] = []
    for key, value, quoted in pairs:
        if cef:
            escaped = _escape(value, "=")
            rendered.append(f"{key}={escaped}")
            continue
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        needs_quote = quoted or bool(re.search(r"\s", escaped))
        rendered.append(f'{key}="{escaped}"' if needs_quote else f"{key}={escaped}")
    return " ".join(rendered)


def parse_cef(text: str) -> tuple[list[str], list[tuple[str, str, bool]]]:
    stripped = text.strip("\r\n")
    if not stripped.startswith("CEF:"):
        raise ValueError("input is not CEF")
    parts = _split_escaped(stripped[4:], "|", maxsplit=7)
    if len(parts) != 8:
        raise ValueError("invalid CEF header: expected version, six header fields and extension")
    header = [_unescape(part) for part in parts[:7]]
    return header, _parse_space_pairs(parts[7])


def render_cef(header: list[str], pairs: list[tuple[str, str, bool]]) -> str:
    if len(header) != 7:
        raise ValueError("CEF header must contain 7 fields")
    escaped = [_escape(str(value), "|") for value in header]
    extension = _render_space_pairs(pairs, cef=True)
    return "CEF:" + "|".join(escaped) + "|" + extension


# ------------------------------------------------------------ LEEF utilities


def _leef_delimiter(token: str) -> str:
    token = _unescape(token)
    if token.lower() in {"0x09", "\t", "tab"}:
        return "\t"
    if token.lower().startswith("0x"):
        try:
            return chr(int(token[2:], 16))
        except (ValueError, OverflowError):
            pass
    if len(token) == 1:
        return token
    raise ValueError(f"invalid LEEF delimiter: {token}")


def parse_leef(text: str) -> tuple[list[str], list[tuple[str, str, bool]], str]:
    stripped = text.strip("\r\n")
    if not stripped.startswith("LEEF:"):
        raise ValueError("input is not LEEF")
    parts = _split_escaped(stripped[5:], "|", maxsplit=6)
    if len(parts) not in {6, 7}:
        raise ValueError("invalid LEEF header")
    header = [_unescape(part) for part in parts[:5]]
    if len(parts) == 7:
        delimiter = _leef_delimiter(parts[5])
        ext = parts[6]
    else:
        ext = parts[5]
        delimiter = "\t" if "\t" in ext else " "

    pairs: list[tuple[str, str, bool]] = []
    if not ext:
        return header, pairs, delimiter
    if delimiter != " ":
        pair_parts = _split_escaped(ext, delimiter)
        for item in pair_parts:
            if not item:
                continue
            key, sep, value = item.partition("=")
            if not sep or not key:
                raise ValueError(f"invalid LEEF extension item: {item}")
            quoted = len(value) >= 2 and value[0] == value[-1] == '"'
            raw_value = value[1:-1] if quoted else value
            pairs.append((key, _unescape(raw_value), quoted))
    else:
        pairs = _parse_space_pairs(ext)
    return header, pairs, delimiter


def render_leef(header: list[str], pairs: list[tuple[str, str, bool]], delimiter: str) -> str:
    if len(header) != 5:
        raise ValueError("LEEF header must contain 5 fields")
    base = "LEEF:" + "|".join(_escape(str(value), "|") for value in header)
    if not pairs:
        return base + "|"
    if delimiter == " ":
        return base + "|" + _render_space_pairs(pairs)
    extension = delimiter.join(
        f'{key}="{_escape(value, delimiter).replace(chr(34), chr(92)+chr(34))}"'
        if quoted
        else f"{key}={_escape(value, delimiter)}"
        for key, value, quoted in pairs
    )
    delimiter_header = "" if delimiter == "\t" else _escape(delimiter, "|") + "|"
    return base + "|" + delimiter_header + extension


# ---------------------------------------------------------- Syslog utilities


SYSLOG_KV_RX = re.compile(r"(?:(?<=^)|(?<=\s))([A-Za-z][A-Za-z0-9_.-]{0,127})=(\"(?:\\.|[^\"])*\"|\S+)")


RFC3164_PREFIX_RX = re.compile(
    r"^(?P<head><\d+>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)(?P<host>\S+)(?P<rest>.*)$"
)
RFC5424_PREFIX_RX = re.compile(
    r"^(?P<head><\d+>\d+\s+\S+\s+)(?P<host>\S+)(?P<rest>.*)$"
)


def split_syslog_prefix(prefix: str) -> tuple[str, str | None, str]:
    for rx in (RFC5424_PREFIX_RX, RFC3164_PREFIX_RX):
        match = rx.match(prefix)
        if match:
            return match.group("head"), match.group("host"), match.group("rest")
    return "", None, prefix


def join_syslog_prefix(header: str, hostname: str | None, remainder: str) -> str:
    if hostname is None:
        return remainder
    return header + hostname + remainder


def parse_syslog_kv(text: str) -> tuple[str, list[tuple[str, str, bool]]]:
    stripped = text.strip("\r\n")
    matches = list(SYSLOG_KV_RX.finditer(stripped))
    if not matches:
        raise ValueError("no key=value fields found")
    prefix = stripped[: matches[0].start()].rstrip()
    pairs: list[tuple[str, str, bool]] = []
    cursor = matches[0].start()
    for index, match in enumerate(matches):
        if index and stripped[cursor:match.start()].strip():
            raise ValueError("unparsed text between Syslog key=value fields")
        raw = match.group(2)
        quoted = raw.startswith('"') and raw.endswith('"')
        value = raw[1:-1] if quoted else raw
        value = value.replace('\\"', '"').replace("\\\\", "\\")
        pairs.append((match.group(1), value, quoted))
        cursor = match.end()
    if stripped[cursor:].strip():
        raise ValueError("unparsed trailing text after Syslog key=value fields")
    return prefix, pairs


def render_syslog(prefix: str, pairs: list[tuple[str, str, bool]]) -> str:
    body = _render_space_pairs(pairs)
    return (prefix + " " + body).strip()


# -------------------------------------------------------------- dispatchers


_TOKEN_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]{2,252}")


def _iter_strings(text: str):
    """Token con la forma di hostname presenti nel testo grezzo.

    Volutamente indipendente dal formato (JSON/NDJSON/CEF/...): serve solo a
    sapere QUALI FQDN esistono nel documento, non a interpretarlo.
    """
    for m in _TOKEN_RX.finditer(text):
        tok = m.group(0)
        if "." in tok:
            yield tok


def anonymize_structured(
    fmt: str,
    text: str,
    anon: Anonymizer,
    vault: Vault,
    *,
    safe: bool,
    source: str,
    family: str | None = None,
) -> StructuredResult:
    forced = canonical_kit_id(family)
    detection = kit_info(forced, forced=True) if forced else detect_structured_vendor(fmt, text)
    effective_family = forced or detection.get("id") or (fmt if fmt in {"cef", "leef", "syslog"} else None)
    # v0.18.0: pre-pass sul documento per collegare i nomi host brevi ai loro
    # FQDN (stesso host = stesso token). Solo in-job: nessuna dipendenza dalla
    # storia del vault, quindi l'output resta determinato dal solo input.
    try:
        anon.set_host_label_index(build_host_label_index(_iter_strings(text)))
    except Exception:                       # mai bloccare l'anonimizzazione
        anon.set_host_label_index({})
    processor = StructuredAnonymizer(anon, vault, safe=safe, source=source, family=effective_family)
    if fmt == "json":
        result = processor.process_json(text)
    elif fmt == "ndjson":
        result = processor.process_ndjson(text)
    elif fmt == "cef":
        result = processor.process_cef(text)
    elif fmt == "leef":
        result = processor.process_leef(text)
    elif fmt == "syslog":
        result = processor.process_syslog(text)
    else:
        raise ValueError(f"unsupported structured format: {fmt}")
    result.catalog = str(effective_family) if effective_family else None
    result.vendor_detection = detection
    # v0.18.1: sweep finale di sicurezza sull'output completo, limitato alle
    # identita' (user/email). Durante il processing il vault si popola man mano:
    # un'identita' che compare in un campo descrittivo PRIMA del proprio campo
    # identita' (l'ordine delle chiavi non e' garantito) sfuggirebbe allo sweep
    # per-campo. Qui il vault e' completo, quindi l'ordine non conta piu'.
    if safe:
        try:
            swept_output, swept_n = sweep_known(vault, result.output, anon.opt,
                                                kinds=IDENTITY_SWEEP_KINDS)
            if swept_n:
                result.output = swept_output
                result.swept += swept_n
        except Exception:                   # mai bloccare l'anonimizzazione
            pass
    return result


def deanonymize_structured(fmt: str, text: str, deanon: Deanonymizer) -> str:
    processor = StructuredDeanonymizer(deanon)
    if fmt == "json":
        return processor.process_json(text)
    if fmt == "ndjson":
        return processor.process_ndjson(text)
    if fmt == "cef":
        return processor.process_cef(text)
    if fmt == "leef":
        return processor.process_leef(text)
    if fmt == "syslog":
        return processor.process_syslog(text)
    raise ValueError(f"unsupported structured format: {fmt}")
