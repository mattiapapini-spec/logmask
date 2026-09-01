"""Outlook .pst ingestion: extract messages and anonymize them to CSV / NDJSON.

Reading a .pst uses the read-only ``readpst`` tool (libpst / the ``pst-utils``
package), which converts the PST into per-folder mbox files. Writing a .pst is
deliberately NOT supported: there is no reliable open-source PST writer, so the
output is a per-message table (NDJSON or CSV), not a rebuilt mailbox.

Each message becomes a record and its fields are anonymized by the standard
LogMask engine (same tenant vault, so a sender is the same pseudonym in every
message). Recipient/sender fields are reduced to their e-mail ADDRESSES before
masking (the display name is dropped, not just masked), which removes the
"Mario Rossi" display-name leak; subject and body are scrubbed as free text
(e-mails now constant per domain, plus IPs, hosts, message-ids, client names);
date, folder and the attachment flag are kept.
"""
from __future__ import annotations

import csv
import html
import io
import json
import mailbox
import shutil
import os
import re
import subprocess
import tempfile
from email.message import Message
from html.parser import HTMLParser
from email.utils import getaddresses
from pathlib import Path
from typing import Iterator

READPST = "readpst"

# Fields anonymized as free text (everything that can carry PII); the rest of a
# record (date, folder, hasAttachments) is operational metadata and kept.
TEXT_FIELDS = ("from", "toRecipients", "ccRecipients", "bccRecipients",
               "subject", "completeHeader", "body", "attachmentNames")
# v0.23.1: due colonne per il contenuto del messaggio.
#   completeHeader - il messaggio come esce dall'archivio: MIME, HTML, header
#                    dei messaggi inoltrati e citati. Nulla viene perso.
#   body           - lo stesso contenuto ridotto a testo leggibile: niente tag,
#                    niente entita' HTML, spaziatura normalizzata. E' la colonna
#                    che un analista legge davvero.
RECORD_FIELDS = ("date", "folder", "from", "toRecipients", "ccRecipients",
                 "bccRecipients", "subject", "hasAttachments", "attachmentNames",
                 "completeHeader", "body")


def readpst_available() -> bool:
    """True if the ``readpst`` extractor is installed (pst-utils)."""
    return shutil.which(READPST) is not None


READPST_TIMEOUT = int(os.environ.get("LOGMASK_READPST_TIMEOUT", "300"))
# v0.24.1: tetto sui byte ESTRATTI. Il limite upload agisce sul .pst compresso;
# un archivio confezionato ad arte puo' far scrivere a readpst molti piu' byte
# di quelli caricati, fino a esaurire il disco del container. Il controllo
# avviene dopo l'estrazione (readpst non e' interrompibile a meta') ma prima di
# caricare i messaggi in memoria.
MAX_EXTRACTED = int(os.environ.get("LOGMASK_PST_MAX_EXTRACTED",
                                   str(1024 * 1024 * 1024)))


class PstExtractionError(RuntimeError):
    """readpst non e' riuscito a estrarre l'archivio: il messaggio riporta il
    motivo dato dallo strumento, invece di lasciare l'utente senza risposta."""


def _spawn(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=False, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=READPST_TIMEOUT)


def _rejected_option(proc) -> bool:
    """True se readpst ha rifiutato un'opzione (build senza -j)."""
    blob = ((proc.stderr or b"") + (proc.stdout or b"")).decode("utf-8", "replace").lower()
    return "usage:" in blob or "invalid option" in blob or "illegal option" in blob


def _run_readpst(pst_path: Path, out_dir: Path) -> None:
    """Estrae un PST in file mbox per cartella sotto out_dir (ricorsivo).

    v0.22.6: con timeout e stdin chiuso. Senza timeout, un PST protetto da
    password o danneggiato poteva bloccare readpst all'infinito: la richiesta
    non tornava mai e il browser mostrava "Failed to fetch", cioe' nessuna
    diagnosi. Ora dopo LOGMASK_READPST_TIMEOUT secondi si fallisce con un
    messaggio esplicito.
    """
    # -o output dir, -r ricrea la gerarchia cartelle, -q silenzioso,
    # -j 0 NESSUN job parallelo: con i job attivi libpst estrae una quantita' di
    # posta diversa a ogni esecuzione (libpst#7) e, se un figlio muore, il padre
    # esce comunque con status 0 (Ubuntu #1130751) - cioe' messaggi persi in
    # silenzio. Per un'anonimizzazione la perdita silenziosa e' inaccettabile.
    args = [READPST, "-o", str(out_dir), "-r", "-q", "-j", "0", str(pst_path)]
    try:
        proc = _spawn(args)
        if proc.returncode != 0 and _rejected_option(proc):
            # build di readpst senza -j: si riprova senza, non si fallisce.
            args = [READPST, "-o", str(out_dir), "-r", "-q", str(pst_path)]
            proc = _spawn(args)
    except subprocess.TimeoutExpired as exc:
        raise PstExtractionError(
            f"readpst non ha risposto entro {READPST_TIMEOUT}s: l'archivio "
            "potrebbe essere protetto da password o danneggiato."
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        detail = detail.splitlines()[-1] if detail else f"codice {proc.returncode}"
        raise PstExtractionError(f"readpst ha fallito: {detail[:300]}")


def _decode(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _body(msg: Message) -> str:
    """First text/plain body; fall back to the text/html part.

    v0.23.1: un messaggio non multipart in SOLO HTML - cioe' la maggior parte
    della posta reale - restituiva stringa vuota, perche' si accettava solo
    text/plain. Il contenuto del messaggio spariva dall'export senza alcun
    errore. Ora si accetta qualsiasi parte testuale.
    """
    if not msg.is_multipart():
        if msg.get_content_maintype() == "text":
            return _decode(msg)
        return ""
    plain, html = "", ""
    for part in msg.walk():
        cdisp = str(part.get("Content-Disposition") or "")
        if "attachment" in cdisp.lower():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and not plain:
            plain = _decode(part)
        elif ctype == "text/html" and not html:
            html = _decode(part)
    return plain or html


_HTML_HINT_RX = re.compile(
    r"<\s*/?\s*(?:html|body|head|div|p|br|table|tr|td|span|a|font|style)\b", re.I)
# Tag che in un testo leggibile corrispondono a un'andata a capo.
_BLOCK_TAGS = frozenset({
    "p", "div", "br", "tr", "li", "ul", "ol", "table", "blockquote", "hr",
    "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article",
})
_DROP_TAGS = frozenset({"script", "style", "head", "title"})
# Celle di tabella: separatore, non a capo, altrimenti una riga di tabella
# diventa illeggibile su piu' righe - ma senza separatore i valori si
# incollano fra loro ("Importo1.250,00").
_CELL_TAGS = frozenset({"td", "th"})
_INVISIBLE_RX = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad]")


class _TextExtractor(HTMLParser):
    """Estrattore di testo tollerante: l'HTML delle e-mail e' spesso malformato,
    quindi si usa il parser di libreria (che non solleva su tag non chiusi)
    invece di espressioni regolari."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in _DROP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        elif tag in _CELL_TAGS:
            self.parts.append("\t")

    def handle_startendtag(self, tag, attrs):
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _DROP_TAGS:
            self._skip = max(0, self._skip - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        elif tag in _CELL_TAGS:
            self.parts.append("\t")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def readable_text(raw: str) -> str:
    """Il contenuto del messaggio ridotto a testo che una persona legge.

    Toglie il markup (tag, entita', blocchi <style>/<script>) e normalizza la
    spaziatura, senza rimuovere niente di sostanziale: le catene di risposta e
    i messaggi inoltrati restano, perche' in un'analisi sono spesso la prova.
    Il contenuto integrale resta comunque in completeHeader.
    """
    if not raw:
        return ""
    text = raw
    if _HTML_HINT_RX.search(raw):
        parser = _TextExtractor()
        try:
            parser.feed(raw)
            parser.close()
            text = "".join(parser.parts)
        except Exception:
            # HTML irrecuperabile: meglio il testo grezzo che una colonna vuota.
            text = html.unescape(re.sub(r"<[^>]{0,4000}>", " ", raw))
    text = text.replace("\xa0", " ").replace("\r\n", "\n").replace("\r", "\n")
    text = _INVISIBLE_RX.sub("", text)
    text = re.sub(r"[ \x0b\f]+", " ", text)
    text = re.sub(r"[ \t]*\t[ \t]*", "\t", text)     # celle: un solo separatore
    text = re.sub(r"[ \t]*\n[ \t]*", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _attachment_names(msg: Message) -> list[str]:
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            cdisp = str(part.get("Content-Disposition") or "")
            fn = part.get_filename()
            if fn and ("attachment" in cdisp.lower() or part.get_content_maintype() != "text"):
                names.append(fn)
    return names


def _addresses(msg: Message, header: str) -> str:
    """Comma-separated e-mail ADDRESSES only (display names dropped)."""
    pairs = getaddresses(msg.get_all(header, []))
    return ", ".join(addr for _name, addr in pairs if addr)


def message_to_record(msg: Message, folder: str = "") -> dict:
    names = _attachment_names(msg)
    complete = _body(msg)
    return {
        "date": msg.get("Date", ""),
        "folder": folder,
        "from": _addresses(msg, "From"),
        "toRecipients": _addresses(msg, "To"),
        "ccRecipients": _addresses(msg, "Cc"),
        "bccRecipients": _addresses(msg, "Bcc"),
        "subject": msg.get("Subject", ""),
        "hasAttachments": "true" if names else "false",
        "attachmentNames": "; ".join(names),
        "completeHeader": complete,
        "body": readable_text(complete),
    }


def parse_mbox(mbox_path: Path, folder: str = "") -> Iterator[dict]:
    box = mailbox.mbox(str(mbox_path), factory=None, create=False)
    try:
        for msg in box:
            yield message_to_record(msg, folder=folder)
    finally:
        box.close()


def extract_records(pst_path: Path) -> list[dict]:
    """Extract every message of a .pst as a list of raw (un-anonymized) records."""
    if not readpst_available():
        raise RuntimeError(
            "readpst not found: install the 'pst-utils' package (Debian/Ubuntu: "
            "apt-get install -y pst-utils).")
    records: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        _run_readpst(Path(pst_path), out)
        extracted = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
        if extracted > MAX_EXTRACTED:
            raise PstExtractionError(
                f"l'archivio si espande a {extracted // (1024*1024)} MiB "
                f"(limite {MAX_EXTRACTED // (1024*1024)} MiB): file sospetto, "
                "non elaborato.")
        for path in sorted(out.rglob("*")):
            if not path.is_file():
                continue
            folder = str(path.parent.relative_to(out)) if path.parent != out else ""
            folder = (folder + "/" + path.name).strip("/")
            try:
                records.extend(parse_mbox(path, folder=folder))
            except Exception:
                continue   # not an mbox file (e.g. an extracted attachment)
    return records


def anonymize_records(records: list[dict], anon, scrub=None) -> list[dict]:
    """Anonymize the text fields of each record via the LogMask engine.

    v0.23.0: ``scrub`` permette di passare la stessa catena completa usata per
    i .docx (motore + sweep del vault + pseudonimizzazione dei residui), cosi'
    posta e documenti hanno la stessa copertura. Senza, si usa il solo motore.
    """
    scrub = scrub or anon.process
    out = []
    for rec in records:
        arec = {}
        for key in RECORD_FIELDS:
            val = rec.get(key, "")
            if key in TEXT_FIELDS and val:
                arec[key] = scrub(str(val))
            else:
                arec[key] = val
        out.append(arec)
    return out


def to_ndjson(records: list[dict]) -> str:
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in records)


def to_csv(records: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(RECORD_FIELDS),
                            extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for rec in records:
        writer.writerow(rec)
    return buf.getvalue()


def anonymize_pst(pst_path, anon, fmt: str = "ndjson", scrub=None) -> tuple[str, int]:
    """Extract, anonymize and serialize a .pst. Returns (output, message_count)."""
    records = anonymize_records(extract_records(Path(pst_path)), anon, scrub=scrub)
    body = to_csv(records) if fmt == "csv" else to_ndjson(records)
    return body, len(records)
