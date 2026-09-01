"""v0.22.0 — anonimizzazione di documenti .docx mantenendo il formato.

A differenza del PST, un .docx e' uno zip di XML: si puo' RISCRIVERE. Il file
restituito e' un .docx valido con stili, tabelle, intestazioni e numerazione
intatti; cambia solo il testo.

Il punto delicato e' che Word spezza il testo su piu' "run" in modo arbitrario
(un'aggiunta, un correttore, un cambio di formato): "mario.rossi" puo' essere
memorizzato come "mario" + ".rossi". Anonimizzare run per run lo mancherebbe -
un leak. Per questo ogni paragrafo viene trattato cosi':

  1. si anonimizza il testo COMPLETO del paragrafo (nessun valore sfugge);
  2. si anonimizza anche run per run e si confrontano i due risultati;
  3. se coincidono si scrive il per-run: la formattazione interna (grassetto su
     una parola sola, link, colori) resta esattamente com'era;
  4. se differiscono - cioe' un valore era spezzato fra run - si scrive il
     testo del paragrafo nel primo run e si svuotano gli altri. Si perde la
     formattazione DENTRO quel paragrafo, mai il mascheramento.

Vengono trattati anche intestazioni, pie' di pagina, note, commenti, caselle di
testo, i metadati del documento (autore, societa', ultimo salvataggio) e i nomi
autore delle revisioni: tutti posti dove finiscono nomi di persone.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import zipfile
from dataclasses import dataclass, field

# v0.24.1: tetto sul contenuto DECOMPRESSO. Il limite upload agisce sul file
# compresso: un .docx da 200 KB puo' espandersi a 200 MB in memoria (misurato:
# picco RSS 613 MB) e con il limite a 64 MB si arriva a decine di GB - un OOM
# del container confezionabile ad arte. Le dimensioni dichiarate nell'indice
# zip possono mentire, quindi si controlla due volte: prima la somma
# dichiarata, poi i byte realmente letti.
MAX_UNCOMPRESSED = int(os.environ.get("LOGMASK_DOCX_MAX_UNCOMPRESSED",
                                      str(256 * 1024 * 1024)))


class DocxTooLargeError(ValueError):
    """Il documento decompresso supera il tetto: probabile zip bomb."""


def _check_declared_sizes(zf: zipfile.ZipFile) -> None:
    declared = sum(i.file_size for i in zf.infolist())
    if declared > MAX_UNCOMPRESSED:
        raise DocxTooLargeError(
            f"il documento decompresso dichiara {declared // (1024*1024)} MiB "
            f"(limite {MAX_UNCOMPRESSED // (1024*1024)} MiB): file sospetto, "
            "non elaborato.")


def _read_member(zf: zipfile.ZipFile, item: zipfile.ZipInfo, budget: list) -> bytes:
    """Legge un membro rispettando il budget totale di byte decompressi."""
    with zf.open(item) as fh:
        payload = fh.read(budget[0] + 1)
    budget[0] -= len(payload)
    if budget[0] < 0:
        raise DocxTooLargeError(
            "il documento si espande oltre il limite consentito "
            f"({MAX_UNCOMPRESSED // (1024*1024)} MiB): probabile zip bomb, "
            "non elaborato.")
    return payload

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

# Parti del pacchetto che contengono testo visibile.
TEXT_PARTS_RX = re.compile(
    r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$")
# Metadati: autore, ultimo salvataggio, societa', manager.
CORE_PROPS = "docProps/core.xml"
APP_PROPS = "docProps/app.xml"

_CORE_PII_TAGS = ("creator", "lastModifiedBy", "lastPrinted")
_APP_PII_TAGS = ("Company", "Manager")


@dataclass
class DocxResult:
    data: bytes
    paragraphs: int = 0
    changed: int = 0
    tokens_in: int = 0          # pseudonimi presenti nell'input
    tokens_left: int = 0        # pseudonimi ancora presenti nell'output
    collapsed: int = 0          # paragrafi in cui si e' persa la formattazione interna
    parts: list = field(default_factory=list)
    metadata_scrubbed: int = 0
    warnings: list = field(default_factory=list)


def is_docx(data: bytes) -> bool:
    """Un .docx e' uno zip che contiene word/document.xml."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return "word/document.xml" in zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def _set_text(node, value: str) -> None:
    node.text = value
    # senza xml:space="preserve" Word mangia gli spazi iniziali/finali
    if value != value.strip():
        node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")


def _process_part(xml_bytes: bytes, scrub, result: DocxResult) -> bytes:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_bytes)
    for paragraph in root.iter(W + "p"):
        nodes = [t for t in paragraph.iter(W + "t")]
        if not nodes:
            continue
        result.paragraphs += 1
        originals = [n.text or "" for n in nodes]
        joined = "".join(originals)
        if not joined.strip():
            continue

        whole = scrub(joined)                       # 1) verita' di riferimento
        per_run = [scrub(t) if t.strip() else t for t in originals]
        if "".join(per_run) == whole:               # 3) formattazione preservata
            if per_run != originals:
                result.changed += 1
                for node, value in zip(nodes, per_run):
                    _set_text(node, value)
        else:                                       # 4) valore spezzato fra run
            result.changed += 1
            result.collapsed += 1
            _set_text(nodes[0], whole)
            for node in nodes[1:]:
                _set_text(node, "")

    # nomi autore di revisioni e commenti (w:author su w:ins/w:del/w:comment)
    for node in root.iter():
        author = node.get(W + "author")
        if author and author.strip():
            masked = scrub(author)
            if masked != author:
                node.set(W + "author", masked)
                result.metadata_scrubbed += 1

    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _process_props(xml_bytes: bytes, tags: tuple, scrub, result: DocxResult) -> bytes:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_bytes)
    for node in root.iter():
        local = node.tag.rsplit("}", 1)[-1]
        if local in tags and node.text and node.text.strip():
            masked = scrub(node.text)
            if masked != node.text:
                node.text = masked
                result.metadata_scrubbed += 1
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def count_pseudonyms(data: bytes) -> int:
    """Quanti token pseudonimo compaiono nel testo del documento.

    Serve a dire se un ripristino e' COMPLETO: "66 paragrafi ripristinati" da
    solo non distingue "erano solo 66 a contenere pseudonimi" da "ne sono
    rimasti indietro". Confrontando i token prima e dopo si ottiene la
    risposta.
    """
    import re as _re
    import xml.etree.ElementTree as ET

    # Solo le forme INCONFONDIBILI di pseudonimo. Le forme IP/MAC sono escluse
    # di proposito: un IP sintetico e' indistinguibile da un IP reale
    # ripristinato (10.0.0.1 e' sia una forma legacy sia un indirizzo vero),
    # quindi contarle darebbe "non risolti" fantasma su un restore riuscito.
    # v0.23.0: esclusi anche secret-* e CLIENT-*, irreversibili per scelta: non
    # sono "rimasti indietro", non torneranno MAI indietro. Contarli farebbe
    # apparire come incompleto ogni ripristino di un documento con credenziali.
    unmistakable = _re.compile(
        r"(?<![A-Za-z0-9])(?:usr-[a-z2-7]{4,10}|host-[a-z2-7]{4,10}|id-[a-z2-7]{8,16}"
        r"|(?:cf|iban|tel|person|addr|cloud)-[a-z2-7]{8,16}|DOM-[a-z2-7]{8})")
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        _check_declared_sizes(zf)
        budget = [MAX_UNCOMPRESSED]
        for item in zf.infolist():
            name = item.filename
            if not TEXT_PARTS_RX.match(name):
                continue
            try:
                root = ET.fromstring(_read_member(zf, item, budget))
            except DocxTooLargeError:
                raise
            except Exception:
                continue
            for paragraph in root.iter(W + "p"):
                joined = "".join((t.text or "") for t in paragraph.iter(W + "t"))
                total += len(unmistakable.findall(joined))
    return total


def deanonymize_docx(data: bytes, restore) -> DocxResult:
    """Ripristina un .docx anonimizzato restituendo un .docx.

    Speculare ad anonymize_docx: si sostituiscono gli pseudonimi con i valori
    originali dentro le stesse parti del pacchetto, quindi il documento
    ripristinato ha ancora stili, tabelle e indici al loro posto. Come
    nell'anonimizzazione il paragrafo viene ricomposto quando un token risulta
    spezzato fra run, cosi' nessuno pseudonimo resta indietro.
    """
    result = anonymize_docx(data, restore)
    result.tokens_in = count_pseudonyms(data)
    result.tokens_left = count_pseudonyms(result.data)
    return result


def anonymize_docx(data: bytes, scrub) -> DocxResult:
    """Restituisce un .docx anonimizzato, con la stessa struttura dell'originale.

    `scrub` e' la funzione di mascheramento (tipicamente Anonymizer.process
    seguita dai controlli Safe mode): riceve testo, restituisce testo.
    """
    result = DocxResult(data=b"")
    src = io.BytesIO(data)
    out = io.BytesIO()
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        names = zin.namelist()
        if "word/document.xml" not in names:
            raise ValueError("non e' un documento .docx valido")
        _check_declared_sizes(zin)
        budget = [MAX_UNCOMPRESSED]
        for item in zin.infolist():
            payload = _read_member(zin, item, budget)
            try:
                if TEXT_PARTS_RX.match(item.filename):
                    payload = _process_part(payload, scrub, result)
                    result.parts.append(item.filename)
                elif item.filename == CORE_PROPS:
                    payload = _process_props(payload, _CORE_PII_TAGS, scrub, result)
                elif item.filename == APP_PROPS:
                    payload = _process_props(payload, _APP_PII_TAGS, scrub, result)
            except Exception:                      # parte illeggibile: fail-closed
                if TEXT_PARTS_RX.match(item.filename):
                    raise
                result.warnings.append(
                    f"parte non elaborata (lasciata invariata): {item.filename}")
            zout.writestr(item, payload)

    embedded = [n for n in names
                if n.startswith(("word/media/", "word/embeddings/"))]
    if embedded:
        result.warnings.append(
            f"{len(embedded)} oggetti incorporati (immagini/allegati) non "
            "possono essere anonimizzati: verificarli a mano prima di condividere.")
    result.data = out.getvalue()
    return result
