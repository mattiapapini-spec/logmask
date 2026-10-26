"""v0.26.0 - anonimizzazione di documenti PDF.

Due modalita', perche' i due bisogni sono diversi:

  - "text": estrae il testo pagina per pagina e lo restituisce anonimizzato.
    Nessun rischio residuo, ripristino completo, si perde l'impaginazione.
  - "pdf": restituisce un PDF con pagine e posizioni al loro posto.

La modalita' "pdf" e' quella delicata. Coprire il testo con un rettangolo NON
lo rimuove: resta nel content stream e si recupera con un copia-incolla. E' la
fuga piu' classica dei documenti "redatti", e non e' teorica - ci sono finiti
tribunali e ministeri. Qui il testo originale viene eliminato davvero
(apply_redactions) e lo pseudonimo scritto al suo posto; alla fine il PDF
prodotto viene RILETTO e si verifica che nessun valore originale sia ancora
estraibile. Se lo fosse, l'operazione fallisce invece di consegnare un file che
sembra anonimizzato.

Vengono trattati anche i punti dove il testo si nasconde: metadati del
documento, XMP, titoli dei segnalibri, contenuto delle annotazioni e valori dei
campi modulo. Allegati incorporati e JavaScript non sono mascherabili e
vengono rimossi, perche' lasciarli passare vanificherebbe tutto il resto.
"""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field

try:
    import pymupdf                       # PyMuPDF >= 1.24
except ImportError:                      # pragma: no cover
    try:
        import fitz as pymupdf           # nome storico
    except ImportError:
        pymupdf = None

# Tetto sulle pagine: un PDF piccolo puo' dichiarare decine di migliaia di
# pagine e far esplodere memoria e tempo. Vedi docx_anon.MAX_UNCOMPRESSED.
MAX_PAGES = int(os.environ.get("LOGMASK_PDF_MAX_PAGES", "2000"))

_META_KEYS = ("title", "author", "subject", "keywords", "creator", "producer")


class PdfUnavailableError(RuntimeError):
    """PyMuPDF non installato: il supporto PDF non e' disponibile."""


class PdfLeakError(RuntimeError):
    """Il PDF prodotto conterrebbe ancora un valore in chiaro: si blocca."""


class PdfTooLargeError(ValueError):
    """Troppe pagine: file sospetto."""


class PdfUnreadableError(ValueError):
    """Il PDF e' cifrato, protetto da password o corrotto: non apribile."""


@dataclass
class PdfResult:
    data: bytes = b""
    text: str = ""
    pages: int = 0
    spans: int = 0
    changed: int = 0
    metadata_scrubbed: int = 0
    annotations: int = 0
    widgets: int = 0
    attachments_removed: int = 0
    image_only_pages: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def available() -> bool:
    return pymupdf is not None


def is_pdf(data: bytes) -> bool:
    return bool(data) and data[:5] == b"%PDF-"


def _require():
    if pymupdf is None:
        raise PdfUnavailableError(
            "Supporto PDF non disponibile: manca PyMuPDF nel container. "
            "Ricostruisci l'immagine con docker compose build --no-cache.")


def _open(data: bytes):
    _require()
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:                 # file non apribile come PDF
        raise PdfUnreadableError(
            "il file non e' un PDF leggibile: potrebbe essere corrotto o in un "
            "formato non supportato.") from exc
    # v0.26.2: un PDF protetto da password si apre ma needs_pass resta 1 finche'
    # non si autentica; senza la password il contenuto non e' accessibile e
    # ogni get_text tornerebbe vuoto - cioe' un documento "anonimizzato" che in
    # realta' non e' stato letto. Meglio dirlo che consegnare un file falso.
    if getattr(doc, "needs_pass", 0):
        doc.close()
        raise PdfUnreadableError(
            "il PDF e' protetto da password: rimuovi la protezione (aprilo e "
            "salvane una copia senza password) prima di anonimizzarlo.")
    pages = doc.page_count
    if pages > MAX_PAGES:
        doc.close()
        raise PdfTooLargeError(
            f"il documento dichiara {pages} pagine (limite {MAX_PAGES}): "
            "file sospetto, non elaborato.")
    return doc


def extract_text(data: bytes) -> list[str]:
    """Testo di ogni pagina, nell'ordine di lettura."""
    doc = _open(data)
    try:
        return [page.get_text() for page in doc]
    finally:
        doc.close()


def _spans(page) -> list[dict]:
    out = []
    for block in page.get_text("dict").get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                if span.get("text", "").strip():
                    out.append(span)
    return out


# Autore, oggetto e parole chiave di un PDF contengono un nome di persona per
# definizione, ma spesso come token isolato ("mrossi") - una forma che il
# motore non maschera nel testo libero, e giustamente: da sola sarebbe
# indistinguibile da una parola qualsiasi. Qui il contesto lo conosciamo, ed e'
# il campo stesso: si presenta il valore al motore con l'etichetta che gli
# compete, cosi' viene riconosciuto per quello che e'.
_META_IDENTITY_LABEL = {
    "author": "Account Name: ", "creator": "Account Name: ",
    "subject": "Account Name: ", "keywords": "Account Name: ",
}


def _scrub_metadata(doc, scrub, result: PdfResult) -> None:
    meta = doc.metadata or {}
    new = {}
    for key in _META_KEYS:
        value = meta.get(key)
        if value and value.strip():
            masked = scrub(value)
            label = _META_IDENTITY_LABEL.get(key)
            if label:
                # keywords e subject sono spesso elenchi separati da virgola:
                # ogni voce va presentata al motore per conto suo, altrimenti
                # solo la prima riceve l'etichetta e le altre restano intatte.
                parts, out = re.split(r"([,;]\s*)", masked), []
                for part in parts:
                    if not part or re.fullmatch(r"[,;]\s*", part):
                        out.append(part)
                        continue
                    labelled = scrub(label + part)
                    out.append(labelled[len(label):]
                               if labelled != label + part else part)
                masked = "".join(out)
            if masked != value:
                result.metadata_scrubbed += 1
            new[key] = masked
    doc.set_metadata(new)
    try:
        doc.del_xml_metadata()          # XMP: duplica autore, titolo, societa'
    except Exception:
        result.warnings.append("metadati XMP non rimossi: verificarli a mano.")


def _scrub_outline(doc, scrub) -> None:
    try:
        toc = doc.get_toc(simple=True)
    except Exception:
        return
    if not toc:
        return
    changed = [[lvl, scrub(title) if title else title, pno] for lvl, title, pno in toc]
    if changed != toc:
        try:
            doc.set_toc(changed)
        except Exception:
            pass


def _strip_payloads(doc, result: PdfResult) -> None:
    """Allegati e JavaScript non sono mascherabili: si tolgono."""
    try:
        names = doc.embfile_names()
    except Exception:
        names = []
    for name in list(names):
        try:
            doc.embfile_del(name)
            result.attachments_removed += 1
        except Exception:
            result.warnings.append(f"allegato non rimosso: {name}")
    if result.attachments_removed:
        result.warnings.append(
            f"{result.attachments_removed} allegati incorporati rimossi: il loro "
            "contenuto non e' mascherabile e sarebbe uscito in chiaro.")


def _rewrite_page(page, scrub, result: PdfResult) -> None:
    spans = _spans(page)
    result.spans += len(spans)
    if not spans:
        if page.get_images(full=True):
            result.image_only_pages.append(page.number + 1)
        return
    pending = []
    for span in spans:
        original = span["text"]
        masked = scrub(original)
        if masked == original:
            continue
        rect = pymupdf.Rect(span["bbox"])
        pending.append((rect, masked, float(span.get("size") or 10)))
        page.add_redact_annot(rect)
    if not pending:
        return
    page.apply_redactions()
    for rect, masked, size in pending:
        # Lo pseudonimo puo' essere piu' largo dell'originale: si allarga il
        # riquadro fino al margine e, se serve, si riduce il corpo. Meglio un
        # carattere piu' piccolo che un valore troncato.
        box = pymupdf.Rect(rect.x0, rect.y0 - 1,
                           min(page.rect.x1 - 4, max(rect.x1, rect.x0 + len(masked) * size * 0.62)),
                           rect.y1 + 2)
        fontsize = size
        while fontsize > 3:
            if page.insert_textbox(box, masked, fontsize=fontsize,
                                   fontname="helv", align=0) >= 0:
                break
            fontsize -= 0.5
        else:
            result.warnings.append(
                f"pagina {page.number + 1}: uno pseudonimo non e' entrato nello "
                "spazio del valore originale.")
        result.changed += 1


def _scrub_annotations(page, scrub, result: PdfResult) -> None:
    for annot in page.annots() or []:
        info = annot.info or {}
        new = dict(info)
        touched = False
        for key in ("content", "title", "subject"):
            value = info.get(key)
            if value and value.strip():
                masked = scrub(value)
                if masked != value:
                    new[key] = masked
                    touched = True
        if touched:
            try:
                annot.set_info(new)
                annot.update()
                result.annotations += 1
            except Exception:
                result.warnings.append(
                    f"pagina {page.number + 1}: annotazione non aggiornata.")
    for widget in page.widgets() or []:
        value = getattr(widget, "field_value", None)
        if isinstance(value, str) and value.strip():
            masked = scrub(value)
            if masked != value:
                try:
                    widget.field_value = masked
                    widget.update()
                    result.widgets += 1
                except Exception:
                    result.warnings.append(
                        f"pagina {page.number + 1}: campo modulo non aggiornato.")


def anonymize_pdf(data: bytes, scrub) -> PdfResult:
    """PDF -> PDF: il testo originale viene RIMOSSO e sostituito sul posto."""
    result = PdfResult()
    doc = _open(data)
    try:
        result.pages = doc.page_count
        originals = [page.get_text() for page in doc]
        _strip_payloads(doc, result)
        for page in doc:
            _scrub_annotations(page, scrub, result)
            _rewrite_page(page, scrub, result)
        # Dopo le pagine, non prima: a questo punto il vault conosce gia' i
        # valori del documento, quindi un autore che compare anche nel testo
        # riceve lo STESSO pseudonimo invece di uno slegato.
        _scrub_metadata(doc, scrub, result)
        _scrub_outline(doc, scrub)
        out = io.BytesIO()
        doc.save(out, garbage=4, deflate=True, clean=True)
        result.data = out.getvalue()
    finally:
        doc.close()
    if result.image_only_pages:
        result.warnings.append(
            f"{len(result.image_only_pages)} pagine senza testo (probabile "
            f"scansione): {result.image_only_pages[:10]}. Il loro contenuto NON "
            "e' stato analizzato ne' mascherato - verificarle a mano prima di "
            "condividere il documento.")
    _verify(result.data, originals, scrub)
    return result


def deanonymize_pdf(data: bytes, restore) -> PdfResult:
    """PDF -> PDF: gli pseudonimi tornano ai valori originali.

    Stessa meccanica dell'anonimizzazione, con la funzione inversa. Le
    posizioni restano quelle del documento anonimizzato: il file e' leggibile e
    completo, non identico all'originale di partenza.
    """
    result = PdfResult()
    doc = _open(data)
    try:
        result.pages = doc.page_count
        _scrub_metadata(doc, restore, result)
        _scrub_outline(doc, restore)
        for page in doc:
            _scrub_annotations(page, restore, result)
            _rewrite_page(page, restore, result)
        out = io.BytesIO()
        doc.save(out, garbage=4, deflate=True, clean=True)
        result.data = out.getvalue()
    finally:
        doc.close()
    return result


def _verify(data: bytes, originals: list[str], scrub) -> None:
    """Rilegge il PDF prodotto e controlla che i valori spariti dal testo
    mascherato non siano rimasti nel file.

    Il confronto avviene sulla PAGINA intera, non sui singoli frammenti: un
    valore puo' essere spezzato fra due span e sfuggire alla sostituzione, e un
    controllo fatto sugli stessi frammenti userebbe la stessa vista limitata
    che ha causato l'errore - non lo vedrebbe mai. Confrontando "cosa sarebbe
    dovuto sparire dalla pagina" con "cosa e' ancora estraibile dal file" il
    controllo resta indipendente da come e' avvenuta la sostituzione.
    """
    produced_parts = list(extract_text(data))
    # v0.26.2: get_text NON estrae il contenuto di annotazioni e campi modulo.
    # Se _scrub_annotations avesse mancato qualcosa, il controllo sul solo
    # testo di pagina non se ne accorgerebbe. Qui si aggiunge quel contenuto,
    # cosi' la verifica copre ogni superficie che puo' portare testo.
    doc = _open(data)
    try:
        for page in doc:
            for annot in page.annots() or []:
                info = annot.info or {}
                produced_parts.extend(str(info.get(k, "")) for k in
                                      ("content", "title", "subject"))
            for widget in page.widgets() or []:
                value = getattr(widget, "field_value", None)
                if isinstance(value, str):
                    produced_parts.append(value)
    finally:
        doc.close()
    produced = "\n".join(produced_parts)
    leaked: list[str] = []
    for page_text in originals:
        if not page_text.strip():
            continue
        masked_page = scrub(page_text)
        for token in set(re.findall(r"[^\s]{4,}", page_text)):
            if token in masked_page:
                continue                 # non doveva sparire
            if token in produced:
                leaked.append(token)
                if len(leaked) >= 5:
                    break
        if leaked:
            break
    if leaked:
        raise PdfLeakError(
            f"il PDF prodotto conterrebbe ancora {len(leaked)} valori in "
            "chiaro che dovevano essere mascherati: operazione annullata "
            "invece di consegnare un file che sembra anonimizzato.")


PDF_PSEUDO_RX = re.compile(
    r"(?<![A-Za-z0-9])(?:usr-[a-z2-7]{4,10}|host-[a-z2-7]{4,10}|id-[a-z2-7]{8,16}"
    r"|(?:cf|iban|tel|person|addr|cloud|vat)-[a-z2-7]{8,16}|DOM-[a-z2-7]{8})")


def count_pseudonyms(data: bytes) -> int:
    """Quanti pseudonimi risolvibili compaiono nel testo del PDF."""
    return sum(len(PDF_PSEUDO_RX.findall(page)) for page in extract_text(data))
