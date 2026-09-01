# LogMask

**Reversible, fail-closed pseudonymization of SOC logs** — self-hosted, per-tenant, audit-ready.

*Pseudonimizzazione reversibile e fail-closed di log SOC.* Versione corrente: vedi [`VERSION`](VERSION) e [`CHANGELOG.md`](CHANGELOG.md). Documentazione completa (EN/IT): [`docs/`](docs/).

Pseudonimizzazione reversibile e fail-closed di log SOC tramite interfaccia web e CLI. Il servizio supporta isolamento per tenant, autenticazione/RBAC, upload e download, parser strutturati, kit vendor versionati e policy DLP/PII.

> LogMask esegue **pseudonimizzazione**, non anonimizzazione definitiva: chi possiede chiave e vault del tenant può ricostruire i valori pseudonimizzati. I valori elisi con `[ELIDED]` sono invece volutamente irreversibili.

## Novità 0.10.4 — Elastic/Kibana wrapper + Trend nested kit

Questa release migliora gli alert Elastic/Kibana che contengono payload Trend Micro Vision One annidati.

- normalizza i prefissi `_source.`, `fields.`, `signal.*` e `kibana.alert.original_*`;
- applica il kit Trend ai rami `trend_micro_vision_one.alert.*` anche quando il contenitore esterno è ECS;
- maschera `account_value`, `created_by`, `updated_by`, ID Workbench/incident/filter/model e `ref=` negli URL;
- mantiene leggibili metadati SOC operativi come `event.dataset`, `event.module`, `data_stream.*`, `threat.technique.id`, `schema_version`, `status`, `input.type`, `agent.type`, `url.scheme`;
- riduce le elisioni inutili negli alert Elastic/Trend senza disattivare il fail-closed.

## Novità 0.10.2 — IPv4 sintetici non collidenti

Gli IPv4 pseudonimizzati non usano più range realistici del cliente come `10.0.0.0/8` o `100.64.0.0/10`.
La nuova generazione usa il blocco benchmark `198.18.0.0/15`:

- `198.18.x.y` per IP interni, quando `keep_scope` è attivo;
- `198.19.x.y` per IP pubblici/esterni;
- il reverse resta compatibile con i vecchi pseudonimi `10.x.x.x` e `100.x.x.x` già presenti nei vault.

## Novità 0.10.1 — Multi-file per sessione

L'interfaccia supporta il caricamento di più file nella stessa sessione browser per entrambi i flussi:

- **Anonimizza**: ogni file viene processato singolarmente con tenant, policy IP, kit vendor e policy DLP correnti;
- **Ripristina**: ogni file pseudonimizzato viene risolto singolarmente con il vault del tenant selezionato;
- i file restano in memoria lato browser; il backend riceve solo il contenuto del file in elaborazione;
- il nome completo del file non viene scritto nel vault e non viene inviato nell'audit operativo;
- i risultati conformi sono scaricabili in un unico ZIP generato localmente nel browser;
- i file bloccati dal controllo fail-closed o in errore sono esclusi dallo ZIP e restano indicati nel report della sessione.

Per lavorare su batch grandi, lascia attivo Safe mode e controlla sempre la tabella di stato prima di usare lo ZIP.

## Novità 0.8.0 — DLP e PII avanzata

Il nuovo motore DLP opera su testo libero, CSV/TSV, JSON, NDJSON, CEF, LEEF e Syslog. Viene eseguito anche sui campi che un kit vendor classifica come operativi.

Categorie incluse:

- password, secret, API key, OAuth token, bearer/basic auth, JWT e cookie;
- chiavi private e materiale PEM;
- codice fiscale italiano validato;
- IBAN validato MOD-97;
- telefoni, nominativi e indirizzi con contesto esplicito;
- UUID/GUID, Azure Resource ID, AWS ARN e account ID;
- parametri sensibili nelle query string.

Ogni categoria può essere configurata su:

- `pseudonymize`: reversibile tramite vault;
- `redact`: `[ELIDED]`, irreversibile;
- `block`: blocca copia e download;
- `keep`: mantenimento intenzionale.

Per impostazione predefinita, credenziali, token, URL sensibili e materiale PEM vengono **elisi**, mentre PII e identificativi cloud vengono **pseudonimizzati**.

Dettagli: [`docs/DLP_POLICY.md`](docs/DLP_POLICY.md). Esempi: `examples/dlp/`.

## Kit vendor 0.7

Sono inclusi dieci kit:

- Palo Alto Cortex XDR / XSIAM / XSOAR;
- Microsoft Defender XDR / Entra ID / M365;
- Trend Micro Vision One / Apex One;
- Elastic Common Schema;
- Fortinet FortiGate / FortiEDR;
- SentinelOne Singularity;
- Sophos Central / XDR;
- Cisco Secure Endpoint / SecureX;
- Darktrace / Exabeam;
- Acronis Cyber Protect / EDR.

Ogni elaborazione mostra kit rilevato, confidenza, copertura, campi fuori catalogo, valori elisi e trasformazioni fallite. Un kit non disattiva mai il fail-closed.

Dettagli: [`docs/VENDOR_KITS.md`](docs/VENDOR_KITS.md). Esempi: `examples/vendors/`.

## Documenti .docx

Un .docx caricato viene restituito come .docx anonimizzato, con struttura e
stili intatti. Se un valore da mascherare risulta spezzato su piu' porzioni di
testo (Word lo fa spesso), quel paragrafo viene ricomposto: si perde la
formattazione interna a quel paragrafo, mai il mascheramento. Vengono trattati
anche note, commenti, metadati (autore, societa') e nomi autore delle
revisioni. Immagini e oggetti incorporati non sono anonimizzabili: viene
mostrato un avviso.

## Formati supportati

| Formato | Auto-detect | Multi-record | Reverse strutturato |
|---|---:|---:|---:|
| Testo libero | sì | n/d | sì |
| CSV/TSV | sì | sì | sì |
| JSON | sì | oggetti/array | sì |
| NDJSON | sì | sì | sì |
| CEF | sì | sì | sì |
| LEEF | sì | sì | sì |
| Syslog `key=value` | sì | sì | sì |

JSON e NDJSON vengono attraversati ricorsivamente. CEF e LEEF preservano header, delimitatori ed escaping. Syslog richiede una sequenza completa di coppie `key=value`.

## Policy IP

- `all`: anonimizza IP interni e pubblici;
- `internal`: anonimizza soltanto RFC1918, loopback, link-local e IPv6 ULA/link-local;
- `none`: mantiene tutti gli IP.

La policy vale per tutti i formati supportati. Quando un IP viene pseudonimizzato, l'output usa il blocco benchmark `198.18.0.0/15`, non indirizzi che possono sembrare appartenere alla rete reale del cliente.


## Workflow SOC

La v0.10.x include profili operativi per il lavoro SOC:

- Ticket cliente;
- Analisi AI esterna;
- Threat hunting interno;
- Report / allegato.

Ogni profilo applica preset a formato, Safe mode, policy IP e DLP. L'interfaccia permette anche di generare template operativi, confrontare originale e anonimizzato, approvare campi ambigui in sessione e consultare l'archivio temporaneo della sessione browser.

Dettagli: `docs/WORKFLOW_SOC.md`.

## Avvio

```powershell
docker compose up -d --build
docker compose logs --tail 100 logmask
```

Accesso:

```text
http://127.0.0.1:8090
http://IP_PRIVATO_DEL_PC:8090
```

Per limitare l'ascolto a localhost:

```powershell
$env:LOGMASK_BIND = "127.0.0.1"
docker compose up -d
```

## Primo accesso

Se `LOGMASK_ADMIN_PASSWORD` non è impostata:

```powershell
Get-Content .\data\bootstrap-admin.txt
```

Accedi come `admin` e cambia la password. Il file di bootstrap viene eliminato automaticamente.

## Utilizzo web

1. Seleziona tenant e formato.
2. Incolla il log oppure usa **Carica file** / drag & drop.
3. Lascia il kit vendor in auto-detect oppure forza il prodotto corretto.
4. Seleziona la policy IP.
5. Apri **Policy DLP / PII avanzata** per controllare le azioni per categoria.
6. Mantieni Safe mode attivo.
7. Esegui l'anonimizzazione.
8. Copia o scarica il risultato soltanto quando la verifica è `OK`.

Il caricamento viene letto nel browser e inviato al backend solo al momento dell'elaborazione. Sono supportati UTF-8, UTF-16LE/BE con BOM e fallback Windows-1252. Limite predefinito: 8 MiB.

## CLI

Policy predefinita:

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant acme --format auto --safe --ip-mode internal input.json -o output.json
```

Override DLP:

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant acme --safe --dlp private_key=block --dlp iban=pseudonymize `
  input.log -o output.log
```

Policy da file:

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant acme --safe --dlp-policy .\examples\dlp\policy.json `
  input.log -o output.log
```

Reverse:

```powershell
python logmask.py --key data/master.key --vault data/vault.db deanonymize `
  --tenant acme --format auto output.json -o restored.json
```

## Ruoli

| Ruolo | Anonimizza | Report | Reverse | Utenti/audit |
|---|---:|---:|---:|---:|
| `operator` | sì | no | no | no |
| `analyst` | sì | sì | no | no |
| `reverser` | sì | sì | sì | no |
| `admin` | sì | sì | sì | sì |

Gli utenti non amministratori operano soltanto sui tenant assegnati.

## Dati e multi-tenant

- vault tenant: `data/tenants/<tenant>/vault.db`;
- vault precedente: tenant `legacy`, `data/vault.db`;
- autenticazione e audit: `data/auth.db`;
- master key: `data/master.key`.

Lo stesso dato genera pseudonimi differenti tra tenant. I secret con policy `redact` non vengono inseriti nel vault.

### Nomi di persona

Dalle liste generiche (`persons/` di serie, piu' `data/persons/`) viene
mascherata **solo la coppia "Nome Cognome"** adiacente e capitalizzata: un
token singolo non basta, perche' cognomi come Costa/Monti/Riva e nomi
internazionali come Will/May/Mark/June sono anche parole comuni dei log, e
mascherarli isolati distruggerebbe verbi, date e brand (es. "Chase Bank" in un
alert di phishing). Le liste di serie sono una BASE ridotta: per estenderle
metti i file in `data/persons/`: vengono riconosciuti per PREFISSO del nome
(`nomi*`, `first_names*`, `names*`, `given*` come nomi; `cognomi*`,
`last_names*`, `surname*` come cognomi), quindi puoi tenere il nome
originale del file scaricato. Tutti i file vengono UNITI, non sostituiti.
Le righe non valide (disclaimer, markup, alfabeti non latini, binario in
coda ai file scaricati dalla pagina invece che dal raw) sono scartate.

Formati riconosciuti: `Mario Rossi`, `mario rossi`, `mario.rossi`,
`mario_rossi`, `mario-rossi` e gli ordini invertiti. Non viene toccato cio' che
sta dentro un'e-mail, un FQDN o un percorso.

Per mascherare anche un **cognome da solo** serve `data/person_terms.txt`: sono
le persone realmente esistenti in quel cliente (popolabile dall'export
AD/Entra), quindi la precisione e' massima e non dipende dalla lingua.

### Config runtime in `data/` (mai nel repo)

Quattro file opzionali, ricaricati a caldo, uno per riga con commenti `#`:
`client_terms.txt` (nomi cliente, sempre mascherati), `host_terms.txt`
(convenzioni hostname, wildcard `*`), `tenant_networks.txt` (CIDR del cliente),
`keep_fields.txt` (colonne extra in chiaro in Safe mode). Template fittizi in
`examples/data/*.txt.example`: copiali in `data/` e personalizzali. La cartella
`data/` e' in `.gitignore` (contiene master key, vault e nomi reali): non va
mai committata ne' inclusa in una release.

## Aggiornamento dalla 0.7

```powershell
Copy-Item .\data ..\logmask-data-backup-v07 -Recurse
docker compose down
```

Sostituisci i file applicativi, conserva `data`, quindi:

```powershell
docker compose up -d --build
docker compose logs --tail 100 logmask
```

Non sono previste migrazioni distruttive del vault.

## Limiti attuali

- il riconoscimento di nomi, telefoni e indirizzi richiede un campo o una label esplicita per contenere i falsi positivi;
- un secret non etichettato e senza forma riconoscibile può non essere rilevato;
- i vendor possono aggiungere o rinominare campi: verificare sempre il report;
- JSON viene riserializzato e la spaziatura può cambiare;
- RFC5424 Structured Data non ha ancora un parser dedicato;
- il caricamento web legge il file interamente in memoria: servono circa
  64 MB fissi piu' ~12,7 MB per ogni MB di input (un upload da 64 MiB richiede
  ~900 MB di RAM e ~90 s); per export grandi usare la sessione multi-file o la CLI;
- master key e vault sono ancora nello stesso volume e il container gira come root: l'hardening 0.5 resta da implementare.
- i PST vengono estratti e anonimizzati in NDJSON/CSV: la riscrittura di un .pst non e' supportata;
- le regole kit utente (data/kits/) hanno priorita': un `action: keep` errato espone il campo — rivedere sempre i TODO delle proposte;
- il progetto non ha ricevuto un audit di sicurezza indipendente: vedere SECURITY.md e rivedere l'output prima di condividerlo.

## Test

```powershell
$env:PYTHONPATH = "."
pytest -q
```

La suite copre autenticazione, RBAC, CSRF, multi-tenant, fail-closed, policy IP, parser strutturati, upload/download, vendor kit e policy DLP/PII.


## v0.10.4 - Valutazione campi

Il workflow **Valutazione campi** genera un template operativo per audit della qualità di anonimizzazione. Non chiede FP/TP: valuta campi sensibili residui, elisioni eccessive, pseudonimizzazioni errate e tuning del kit.

La release riduce inoltre la pseudonimizzazione aggressiva nei testi descrittivi e tratta i valori `WB-*` come identificativi opachi reversibili.

## Licenza e sicurezza

**Licenza: GNU AGPL-3.0** (vedi `LICENSE`) — © 2026 Mattia Papini. In breve:
uso, studio e modifica liberi; chi distribuisce LogMask o lo offre come
servizio in rete (anche modificato) deve rendere disponibile il proprio
sorgente agli utenti, alle stesse condizioni.

**Dual licensing / uso commerciale.** Se vuoi integrare LogMask in un prodotto
o servizio senza gli obblighi dell'AGPL (cioe' senza pubblicare il tuo
sorgente), e' disponibile una licenza commerciale separata: contatta l'autore
a `mattia.papini@gmail.com`. La dipendenza PDF (PyMuPDF) e' anch'essa AGPL,
quindi il licenziamento commerciale del modulo PDF richiede in aggiunta una
licenza Artifex; il supporto PDF e' opzionale e l'applicazione funziona senza.

Threat model, limiti di protezione e canale per segnalare vulnerabilita' in
`SECURITY.md`.
