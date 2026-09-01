# LogMask — Documentazione tecnica

**Versione 0.27.6** · Pseudonimizzazione reversibile e fail-closed di log SOC, self-hosted

---

## Indice

1. [Cos'è LogMask](#1-cosè-logmask)
2. [Concetti fondamentali](#2-concetti-fondamentali)
3. [Architettura](#3-architettura)
4. [Installazione e deployment](#4-installazione-e-deployment)
5. [Configurazione](#5-configurazione)
6. [Guida all'uso](#6-guida-alluso)
7. [Formati supportati](#7-formati-supportati)
8. [Il motore di pseudonimizzazione](#8-il-motore-di-pseudonimizzazione)
9. [Riferimento delle forme dei token](#9-riferimento-delle-forme-dei-token)
10. [Kit vendor](#10-kit-vendor)
11. [Categorie DLP e Safe mode](#11-categorie-dlp-e-safe-mode)
12. [Riferimento API](#12-riferimento-api)
13. [Modello di sicurezza](#13-modello-di-sicurezza)
14. [Operazioni e risoluzione problemi](#14-operazioni-e-risoluzione-problemi)
15. [Considerazioni normative (UE / Italia, uso dell'AI)](#15-considerazioni-normative-ue--italia-uso-dellai)
16. [Estendere LogMask](#16-estendere-logmask)

---

## 1. Cos'è LogMask

LogMask è uno strumento self-hosted, con interfaccia web e CLI, che **pseudonimizza i log di sicurezza** così che possano essere condivisi — con un analista esterno, il supporto di un vendor o un assistente AI — senza rivelare i dati che identificano il cliente, preservando al tempo stesso il valore analitico e forense del log.

L'obiettivo di progetto è specifico e asimmetrico: **non far mai trapelare dati che identificano il cliente, anche a costo della leggibilità**, mantenendo intatti gli indicatori di compromissione (hash, GUID, URL, nomi di file, porte, event code) perché il log resti utile all'indagine.

Due proprietà lo rendono praticabile:

- **Reversibile per costruzione.** Il mascheramento è deterministico e reversibile sul tenant che l'ha prodotto: lo stesso valore diventa sempre lo stesso pseudonimo, e chi possiede il vault e la chiave del tenant può ripristinare l'originale. Questo permette a un analista di correlare gli eventi in un export condiviso e, in seguito, di risalire da un riscontro all'host o all'utente reale.
- **Fail-closed.** Quando LogMask non riesce a classificare con sicurezza un campo, non lo lascia passare in chiaro. In Safe mode il campo viene eliso; il testo libero non classificato che potrebbe contenere un'identità viene mascherato come testo invece che tenuto. La postura predefinita è proteggere, non esporre.

> **Pseudonimizzazione, non anonimizzazione.** LogMask esegue *pseudonimizzazione*, reversibile da chi possiede chiave e vault del tenant. **Non** è anonimizzazione irreversibile. Un sottoinsieme di trasformazioni è volutamente irreversibile — i nomi cliente (`CLIENT-…`), i segreti (`secret-…`) e i campi elisi (`[ELIDED]`) non vengono mai memorizzati e non sono recuperabili. Le conseguenze giuridiche di questa distinzione sono trattate nel [§15](#15-considerazioni-normative-ue--italia-uso-dellai).

---

## 2. Concetti fondamentali

**Tenant.** Ogni operazione avviene nel contesto di un tenant (un cliente). Ogni tenant ha il proprio vault, le proprie chiavi derivate e il proprio ambito di autorizzazione. Due tenant non condividono mai gli pseudonimi: lo stesso nome host mascherato per il tenant A e per il tenant B produce due token diversi e slegati.

**Vault.** Un database SQLite per tenant che conserva la corrispondenza tra un valore reale e il suo pseudonimo. I valori originali sono conservati **cifrati** (AES-GCM, un nonce casuale per riga). Il vault è l'unica cosa che rende reversibile un export mascherato; perderlo significa perdere per sempre la capacità di ripristinare.

**Pseudonimo / token.** Il valore sintetico che sostituisce quello reale, es. `usr-4ozopszr` per un utente o `host-ri6jxfsb.masked.local` per un host. Le forme dei token sono nel [§9](#9-riferimento-delle-forme-dei-token).

**Kind (tipo).** La categoria di un valore — user, email, fqdn, ipv4, windomain, iban e così via. Il tipo determina la forma del token e se il valore è reversibile.

**Kit vendor.** Un insieme di regole YAML che mappa i nomi campo di un prodotto specifico a tipi e azioni (mask / keep / text / drop). I kit sono ciò che permette a LogMask di classificare un export Cortex XDR diversamente da uno Elastic ECS. Vedi [§10](#10-kit-vendor).

**Safe mode.** Un interruttore fail-closed: qualsiasi campo che nessun kit e nessuna euristica ha saputo classificare viene eliso (`[ELIDED]`) invece di passare in chiaro. Vedi [§11](#11-categorie-dlp-e-safe-mode).

**Azione.** Cosa accade a un campo: `mask` (pseudonimo reversibile), `keep` (lasciato com'è — per metadati operativi e IOC), `text` (scrubbing di testo libero, per messaggi e descrizioni), `drop` (rimosso).

---

## 3. Architettura

LogMask è un singolo container che esegue un'applicazione FastAPI, la quale serve sia l'API JSON sia l'interfaccia web a pagina singola.

```
┌──────────────────────────────────────────────────────────┐
│  Browser (app a pagina singola, JS vanilla)                │
│   • pannelli anonimizza / ripristina   • kit studio        │
│   • card docx / pst / pdf   • amministrazione (utenti, audit)│
└───────────────┬────────────────────────────────────────────┘
                │ HTTPS (sessione cookie + CSRF double-submit)
┌───────────────▼────────────────────────────────────────────┐
│  App FastAPI (app.py)                                       │
│   • auth / RBAC (auth.py)         • endpoint                │
│   • middleware dimensione richiesta + sicurezza            │
├─────────────────────────────────────────────────────────────┤
│  Motore (logmask.py)              Strutturati (structured.py)│
│   • master regex, builder per      • parser JSON / NDJSON /  │
│     tipo, guardie                    CEF / LEEF / syslog     │
│   • scansione DLP (dlp.py)        Kit vendor (vendor_kits)   │
│   • CSV / testo / sweep identità  Documenti:                │
│                                     docx_anon / pst_anon /   │
│                                     pdf_anon                 │
├─────────────────────────────────────────────────────────────┤
│  Vault per tenant (SQLite, AES-GCM)   Chiave master (0600)   │
└─────────────────────────────────────────────────────────────┘
```

**Componenti principali:**

- `app.py` — endpoint HTTP, dipendenza di autenticazione, middleware per dimensione della richiesta e header di sicurezza, gestione degli upload.
- `auth.py` — archivio utenti, hashing password Argon2, gestione sessioni e token CSRF, RBAC, rate limiting sul login, log di audit.
- `logmask.py` — il motore di pseudonimizzazione: la master regex, i builder di pseudonimi per tipo, tutte le guardie di correttezza (IOC, blob opaco, host-originale, nomi di persona, P.IVA/indirizzi, identità nel testo), il motore CSV e lo sweep dei valori noti al vault.
- `structured.py` — rilevamento del formato e parser strutturati (JSON, NDJSON, CEF, LEEF, syslog).
- `dlp.py` — il catalogo delle categorie DLP e lo scanner dei residui sensibili (credenziali, IBAN, codice fiscale, telefono, P.IVA, indirizzo, id cloud, parametri URL sensibili).
- `vendor_kits.py` — caricamento kit, validazione, hot reload e rilevamento vendor.
- `docx_anon.py`, `pst_anon.py`, `pdf_anon.py` — gestori documentali per Word, archivi Outlook e PDF.
- `workflows.py` — i "profili di lavoro" preimpostati (ticket, analisi AI, threat hunting, report, qualità campi).

**Dati a riposo:** ogni vault di tenant è un file SQLite cifrato nella cartella dati; la chiave master è una chiave casuale di 32 byte con permessi `0600`, usata per derivare le chiavi per tenant tramite HMAC.

---

## 4. Installazione e deployment

### Requisiti

- Docker e Docker Compose.
- Nessun servizio esterno: il vault è SQLite locale; non c'è un server di database, un broker di messaggi o una dipendenza cloud.

### Avvio rapido

```bash
# dalla cartella del progetto
docker compose build --no-cache
docker compose up -d
```

Al primo avvio, se non è configurata alcuna password admin, una password di bootstrap casuale viene scritta in `./data/bootstrap-admin.txt`. Accedi come `admin` con quella password; ti sarà richiesto di cambiarla prima di ogni altra operazione.

L'interfaccia è poi raggiungibile su `http://<host>:8090/`.

### PowerShell (Windows)

```powershell
cd "$env:USERPROFILE\Claude\Projects\logmask-web-v0.10.4"
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Esposizione di rete

Per impostazione predefinita il container si lega a `0.0.0.0`, cioè è raggiungibile da tutta la LAN. Per un deployment su singola postazione, accessibile solo dall'host, imposta:

```
LOGMASK_BIND=127.0.0.1
```

nel file `.env`. Per uno strumento che tratta log di clienti vale la pena deciderlo consapevolmente; vedi [§13](#13-modello-di-sicurezza).

### Porte

Il file compose mappa `${LOGMASK_PORT:-8090}:8080` — l'app ascolta su `8080` dentro il container, pubblicata di default su `8090` sull'host.

### Supporto PDF e licenza

La gestione dei PDF usa **PyMuPDF**, distribuito con licenza **AGPL-3.0** — la stessa con cui è rilasciato LogMask, quindi l'opera combinata è coerente sul piano delle licenze. La pubblicazione del sorgente di LogMask soddisfa per costruzione l'obbligo AGPL di disponibilità del sorgente. Per il licenziamento commerciale di LogMask senza obblighi AGPL vedi il README (per il modulo PDF opzionale serve in aggiunta una licenza commerciale PyMuPDF da Artifex).

---

## 5. Configurazione

La configurazione avviene interamente tramite variabili d'ambiente (tipicamente nel `.env`) e file dati opzionali nella cartella dati. Nulla va scritto nel codice.

### Variabili d'ambiente

| Variabile | Default | Scopo |
|---|---|---|
| `LOGMASK_DATA` | `/data` | Cartella dati (vault, chiave, file di config) |
| `LOGMASK_BIND` | `0.0.0.0` | Indirizzo di bind; `127.0.0.1` per solo host |
| `LOGMASK_PORT` | `8090` | Porta pubblicata sull'host |
| `LOGMASK_ADMIN_USER` | `admin` | Username admin di bootstrap |
| `LOGMASK_ADMIN_PASSWORD` | *(casuale)* | Password admin di bootstrap; se vuota, scritta in `data/bootstrap-admin.txt` |
| `LOGMASK_KEY_FILE` | `data/master.key` | Posizione chiave master (32 byte, `0600`) |
| `LOGMASK_COOKIE_SECURE` | `false` | `true` dietro HTTPS per marcare i cookie Secure |
| `LOGMASK_SESSION_IDLE_SECONDS` | `1800` | Timeout sessione inattiva |
| `LOGMASK_SESSION_MAX_SECONDS` | `28800` | Durata massima assoluta della sessione |
| `LOGMASK_LOGIN_MAX_FAILURES` | `5` | Login falliti prima del blocco |
| `LOGMASK_LOGIN_WINDOW_SECONDS` | `900` | Finestra di blocco |
| `LOGMASK_MAX_BODY_BYTES` | `12582912` | Corpo massimo della richiesta |
| `LOGMASK_MAX_FILE_BYTES` | `8388608` | Dimensione massima file caricato |
| `LOGMASK_CLIENT_TERMS` / `_FILE` | — | Nomi cliente da mascherare/scrubbare (inline o file) |
| `LOGMASK_CLIENT_TERM_MODE` | `pseudonymize` | `pseudonymize` \| `elide` \| `label` |
| `LOGMASK_CLIENT_TERM_LABEL` | `[CLIENTE]` | Etichetta usata quando la modalità è `label` |
| `LOGMASK_HOST_TERMS` / `_FILE` | — | Glob di nomi host di proprietà del tenant |
| `LOGMASK_TENANT_NETWORKS` / `_FILE` | — | CIDR pubblici che identificano il cliente |
| `LOGMASK_PERSON_TERMS` / `_FILE` | — | Nomi di persone realmente presenti nel tenant |
| `LOGMASK_KEEP_FIELDS` / `_FILE` | — | Nomi campo da forzare a `keep` |
| `LOGMASK_DOCX_MAX_UNCOMPRESSED` | `268435456` | Tetto sul decompresso .docx (guardia zip-bomb) |
| `LOGMASK_PST_MAX_EXTRACTED` | `1073741824` | Tetto sull'estratto .pst |
| `LOGMASK_READPST_TIMEOUT` | `300` | Timeout (s) del sottoprocesso readpst |
| `LOGMASK_PDF_MAX_PAGES` | `2000` | Tetto sul numero di pagine PDF |

Il tipico `.env` di produzione alza i limiti di upload per gli export XQL/Discover grandi, es. `LOGMASK_MAX_FILE_BYTES=67108864` e `LOGMASK_MAX_BODY_BYTES=100663296`.

### File dati

Stanno nella cartella dati e sono ricaricati a caldo dove indicato. Nessuno di essi contiene nomi cliente reali nel repository — il repository include solo file `.example`.

| File | Scopo |
|---|---|
| `data/client_terms.txt` | Nomi cliente da scrubbare/mascherare; uno per riga |
| `data/host_terms.txt` | Glob di nomi host di proprietà del tenant (es. `WKS*`, `*DC*`) |
| `data/tenant_networks.txt` | CIDR pubblici che identificano il cliente |
| `data/person_terms.txt` | Nomi di dipendenti reali presenti nel tenant |
| `data/keep_fields.txt` | Nomi campo da tenere sempre leggibili |
| `data/persons/` | Liste di nomi e cognomi per il rilevamento generico di persone |
| `data/kits/*.yaml` | Kit vendor utente (estendono o sostituiscono quelli di serie; hot reload) |

> **Igiene dei segreti.** `client_terms.txt` e `person_terms.txt` contengono per natura valori reali e identificativi. Sono configurazione, non dati da condividere, e vanno trattati con la stessa cura di un segreto.

---

## 6. Guida all'uso

L'interfaccia è una pagina unica con pannelli raggruppati per attività.

### Anonimizza

Incolla un log, oppure carica uno o più file, scegli il formato di output (rilevato automaticamente di default) ed elabora. Il pannello risultato mostra l'output mascherato; un report riassume cosa è stato mascherato, cosa tenuto, cosa eliso e — quando un kit vendor ha fatto match — il vendor rilevato e la copertura.

Controlli principali:

- **Policy IP** — `non anonimizzare IP` / `solo IP interni` / `tutti gli IP`. Default: **tutti**.
- **Policy URL** — `non anonimizzare URL` / `solo host del cliente` / `tutti gli URL`. Default: **tutti**. Le credenziali e i valori di query sensibili vengono comunque trattati, indipendentemente da questa scelta.
- **Safe mode** — elide i campi non classificati (fail-closed). Consigliata attiva.
- **Preserva subnet** — mantiene il raggruppamento /24 degli IPv4 anonimizzati.
- **Maschera reti pubbliche del tenant** — maschera i CIDR di `tenant_networks.txt` anche con "solo IP interni".
- **Kit vendor** — forza un kit specifico, oppure lascia il rilevamento automatico.
- **Profilo di lavoro** — applica un preset coerente (vedi sotto).

### Ripristina (de-anonimizza)

Incolla o carica un output mascherato e riottieni i valori originali. Richiede il permesso `reverse` ed è registrato nel log di audit. Il ripristino funziona su testo, formati strutturati, CSV, `.docx` e `.pdf`.

### Card documenti

- **Word .docx** — restituisce un `.docx` anonimizzato con stili, tabelle, intestazioni e numerazione preservati; cambia solo il testo. Una card gemella ripristina un `.docx` mascherato.
- **Outlook .pst** — estrae ogni messaggio e restituisce un record per messaggio (NDJSON o CSV). Il corpo del messaggio è disponibile sia come `completeHeader` (il messaggio come esce dall'archivio) sia come `body` (lo stesso contenuto ridotto a testo leggibile).
- **PDF** — due modalità: `PDF impaginato` (restituisce un PDF con pagine e posizioni preservate e il testo originale realmente rimosso) oppure `testo` (testo estratto e anonimizzato). Una card gemella ripristina un PDF mascherato.

### Kit studio

Sfoglia i kit installati, apri un kit di serie come copia di partenza, modifica un kit utente, validalo ed esegui un dry-run su un'intestazione per vedere come verrebbe classificata ogni colonna — senza elaborare alcun valore.

### Sessioni

Raccogli più log (incolla e/o file) come voci separate, elaborale insieme e scarica un unico ZIP. Le sessioni vivono in memoria e si azzerano al reload o al logout; nulla viene scritto su disco.

### Profili di lavoro

Preset che applicano un insieme coerente di opzioni. Dalla 0.26.1 ogni profilo maschera per default tutti gli IP e tutti gli URL; l'unica eccezione è **Threat hunting (interno)**, che volutamente mantiene leggibili gli indicatori tecnici per la correlazione interna.

| Profilo | Scopo |
|---|---|
| Ticket cliente | Report verso il cliente: contesto tecnico utile, dati interni e PII protetti |
| Analisi AI esterna | Preset prudente per LLM esterni: tutto mascherato, segreti e PII minimizzati |
| Qualità campi | Audit della qualità di anonimizzazione: copertura, elisioni, tuning campi |
| Threat hunting (interno) | Mantiene leggibili gli indicatori per la correlazione interna; blocca comunque segreti e PII |
| Report / allegato | Output ad alta minimizzazione per allegati, evidenze, report |

### Amministrazione

Gestione utenti (creazione, assegnazione di ruoli e tenant), log di audit e controllo di reset del vault (solo admin; archivia il vault invece di eliminarlo).

---

## 7. Formati supportati

LogMask rileva il formato automaticamente, oppure puoi forzarlo.

| Formato | Note |
|---|---|
| Testo semplice | Scrubbing di testo libero sull'intero input |
| CSV / TSV | Classificazione per colonna tramite kit ed euristiche; gli export verticali chiave/valore vengono ribaltati automaticamente |
| JSON / NDJSON | Mascheramento ricorsivo dei campi; array e oggetti annidati supportati |
| CEF | ArcSight Common Event Format |
| LEEF | IBM QRadar Log Event Extended Format |
| Syslog (key=value) | Syslog strutturato |
| Word `.docx` | Preserva l'impaginazione; restituisce un `.docx` valido |
| Outlook `.pst` | Estrazione per messaggio; richiede `pst-utils` nell'immagine |
| PDF | Redazione con impaginazione preservata o estrazione di testo; richiede PyMuPDF |

Robustezza a livello di byte: il parsing CSV rimuove i byte NUL incorporati (comuni negli export di eventi Windows) invece di fallire; i prefissi di trasporto usati dai wrapper Elastic/Kibana (`_source.`, `fields.`, `winlog.event_data.`, …) vengono rimossi prima del match sui campi, così il kit del prodotto interno si applica comunque.

---

## 8. Il motore di pseudonimizzazione

### Il passaggio di mascheramento

`Anonymizer.process(text)` esegue una master regex sull'input che riconosce, in un ordine di precedenza fisso: URL, indirizzi e-mail, UPN, IPv4/IPv6, indirizzi MAC, pattern utente-nel-percorso (`C:\Users\jdoe\…`), FQDN e domini Windows. Ogni match viene instradato al builder di pseudonimi del suo tipo. Dopo il passaggio della regex, girano una serie di passaggi aggiuntivi:

1. **Hostname nudi** — token host non catturati dai pattern strutturati.
2. **Identità SharePoint** — percorsi `/personal/<chi>/`.
3. **Nomi di persona** — rilevamento nome/cognome tramite liste di serie e del tenant.
4. **Identità in prosa** — narrazioni `User mrossi logged on…` (vedi sotto).
5. **Scansione DLP** — credenziali, IBAN, codice fiscale, telefono, P.IVA, indirizzo, id cloud, parametri URL sensibili.
6. **Termini cliente** — i nomi cliente configurati, sempre mascherati per ultimi come sweep finale.

### Pseudonimi deterministici e con chiave

Uno pseudonimo è un hash con chiave del valore:

```
pseudonimo = builder( HMAC(chiave_tenant, tipo, valore_normalizzato) )
```

Poiché la derivazione è deterministica e legata alla chiave del tenant, lo stesso valore produce sempre lo stesso token all'interno di un tenant, tenant diversi producono token diversi e la corrispondenza non è forzabile a forza bruta senza la chiave del tenant. Il valore originale è conservato cifrato nel vault, così il token è reversibile; i tipi irreversibili (nome cliente, segreto) non vengono mai messi nel vault.

### Lo sweep dei valori noti al vault

Dopo il passaggio principale, LogMask può spazzare l'output alla ricerca dei valori già noti al vault e sostituirli con il loro pseudonimo canonico — è così che un host nominato in un messaggio in testo libero riceve lo stesso token assegnatogli nel suo campo dedicato. Lo sweep è adattivo nel costo: per un singolo evento su un vault grande cerca testo→vault tramite blind index (senza decifrare); per un export enorme su un vault piccolo legge il vault una volta sola. Entrambe le strategie producono lo stesso output.

Nei contesti in linguaggio naturale (documenti, oggetti e corpi di e-mail) lo sweep gira in **modalità prosa**, che sostituisce solo gli originali che non possono essere parole comuni — quelli con una cifra o un separatore (`m.rossi`, `srv-01`, `DOMINIO\utente`) o composti da più parole (`Mario Rossi`). Questo impedisce che una parola comune finita nel vault per una vecchia classificazione errata (`SOC`, `Windows`, `Sicurezza`) corrompa il testo leggibile.

### Guardie di correttezza

Gran parte del motore sono guardie che impediscono il mascheramento *sbagliato*, dannoso quanto una fuga perché distrugge gli IOC o corrompe il testo in silenzio:

- **Guardia hash-IOC** — una sequenza di ≥16 caratteri esadecimali è un indicatore (hash), mai un host; viene tenuta.
- **Guardia blob opaco** — un token adiacente a `+`, `/` o `=` è dentro un blob base64 (es. un `_id` di evento) e non viene mascherato, così gli identificatori univoci non vengono corrotti.
- **Guardia host-originale** — vengono spazzati solo i valori con la forma di un nome macchina; parole di prodotto (`Windows`, `Management`) e nomi di processo (`WmiPrvSE.exe`) no.
- **Guardia prosa-originale** — in linguaggio naturale vengono spazzati solo gli originali con forma di identificatore.
- **Identità nel testo** — le identità chiave/valore dentro i messaggi di evento Windows (`Account Name: mrossi`) e i JSON serializzati (`"SubjectUserName":"mrossi"`) vengono mascherate; i segnaposto dei log (`-`, `N/A`, `0x0`, `%%1833`, `localhost`, `SYSTEM`) no.
- **Controllo Luhn P.IVA** — un numero nudo di 11 cifre viene mascherato come partita IVA italiana solo se supera il controllo di Luhn; altrimenti è trattato come un record id e lasciato stare.
- **Guardia falsi positivi indirizzi** — gli indirizzi non etichettati richiedono un nome via con iniziale maiuscola più un numero civico, così `Potential RMM Tool Installation via Uncommon Process` e `traffic via proxy 8080` non vengono scambiati per indirizzi.

### Idempotenza e reversibilità

Elaborare un output già mascherato non lo cambia: uno pseudonimo esistente viene riconosciuto e lasciato com'è. Il ripristino inverte ogni token reversibile; i token irreversibili (`CLIENT-…`, `secret-…`, `[ELIDED]`) restano, per scelta.

---

## 9. Riferimento delle forme dei token

| Tipo | Input di esempio | Token di esempio | Reversibile |
|---|---|---|---|
| user | `mrossi` | `usr-4ozopszr` | sì |
| email | `a@acme.com` | `usr-6rwixc3e@osgwjo.masked` | sì |
| fqdn / host | `SRV-DC01.corp.local` | `host-ri6jxfsb.masked.local` | sì |
| ipv4 (interno) | `10.20.30.40` | `198.18.x.x` | sì |
| ipv4 (pubblico) | `8.8.8.8` | `198.19.x.x` | sì |
| ipv6 | `fe80::1` | `fd00:…::1` | sì |
| mac | `00:1a:2b:3c:4d:5e` | `02:…` (locally-administered) | sì |
| windomain | `CORP` | `DOM-shphyawa` | sì |
| codice fiscale | `VRGSRA76B55H501Z` | `cf-tyvu3zav7vpf` | sì |
| iban | `IT60X05428…` | `iban-dwchbizxmfec` | sì |
| telefono | `+39 335 1234567` | `tel-vzoftypx33b5` | sì |
| P.IVA | `00743110157` | `vat-y6orweoro2ds` | sì |
| indirizzo | `Via Roma 12` | `addr-6krvk6xmear5` | sì |
| persona | `Mario Rossi` | `person-… person-…` | sì |
| id cloud / UUID | `6f0c9a7e-…` | `cloud-g2xiyb2gkiq5` | sì |
| SID | `S-1-5-21-…` | `S-1-5-21-…` (sintetico) | sì |
| id opaco | (id base64 / hex) | `id-…` | sì |
| **segreto** | `password=Estate2024!` | `secret-…` | **no** (mai nel vault) |
| **nome cliente** | `Acme Spa` | `CLIENT-…` | **no** (mai nel vault) |
| **eliso** | (non classificato, Safe mode) | `[ELIDED]` | **no** |

Gli IPv4 sintetici usano gli intervalli di benchmarking `198.18.0.0/15` (RFC 2544/6890) così da non poter essere confusi con indirizzi reali di produzione o privati; `198.18/16` marca le sorgenti interne e `198.19/16` quelle esterne. Gli IPv6 sintetici usano `fd00::/8` (unique-local). I MAC sintetici usano il prefisso locally-administered `02:…`.

---

## 10. Kit vendor

Un kit è un file YAML che mappa i nomi campo di un vendor a tipi e azioni. Il rilevamento avviene tramite campi fingerprint più suggerimenti d'intestazione; vince il kit col punteggio più alto, soggetto a una confidenza minima.

**Kit di serie (21):** Acronis, AWS CloudTrail, Bitdefender, Cisco Secure Endpoint, Cortex (Palo Alto XDR / XSIAM / XSOAR), CrowdStrike, Darktrace, Elastic ECS, Exabeam (New-Scale CIM 2.0 / Advanced Analytics / Data Lake), Fortinet, Microsoft Defender, Microsoft Entra, Microsoft Sentinel, Okta, Proofpoint, SentinelOne, Sophos, Splunk CIM, Trend Vision One, Wazuh, Zscaler.

**Struttura delle regole.** Ogni regola ha un `pattern` (una regex confrontata col nome campo) più un'`action` e, per `mask`, un `kind`:

```yaml
- pattern: ^(dest|src)_user_(sid|dn|ou|entity_id)$
  action: mask
  kind: user
- pattern: ^action_evtlog_event_id$
  action: keep
- pattern: ^(message|raw_log|description)$
  action: text
```

Le regole sono valutate dall'alto verso il basso; quelle specifiche devono precedere i catch-all generici (un campo come `action_evtlog_event_id` va tenuto *prima* che la regola generica `.*_id$` lo maschererebbe).

**Kit utente.** I file in `data/kits/*.yaml` vengono caricati sopra quelli di serie con hot reload e hanno priorità. Usa il kit studio per aprire un kit di serie come copia, modificarlo, validarlo ed eseguire un dry-run su un'intestazione prima di salvare.

**La copertura è misurata, non presunta.** Il kit Exabeam, per esempio, è costruito sui 1165 nomi di campo pubblicati nel repository ufficiale `ExabeamLabs/CIMLibrary`; un test di regressione verifica che nessun campo il cui nome denota un'identità resti leggibile, mentre i campi operativi restano leggibili.

**Nessun kit può tenere in chiaro i campi sconosciuti.** Una regola di kit è taggata `vendor:` e il Safe mode di proposito non ri-elide i campi classificati da un kit — quindi un catch-all `.* → keep` in fondo a un kit terrebbe leggibile *ogni* campo non riconosciuto, annullando il fail-closed. Un test di regressione sull'intera classe vieta un `.* → keep` (e un `.* → mask` con un kind che non maschera) in qualsiasi kit. Dove un kit ha bisogno di un catch-all per un vendor con moltissimi campi, usa `.* → text`, che processa i valori sconosciuti come testo libero — mascherando ogni identità al loro interno (IP, e-mail, host, `DOMINIO\utente`, nome persona o cliente) e lasciando leggibile il contenuto operativo. Ogni kit deve classificare utenti e IP, e anche gli host tranne i vendor senza un concetto di host (Proofpoint, AWS CloudTrail, Okta, Entra), elencati esplicitamente così un'eccezione è una scelta e non una svista.

---

## 11. Categorie DLP e Safe mode

Indipendentemente dai kit vendor, una scansione DLP trova i valori sensibili ad alta confidenza ovunque nell'output — anche dentro il testo libero. Ogni categoria ha un'azione predefinita e può essere sovrascritta per richiesta.

| Categoria | Tipo | Default |
|---|---|---|
| `credentials` | secret | redact |
| `private_key` | secret | redact |
| `tax_id` | taxid | pseudonymize |
| `iban` | iban | pseudonymize |
| `phone` | phone | pseudonymize |
| `person_name` | person | pseudonymize |
| `address` | address | pseudonymize |
| `vat_id` | vat | pseudonymize |
| `cloud_id` | cloud | pseudonymize |
| `sensitive_url` | secret | redact |

Azioni: `pseudonymize` (token reversibile), `redact` (`[ELIDED]`, irreversibile), `block` (fa fallire l'output), `keep` (lascia in chiaro).

**Safe mode** è l'interruttore fail-closed. Con Safe mode attiva, qualsiasi campo popolato che nessun kit e nessuna euristica ha saputo classificare viene eliso. Il ragionamento è che un campo non classificato è esattamente il posto dove si nasconde un identificatore inatteso; lasciarlo passare in chiaro sarebbe l'unico punto da cui una fuga sfugge.

**Documenti e posta non elidono mai.** Sui percorsi `.docx`, `.pst` e `.pdf`, elidere un campo è un danno netto — il file restituito perde testo e il ripristino non può ricostruirlo. Su quei percorsi ogni valore sensibile diventa uno pseudonimo invece di `[ELIDED]`. I segreti sono l'unica eccezione su quei percorsi: diventano un token deterministico `secret-…` mai scritto nel vault, così il documento resta leggibile ma il segreto non è recuperabile e lo strumento non diventa mai un deposito di password dei clienti.

### Override dei campi non tracciati

I campi che nessun kit classifica vengono elisi in Safe mode. Per cambiare il trattamento di un campo specifico senza scrivere una regola di kit, il report mostra ogni campo non tracciato con una tendina a tre scelte e un pulsante **Salva config campi mancanti**:

- **mantieni** — lascia il valore leggibile (metadati operativi, IOC);
- **pseudonimizza** — token reversibile `id-…` (sempre kind generico `opaque`, che maschera qualsiasi valore; un kind tipizzato come `ipv4` NON viene offerto di proposito, perché restituirebbe invariati i valori non conformi — una fuga);
- **elidi** — `[ELIDED]`.

Le scelte sono salvate globalmente per nome campo in `data/field_overrides.json` (hot reload) e valgono per ogni formato — CSV, JSON/NDJSON, CEF, LEEF, syslog — perché risolte prima del rilevamento vendor. Sono indipendenti dal vendor rilevato, dato che i campi non tracciati compaiono di solito proprio quando nessun kit ha fatto match. Gli override vincono su kit, catalogo ed euristiche, ma un campo senza override continua a essere eliso in Safe mode: il fail-closed è preservato. Il salvataggio richiede il permesso `admin`, come le altre modifiche di configurazione. Dalla 0.27.0 `redact` è anche un'azione valida nei kit, quindi un kit utente può forzare l'elisione di un campo.

---

## 12. Riferimento API

Tutti gli endpoint sono sotto `/api`. La sessione è un cookie; le richieste che modificano lo stato richiedono il token CSRF (double-submit: il valore del cookie `logmask_csrf` ripetuto nell'header `X-CSRF-Token`). Ogni richiesta è autorizzata per ruolo e, dove pertinente, per tenant.

### Autenticazione

| Metodo | Percorso | Permesso | Scopo |
|---|---|---|---|
| POST | `/api/login` | — | Login; restituisce i cookie di sessione + CSRF |
| GET | `/api/me` | sessione | Utente corrente, ruoli, capacità |
| POST | `/api/logout` | sessione | Termina la sessione |
| POST | `/api/change-password` | sessione | Cambia la propria password |

### Anonimizza / ripristina

| Metodo | Percorso | Permesso | Scopo |
|---|---|---|---|
| POST | `/api/anonymize` | anonymize | Input testo / CSV / strutturato (corpo JSON) |
| POST | `/api/anonymize-docx` | anonymize | Documento Word (multipart) |
| POST | `/api/anonymize-pst` | anonymize | Archivio Outlook (multipart) |
| POST | `/api/anonymize-pdf` | anonymize | PDF (multipart; `output=pdf\|text`) |
| POST | `/api/deanonymize` | reverse | Ripristina testo / strutturato / CSV |
| POST | `/api/deanonymize-docx` | reverse | Ripristina un `.docx` mascherato |
| POST | `/api/deanonymize-pdf` | reverse | Ripristina un PDF mascherato |

### Kit e policy

| Metodo | Percorso | Permesso | Scopo |
|---|---|---|---|
| GET | `/api/vendor-kits` | sessione | Elenca i kit installati |
| POST | `/api/kit-dry-run` | sessione | Classifica un'intestazione senza elaborare valori |
| GET | `/api/kits/files` | admin | Elenca i file kit utente |
| GET | `/api/kits/files/{name}` | admin | Legge un kit utente |
| PUT | `/api/kits/files/{name}` | admin | Crea/aggiorna un kit utente (validato) |
| DELETE | `/api/kits/files/{name}` | admin | Elimina un kit utente |
| POST | `/api/kits/validate` | admin | Valida uno YAML di kit |
| GET | `/api/kits/bundled/{kit_id}` | admin | Legge un kit di serie |
| GET | `/api/dlp-categories` | sessione | Catalogo delle categorie DLP |
| GET | `/api/field-overrides` | sessione | Override per campo attuali |
| POST | `/api/field-overrides` | admin | Salva gli override per campo (keep/mask/redact) |
| GET | `/api/workflow-profiles` | sessione | Preset di lavoro |

### Reportistica e amministrazione

| Metodo | Percorso | Permesso | Scopo |
|---|---|---|---|
| GET | `/api/tenants` | sessione | Tenant a cui l'utente può accedere |
| GET | `/api/fields` | reports | Statistiche a livello di campo |
| GET | `/api/stats` | reports | Statistiche del vault |
| GET | `/api/admin/users` | admin | Elenca gli utenti |
| POST | `/api/admin/users` | admin | Crea un utente |
| POST | `/api/admin/vault/reset` | admin | Archivia-e-azzera il vault di un tenant |
| POST | `/api/admin/secret/reset` | admin | Rigenera la master key (archivia chiave + tutti i vault) |
| GET | `/api/admin/audit` | audit | Log di audit |

### Esempio — anonimizza testo

```bash
curl -X POST http://localhost:8090/api/anonymize \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf>" \
  --cookie "logmask_session=<session>; logmask_csrf=<csrf>" \
  -d '{"tenant":"acme","text":"user=mrossi src=10.20.30.40","format":"auto",
       "safe_mode":true,"ip_mode":"all","url_mode":"all"}'
```

Gli errori sono restituiti come JSON con un campo `detail` e, per gli errori imprevisti, un `error_type`; la traccia completa resta nei log del container e non viene mai esposta.

---

## 13. Modello di sicurezza

### Autenticazione e sessioni

- **Le password** sono hashate con Argon2 (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=2`); lunghezza minima 12; lo username non può comparire nella password.
- **Le sessioni** sono cookie marcati `HttpOnly` e `SameSite=strict`; imposta `LOGMASK_COOKIE_SECURE=true` dietro HTTPS. Vengono applicati timeout di inattività e durata assoluta.
- **Il CSRF** usa double-submit: un cookie `logmask_csrf` non-`HttpOnly` deve essere ripetuto nell'header `X-CSRF-Token` a ogni richiesta che modifica lo stato.
- **Rate limiting sul login**: dopo `LOGMASK_LOGIN_MAX_FAILURES` fallimenti nella finestra, l'account è bloccato per la durata della finestra.
- **L'admin di bootstrap** deve cambiare la password al primo accesso prima di qualsiasi altra azione.

### Ruoli (RBAC)

| Ruolo | Permessi |
|---|---|
| `operator` | anonymize |
| `analyst` | anonymize, reports |
| `reverser` | anonymize, reports, reverse |
| `admin` | anonymize, reports, reverse, admin, audit |

Il ripristino (`reverse`) è un privilegio distinto e superiore e ogni ripristino è scritto nel log di audit con utente, tenant, IP ed esito.

### Isolamento dei tenant

Gli identificatori di tenant sono validati da regex e canonicalizzati in una forma sicura per i percorsi (nessun traversal `.`/`..`), poi autorizzati contro l'ambito di tenant dell'utente. Vault e chiavi derivate sono per tenant; un utente può operare solo sui tenant che gli sono concessi.

### Crittografia

- Una chiave master di 32 byte con permessi `0600`.
- Chiavi per tenant derivate tramite HMAC.
- Valori originali cifrati con AES-GCM, un nonce casuale di 12 byte per riga.
- I blind index (hash con chiave) permettono allo sweep di cercare i valori senza decifrare il vault.

### Robustezza sugli input

- **Limiti di dimensione** per richiesta e file (413 al superamento).
- **Guardia zip-bomb `.docx`**: un tetto sulla dimensione decompressa con doppio controllo (dimensioni dichiarate, poi un budget di lettura), perché l'indice zip può mentire. Verificato: un documento da 200 KB che si espande a centinaia di MB viene respinto in millisecondi.
- **Tetto sull'estrazione `.pst`**: la dimensione estratta è limitata; `readpst` gira con un timeout e stdin chiuso, così un archivio corrotto o protetto da password non può bloccare il worker.
- **PDF**: tetto sul numero di pagine; i PDF cifrati/corrotti vengono respinti con un messaggio chiaro; il PDF prodotto viene riletto e si verifica che nessun valore originale sia ancora estraibile prima della consegna.
- **L'espansione di entità XML** (billion-laughs) è bloccata dal parser.
- **I byte NUL nei CSV** vengono rimossi invece di far crashare il parser.
- **Header Content-Security-Policy** e `Cache-Control: no-store` impostati; tutto il DOM dinamico nell'interfaccia è inserito via `textContent`/escaping, non HTML grezzo.

### Considerazioni residue (responsabilità dell'operatore)

- Il bind predefinito è `0.0.0.0` (raggiungibile da LAN); imposta `LOGMASK_BIND=127.0.0.1` per uso solo host.
- Il container gira come root; i tetti sugli input di cui sopra mitigano ma non eliminano questo aspetto.
- `readpst` è codice C di terze parti; il timeout e il tetto sulla dimensione ne limitano l'impatto, non le vulnerabilità interne.
- `client_terms.txt` e `person_terms.txt` contengono valori reali e identificativi e vanno protetti di conseguenza.

---

## 14. Operazioni e risoluzione problemi

### Reset del vault

`Reset vault` (solo admin) archivia il vault del tenant con un timestamp invece di eliminarlo. Poiché il vault è l'unica cosa che rende reversibili gli export passati, azzerarlo significa perdere la corrispondenza per tutto ciò che è già stato condiviso; l'archiviazione consente il recupero se l'azzeramento è stato un errore. La cancellazione definitiva resta una scelta manuale e consapevole.

### Reset secret (master key)

`Reset secret` (solo admin) rigenera la master key — il secret da cui derivano **tutti** i token. Un pop-up riassume il rischio e richiede di digitare la parola `RESET`. L'effetto è globale e distruttivo per la reversibilità:

- ogni token futuro cambia (lo stesso valore produce uno pseudonimo diverso, `secret-…` compresi);
- **ogni vault esistente, di ogni tenant, smette di essere reversibile**, perché cifrato con la chiave precedente.

Come per il reset del vault, nulla viene cancellato: la vecchia chiave e tutti i vault vengono **archiviati** con un timestamp (`master-prereset-…key`, `vault-prereset-…db`) e sono recuperabili **solo insieme** — rimettendo entrambi al loro posto si torna indietro. Utenti e sessioni non dipendono dalla master key, quindi nessuno viene disconnesso, e il cambio ha effetto subito senza riavvio.

Usalo per ottenere un secret nuovo e scollegato — per esempio dopo aver copiato la cartella su un'altra macchina, se vuoi deliberatamente che il nuovo deployment produca token diversi. Al contrario, per mantenere la continuità tra macchine, copia `data/master.key` (e i vault) invece di fare il reset.

### Log di audit

Ogni operazione di anonimizzazione, ripristino, salvataggio override e reset del secret è registrata con azione, utente, tenant, IP ed esito (più i conteggi e, per i fallimenti, il tipo di eccezione — mai il contenuto del log). Usalo per verificare chi ha ripristinato o resettato cosa e quando.

### Situazioni comuni

| Sintomo | Causa probabile / azione |
|---|---|
| `PST anonymization failed: Failed to fetch` | Il `.pst` era ancora aperto in Outlook; il file è cambiato durante l'upload. Chiudi Outlook o lavora su una copia. LogMask legge il file in una copia stabile prima di inviarlo. |
| `il PDF è protetto da password` | Rimuovi la protezione del PDF (aprilo e salvane una copia senza password) prima di anonimizzarlo. |
| Un campo esce in chiaro | Non è stato classificato da alcun kit; attiva Safe mode, oppure aggiungi una regola in un kit utente / una voce in `keep_fields`, oppure esegui un dry-run del kit per vedere la classificazione. |
| È tutto `[ELIDED]` | Nessun kit vendor ha fatto match e Safe mode ha eliso i campi ignoti; forza il kit corretto o aggiungi un kit utente. |
| Il ripristino lascia alcuni valori come pseudonimi | Quei token sono irreversibili per scelta (`CLIENT-…`, `secret-…`) o appartengono al vault di un altro tenant. |
| È diventato lento | Una release precedente aveva uno sweep dipendente dalla dimensione del vault; le release attuali sono indipendenti dal vault. Token singoli molto grandi erano un vettore ReDoS corretto nella 0.26.2. |

### Aggiornamento

Copia la nuova release sopra la cartella del progetto (o estrai lo ZIP di release), poi `docker compose down && docker compose build --no-cache && docker compose up -d`. I vault e la configurazione nella cartella dati sono preservati tra gli aggiornamenti.

---

## 15. Considerazioni normative (UE / Italia, uso dell'AI)

> **Questa sezione è informativa, non è un parere legale.** Riassume come LogMask si colloca nel quadro normativo europeo e italiano al 2026, così da permetterti una valutazione informata con il tuo DPO o un legale. Non è un'opinione di conformità e gli autori di LogMask non sono i tuoi avvocati.

### 15.1 Il fatto giuridico centrale: pseudonimizzazione non è anonimizzazione

Ai sensi del GDPR (Regolamento (UE) 2016/679), la **pseudonimizzazione** è definita all'articolo 4, punto 5, come il trattamento dei dati personali in modo tale che non possano più essere attribuiti a un interessato senza informazioni aggiuntive conservate separatamente. Fondamentale: **il Considerando 26 stabilisce che i dati pseudonimizzati, che potrebbero essere attribuiti a una persona fisica mediante l'uso di informazioni aggiuntive, restano dati personali.** L'anonimizzazione, al contrario, è irreversibile e — sempre per il Considerando 26 — esce dal campo di applicazione del GDPR.

LogMask esegue pseudonimizzazione. Di conseguenza:

- **Un export mascherato da LogMask è, in generale, ancora un dato personale** ai sensi del GDPR, perché il vault più la chiave del tenant sono esattamente quelle "informazioni aggiuntive" che consentono la re-identificazione. Trattarlo (conservarlo, condividerlo, inviarlo a un servizio AI) richiede comunque una base giuridica e attiva comunque gli obblighi del GDPR.
- **Il vault e la chiave master sono le "informazioni aggiuntive"** che l'articolo 4, punto 5, richiede siano "conservate separatamente e soggette a misure tecniche e organizzative". La cifratura AES-GCM per tenant di LogMask, la chiave master a `0600`, l'RBAC e il log di audit sono il tipo di misure che l'articolo contempla — ma la *separazione* (tenere il vault fuori dalle mani del destinatario) è una responsabilità operativa: non consegnare mai il vault insieme a un export mascherato.
- **Le trasformazioni irreversibili si comportano diversamente.** I valori che LogMask non memorizza mai — nomi cliente (`CLIENT-…`), segreti (`secret-…`) e campi elisi (`[ELIDED]`) — non sono reversibili nemmeno da chi possiede il vault, e per quei valori specifici l'export si avvicina all'anonimizzazione. Il resto resta pseudonimo.

Conclusione pratica: LogMask è un **controllo di minimizzazione e riduzione del rischio**, non una bacchetta magica che sottrae i dati al campo di applicazione del GDPR. Riduce in modo sostanziale i dati personali esposti a un destinatario e sostiene il principio di minimizzazione (art. 5, par. 1, lett. c) e l'obbligo di sicurezza del trattamento (art. 32), che è precisamente il suo valore.

### 15.2 Inviare log a un servizio AI

Il caso d'uso specifico a cui mira LogMask — mascherare un log prima di inviarlo a un LLM o assistente AI esterno — si colloca all'interno di due regimi che si sovrappongono.

**GDPR.** Inviare un log a un servizio AI di terze parti è un'operazione di trattamento e, se il fornitore è fuori dall'UE/SEE, potenzialmente un trasferimento. Richiede una base giuridica, un accordo sul trattamento dei dati con il fornitore e l'aderenza al principio di minimizzazione. Il **Garante per la protezione dei dati personali** ha ripetutamente sottolineato la difficoltà di applicare la minimizzazione ai servizi di AI generativa e ha adottato provvedimenti in quest'area (in particolare il caso ChatGPT, chiuso a dicembre 2024 con una sanzione da 15 milioni di euro; si noti che un tribunale italiano ha successivamente annullato il relativo provvedimento, quindi la giurisprudenza è ancora in evoluzione). Pseudonimizzare il log prima che esca dal tuo controllo è un modo diretto e difendibile di onorare la minimizzazione: il servizio AI vede `usr-4ozopszr`, non `mrossi`.

**Regolamento UE sull'IA — AI Act (Regolamento (UE) 2024/1689).** L'AI Act si applica progressivamente. Gli obblighi per i modelli di IA per finalità generali (GPAI) si applicano dal **2 agosto 2025**; una tappa rilevante cade il **2 agosto 2026**, quando entrano in vigore gli obblighi di trasparenza (art. 50, es. dichiarare che un utente sta interagendo con un sistema di IA) e il regime sanzionatorio per i GPAI (ammende fino al 3% del fatturato mondiale annuo o 15 milioni di euro, se superiore). Le tempistiche per alcuni sistemi ad alto rischio sono state successivamente differite (a dicembre 2027 e agosto 2028) dal "Digital Omnibus". LogMask di per sé non è un sistema di IA e non è regolato dall'AI Act; la sua rilevanza è di essere un controllo che puoi porre *a monte* di un sistema di IA per ridurre i dati personali che quel sistema tratta.

### 15.3 La legge nazionale italiana sull'IA (Legge 132/2025)

L'Italia ha adottato la sua prima legge organica sull'IA, la **Legge 23 settembre 2025, n. 132** ("Disposizioni e deleghe al Governo in materia di intelligenza artificiale"), pubblicata in Gazzetta Ufficiale il 25 settembre 2025 ed **in vigore dal 10 ottobre 2025**. È espressamente coordinata con l'AI Act europeo e aggiunge indirizzi di livello nazionale. Individua due autorità nazionali: l'**Agenzia per l'Italia Digitale (AgID)** per la promozione e lo sviluppo, e l'**Agenzia per la Cybersicurezza Nazionale (ACN)** per la vigilanza e la sicurezza. Per un'organizzazione che usa l'IA su dati che possono contenere informazioni personali o sensibili sul piano della sicurezza, la legge rafforza i principi di trasparenza, sorveglianza umana e sicurezza che un controllo di pre-trattamento come LogMask aiuta a rendere operativi.

### 15.4 Cosa LogMask ti dà e cosa non ti dà

**Ti aiuta a:** minimizzare i dati personali e identificativi del cliente esposti quando un log viene condiviso o inviato a un servizio AI; mantenere una corrispondenza reversibile e verificabile sotto il tuo controllo; dimostrare una misura tecnica concreta verso la minimizzazione (art. 5, par. 1, lett. c) e la sicurezza (art. 32); e rimuovere in modo irreversibile gli elementi più sensibili (nomi cliente, segreti).

**Non fa, da solo:** rendere "anonimo" un export mascherato né sottrarlo al campo del GDPR (il vault lo rende re-identificabile); fornire una base giuridica per il trattamento o il trasferimento; sostituire un accordo sul trattamento con un fornitore AI; né esimerti da una DPIA dove richiesta. Queste restano decisioni organizzative.

**Indicazioni operative che ne discendono:**

1. **Non consegnare mai il vault insieme all'export.** La separazione è ciò che rende significativa la pseudonimizzazione ai sensi dell'art. 4, punto 5.
2. **Proteggi il vault e la chiave master** come gli asset sensibili che sono — sono la chiave di re-identificazione.
3. **Preferisci le impostazioni più protettive** quando il destinatario è esterno, soprattutto un servizio AI: tutti gli IP e gli URL mascherati (i default della 0.26.1), Safe mode attiva, segreti e PII minimizzati. Il profilo di lavoro "Analisi AI esterna" codifica questo.
4. **Tratta `client_terms.txt` / `person_terms.txt`** come configurazione riservata.
5. **Conserva il log di audit** come prova di chi ha ripristinato cosa e quando.

---

## 16. Estendere LogMask

### Aggiungere o sovrascrivere un kit vendor

Crea un file YAML in `data/kits/`. Viene ricaricato a caldo e ha priorità sul kit di serie con lo stesso id. Usa il kit studio per partire da una copia di un kit di serie, poi valida ed esegui un dry-run prima di salvare. Metti le regole specifiche prima dei catch-all generici, e preferisci `keep` per i campi operativi e gli IOC, `mask` (con un `kind`) per le identità e `text` per i campi in testo libero.

### Aggiungere un rilevatore DLP

Le categorie DLP stanno in `dlp.py` con etichetta, descrizione, azione predefinita e tipo. Un nuovo rilevatore aggiunge una regex allo scanner dei residui e, dove il valore debba essere reversibile, un corrispondente builder di pseudonimi in `logmask.py`. Le nuove categorie compaiono automaticamente nel pannello DLP dell'interfaccia.

### Regolare il rilevamento di persone / host / cliente

Popola i file dati: `person_terms.txt` per i dipendenti reali (mascherati anche come token nudo), `host_terms.txt` per i glob di nomi host del tenant, `tenant_networks.txt` per i CIDR pubblici che identificano il cliente, `client_terms.txt` per i nomi cliente. Le liste di serie in `data/persons/` alimentano il rilevamento generico dei nomi.

### Disciplina dei test

Ogni cambiamento di comportamento è accompagnato da un test di regressione; la suite è la specifica del comportamento voluto, in particolare per le guardie (un mascheramento troppo aggressivo è trattato come un bug alla pari di una fuga). Esegui l'intera suite prima di costruire una release.

---

*LogMask 0.27.6 — documentazione tecnica. Per lo storico delle modifiche vedi `CHANGELOG.md`.*
