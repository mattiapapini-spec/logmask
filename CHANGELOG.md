# Changelog

## 0.27.6 - licenza: da MIT ad AGPL-3.0 con dual licensing

- **LogMask e' ora rilasciato sotto GNU AGPL-3.0** (testo canonico in LICENSE,
  (c) 2026 Mattia Papini). Chi lo distribuisce o lo offre come servizio in
  rete, anche modificato, deve rendere disponibile il proprio sorgente agli
  utenti. Per l'uso commerciale senza obblighi AGPL e' disponibile una licenza
  separata dall'autore (dual licensing; contatto nel README).
- La scelta rende coerente anche il modulo PDF: PyMuPDF e' AGPL, e ora l'opera
  combinata e' sotto la stessa licenza. Il supporto PDF resta opzionale.
- README e documentazione (EN/IT) aggiornati. Nessun cambiamento di codice.

## 0.27.5 - upload PST: il 413 ora si spiega, e i default reggono i PST

- **Il messaggio del limite upload veniva inghiottito.** Il middleware del
  limite di corpo risponde con {"error": ...} ma il gestore della card PST
  leggeva solo "detail": l'utente vedeva un nudo "HTTP 413" senza sapere che
  il file superava il limite configurato. Ora vengono letti entrambi i campi.
- **Default di .env.example adeguati.** I minimi (8 MiB file / 12 MiB corpo)
  fallivano su qualsiasi PST reale: portati a 64/96 MiB, con nota su come
  alzarli ulteriormente e sull'impatto in memoria.
- Nessun cambiamento per chi ha gia' un .env con limiti propri.

## 0.27.4 - epurazione completa e preparazione GitHub

- **Rimossi tutti i derivati di configurazioni reali da test ed esempi.** I
  fixture usavano glob di naming host e frammenti di percorso provenienti da
  configurazioni di tenant reali (etichettati come tali nei commenti):
  sostituiti con convenzioni inventate di forma equivalente (prefisso,
  suffisso, wildcard in mezzo, suffisso di dominio), cosi' i test verificano
  le stesse proprieta' senza contenere nulla di riconducibile. Aggiornati
  anche l'esempio Cortex (dominio fittizio), l'esempio host_terms, la
  docstring del matcher e un riferimento personale in un fixture.
- **Riscritta la voce di changelog 0.27.3**: descriveva la rimozione dei
  riferimenti citandoli per nome. Ora descrive senza nominare.
- **`.gitignore` e `.dockerignore` rinforzati**: esclusi dati runtime
  (data/, *.db, *.key, bootstrap, override), segreti (.env e varianti, con la
  sola eccezione di .env.example), pacchetti (*.zip, *.tar) e file di lavoro.
  Il .dockerignore esclude anche docs/tests/examples dal contesto di build.
- **README rinnovato** per la pubblicazione (titolo senza versione fissa,
  puntatori a VERSION, CHANGELOG e docs/).
- La suite completa passa invariata: le sostituzioni preservano le forme che
  i test verificano.

## 0.27.3 - rimossi riferimenti a enti reali dagli esempi

- **Placeholder del campo tenant.** Il segnaposto d'esempio richiamava un ente
  reale: sostituito con un esempio fittizio ("es. acme-srl"), chiave i18n
  allineata.
- **Commento in logmask.py.** Un esempio in una docstring citava il nome di un
  cliente reale: sostituito con un nome generico.
- Scansione dell'intero progetto (UI, esempi, kit, test, documentazione) sui
  nomi cliente noti: nessun'altra occorrenza. Gli esempi usano solo nomi
  fittizi (Acme, Contoso) o toponimi generici che non identificano alcun
  cliente.
## 0.27.2 - revisione di completezza dei kit vendor

Audit dei 21 kit per verificare che nessun campo con identita' resti fuori.

- **Microsoft Entra: chiuso un difetto di fail-closed.** Il kit terminava con
  un catch-all `.* -> keep`. Essendo una regola del kit (taggata `vendor:`),
  il Safe mode la saltava: OGNI campo Entra non riconosciuto - anche futuro o
  custom - restava IN CHIARO, anche in Safe mode, annullando la protezione.
  Ora il catch-all e' `text`: un campo sconosciuto viene processato come testo
  libero, quindi ogni identita' al suo interno (IP, e-mail, host, dominio\
  utente, nome persona, nome cliente) viene mascherata, mentre il contenuto
  operativo resta leggibile. In piu': il nome del dispositivo ora e' un host
  (`host-`, non `usr-`), e citta'/provincia/coordinate della posizione vengono
  mascherate (il paese, grossolano, resta leggibile). I campi operativi noti
  (stato, gravita', metodo di autenticazione, browser... in IT ed EN) restano
  esplicitamente leggibili.
- **Proofpoint: coperti utente e host del relay.** Il kit, incentrato sulle
  e-mail, non aveva regole per l'account nudo del destinatario ne' per l'host
  del mail relay. Aggiunte regole difensive (user, hostname/relay/mta, IP
  client), piu' alcuni indirizzi in piu' (bcc, envelope from/rcpt).
- **Test di garanzia sull'intera classe di kit**: nessun kit puo' avere un
  catch-all `.* -> keep` (previene il ritorno del difetto Entra) o un catch-all
  `mask` con un kind che non maschera; ogni kit deve coprire utente e IP, e
  l'host tranne i vendor dichiaratamente senza host (Proofpoint, AWS
  CloudTrail, Okta, Entra) - elencati esplicitamente, cosi' un'eccezione e' una
  scelta e non una svista.

Esito della revisione: gli altri 19 kit sono risultati completi e corretti. In
particolare Zscaler tiene di proposito leggibili URL e host di DESTINAZIONE
(sono l'indicatore in un log proxy), mentre le identita' lato client (utente,
host, IP, device owner) sono mascherate; AWS CloudTrail e Okta non hanno un
campo host dedicato (i dati host viaggiano dentro blob gia' processati come
testo).

## 0.27.1 - reset secret, pop-up di conferma, doc in-app e un footgun chiuso

- **Reset secret (master key) nella pagina admin.** Rigenera la master key da
  cui derivano TUTTI i token: da qui in poi lo stesso valore produce uno
  pseudonimo diverso (secret- compresi) e OGNI vault esistente smette di essere
  reversibile. Come per il reset del vault nulla viene cancellato: la vecchia
  chiave e i vault vengono ARCHIVIATI con timestamp e sono recuperabili solo
  insieme. Utenti e sessioni non dipendono dalla master key: nessuno viene
  disconnesso, e il cambio ha effetto subito senza riavvio. Endpoint
  POST /api/admin/secret/reset (admin + CSRF).
- **Pop-up di conferma con riassunto dei rischi.** Il reset secret apre un
  modale che elenca le conseguenze e si sblocca solo digitando la parola
  RESET. Il pulsante resta disabilitato finche' la parola non e' corretta.
- **Documentazione in-app.** Nuova scheda "Documentazione" (IT/EN, segue la
  lingua dell'interfaccia): guida rapida operativa - uso, forme dei token,
  formati, campi non tracciati, reset vault/secret, sicurezza in breve. La
  documentazione tecnica completa e il PDF restano in docs/.
- **Bug hunt / security audit sulle due nuove funzioni.** Trovato e corretto un
  footgun negli override per campo: un override "pseudonimizza" con un kind
  tipizzato (ipv4, iban...) restituiva il valore INVARIATO quando il contenuto
  non era conforme - una fuga. Ora "pseudonimizza" usa sempre il kind opaco,
  che maschera qualsiasi valore. Verificato: gli override valgono su tutti i
  formati (CSV, JSON/NDJSON, CEF, LEEF, syslog); il reset secret e' serializzato
  con l'anonimizzazione (nessuna corruzione sotto carico concorrente); il
  modale non contiene contenuto controllabile dall'utente (niente XSS).
- Documentazione tecnica EN/IT aggiornata (override campi, reset secret) e PDF
  rigenerato.

## 0.27.0 - gestione diretta dei campi non tracciati

I campi che nessun kit classifica venivano elisi in Safe mode e, per cambiarne
il trattamento, bisognava scrivere a mano una regola in un kit YAML: macchinoso
proprio nel momento in cui serve, cioe' guardando il report di un export nuovo.

- **Menu a tendina per ogni campo fuori kit, nel report.** Accanto all'elenco
  dei campi non tracciati ora c'e' una colonna di tendine con tre scelte:
  **mantieni** (lascia leggibile), **pseudonimizza** (token reversibile,
  opaco di default) ed **elidi** (`[ELIDED]`). Un pulsante **Salva config
  campi mancanti** persiste le scelte, con hot reload immediato: il prossimo
  export usa la configurazione senza altri passaggi.
- **Override globali, non legati al vendor.** I campi non tracciati compaiono
  spesso quando NESSUN kit ha fatto match, quindi legare gli override al kit
  rilevato sarebbe fragile. Gli override valgono per nome campo su qualsiasi
  export e vincono su kit, catalogo ed euristiche - ma restano coerenti col
  fail-closed: un campo senza override continua a essere eliso in Safe mode.
- **`redact` e' ora un'azione valida anche nei kit**, non solo un effetto
  interno del Safe mode: un kit utente puo' forzare l'elisione di un campo.
- Nuovo endpoint `GET/POST /api/field-overrides` (salvataggio riservato agli
  admin, come le altre modifiche di configurazione) e file
  `data/field_overrides.json` ricaricato a caldo. Reversibilita' preservata:
  un campo su "pseudonimizza" torna al valore originale col ripristino.

## 0.26.2 - bug hunt e security audit

Giro mirato sulle superfici nuove (PDF, VAT/indirizzi, identita' nel testo,
kit Exabeam). Quattro difetti reali, tutti corretti.

- **ReDoS nel riconoscimento e-mail.** Il pattern usava una local part
  illimitata: "user_user_user..." senza @ faceva ritentare la @ a ogni
  posizione, con tempo QUADRATICO - 8000 caratteri = 11 secondi, un file di un
  solo token avrebbe bloccato il worker. Ora local part e dominio sono limitati
  ai valori RFC (64 e 255): il costo torna lineare (80.000 caratteri in 74 ms).
- **Falsi positivi gravi nel mascheramento delle identita' in prosa.** La
  0.25.2 mascherava QUALSIASI parola dopo "user"/"account": "user experience",
  "account balance", "user story", "account manager", "user input" - frasi
  comunissime - venivano corrotte in log e documenti. Ora servono DUE segnali:
  o il valore ha forma di identificatore (cifra, punto, underscore) o e'
  seguito da un verbo di autenticazione (logged, authenticated, accesso...).
  "User mrossi logged on" viene ancora mascherato; "user experience" no.
- **PDF cifrati e corrotti davano un errore opaco.** Un PDF protetto da
  password si apre ma non e' leggibile: senza la fix avrebbe prodotto un
  documento "anonimizzato" in realta' vuoto. Ora un PDF protetto o illeggibile
  viene riconosciuto e respinto con un messaggio chiaro (400) invece di un
  generico "fallita (ValueError)".
- **La verifica anti-fuga del PDF ora copre anche annotazioni e campi
  modulo.** get_text non estrae il loro contenuto: se _scrub_annotations avesse
  mancato qualcosa, il controllo sul solo testo di pagina non se ne sarebbe
  accorto. Ora la verifica include ogni superficie che puo' portare testo.

Verificato e gia' a posto: lo split di un valore su piu' span non produce
fughe (PyMuPDF unisce gli span contigui prima dell'estrazione, e la verifica e'
coerente con quella vista); gli endpoint PDF applicano authz, CSRF, isolamento
tenant e limite di dimensione come tutti gli altri; i warning derivati dal PDF
sono resi con textContent (nessun XSS); il tetto sulle pagine regge contro i
file costruiti per esaurire la memoria; VAT e indirizzi non collidono con hash
e IOC e fanno round-trip completo.

## 0.26.1 - il default e' "maschera tutto"

- **Tutti i profili di lavoro partono da "anonimizza tutti gli IP" e "maschera
  tutti gli URL".** Prima "Ticket cliente", "Analisi AI esterna" e "Valutazione
  campi" usavano ip_mode=internal, cioe' lasciavano in chiaro gli IP pubblici
  perche' "sono IOC". E' una scelta legittima, ma non come DEFAULT: chi non
  tocca le impostazioni non sa che sta condividendo indirizzi in chiaro, e su
  un preset dedicato agli LLM esterni e' il posto peggiore dove nasconderla.
  Resta possibile abbassarla a mano, consapevolmente.
- **Ogni profilo dichiara adesso anche url_mode.** Prima nessuno lo faceva:
  cambiando profilo la policy URL restava quella selezionata in precedenza,
  quindi il risultato dipendeva da cosa si era fatto prima - il modo peggiore
  di decidere quanto mascherare.
- **Unica eccezione, dichiarata: "Threat hunting interno"** (ip_mode=none,
  url_mode=internal). Il suo scopo e' tenere leggibili gli indicatori tecnici
  per la correlazione interna: mascherarli lo renderebbe inutile. Un test
  verifica che la descrizione del profilo lo dica.
- Nuovi test che fissano il default su tutti i percorsi - pannello principale,
  .docx, .pst, .pdf e API - compreso il controllo che ogni menu a tendina
  PRESELEZIONI "all": senza l'attributo selected vincerebbe la prima opzione,
  che e' la piu' permissiva.

## 0.26.0 - supporto PDF

Due modalita', perche' i due bisogni sono diversi:

- **PDF impaginato** - restituisce un PDF con pagine e posizioni al loro posto.
- **testo** - estrae il testo pagina per pagina e lo restituisce anonimizzato,
  senza impaginazione ma con ripristino completo.

Piu' il ripristino: gli pseudonimi tornano ai valori originali dentro il PDF.
Le posizioni restano quelle del documento anonimizzato - il file e' leggibile e
completo, non identico all'originale di partenza.

**Il testo originale viene rimosso davvero.** Coprire il testo con un
rettangolo NON lo rimuove: resta nel content stream e si recupera con un
copia-incolla. E' la fuga piu' classica dei documenti "redatti", e non e'
teorica: ci sono finiti tribunali e ministeri. Qui il testo viene eliminato e
lo pseudonimo scritto al suo posto, con il corpo del carattere ridotto quanto
serve perche' uno pseudonimo piu' lungo dell'originale non venga troncato.

**Il PDF prodotto viene riletto e verificato** prima della consegna: si
confronta cosa sarebbe dovuto sparire dalla pagina con cosa e' ancora
estraibile dal file. Il confronto avviene sulla pagina intera, non sui singoli
frammenti - un controllo fatto sugli stessi frammenti userebbe la stessa vista
limitata che avrebbe causato l'errore, e non lo vedrebbe mai. Se qualcosa
resta, l'operazione FALLISCE invece di consegnare un file che sembra
anonimizzato.

Trattati anche i punti dove il testo si nasconde: metadati del documento e XMP,
titoli dei segnalibri, contenuto delle annotazioni, valori dei campi modulo.
Autore, oggetto e parole chiave contengono un nome di persona per definizione
ma spesso come token isolato ("mrossi"), forma che nel testo libero non viene
mascherata - giustamente, sarebbe indistinguibile da una parola qualsiasi. Li
si presenta al motore con l'etichetta che gli compete, voce per voce negli
elenchi separati da virgola. I metadati vengono trattati DOPO le pagine, cosi'
un autore che compare anche nel testo riceve lo stesso pseudonimo.

**Allegati incorporati e JavaScript vengono rimossi**: non sono mascherabili e
lasciarli passare vanificherebbe tutto il resto. **Le pagine senza testo**
(scansioni) non sono analizzabili e vengono elencate esplicitamente: dirlo e'
l'unica cosa che impedisce di condividerle credendole sicure. Tetto sulle
pagine (LOGMASK_PDF_MAX_PAGES, 2000) contro i file costruiti per esaurire la
memoria.

NOTICE: il supporto PDF usa PyMuPDF, distribuito con licenza AGPL-3.0.
L'installazione e' per uso interno; distribuire LogMask a terzi richiederebbe
di pubblicarne il sorgente o di acquistare una licenza commerciale da Artifex.

## 0.25.3 - kit Exabeam sui nomi di campo veri

La 0.25.2 era costruita su un elenco di campi troncato alla lettera P, con le
famiglie src_*/user*/url ricavate per simmetria. Con il repository completo
sotto mano quelle ipotesi si sono rivelate in parte sbagliate: nel Common
Information Model NON esistono user_name, raw_log, rule_name, sha256 ne'
referer - i nomi veri sono user, description, rule_description, hash_sha256 e
referrer. Un kit che cerca campi inesistenti non maschera niente.

- **37 regole su nomi verificati**: 1165 campi di Fields_Descriptions.md piu'
  gli 88 metadati m_* di MetaFieldsMappings.md, dal repository ufficiale
  ExabeamLabs/CIMLibrary.
- **Copertura misurata, non stimata**: 703 campi CIM su 1165 classificati dal
  kit (60%), e ZERO campi identificativi lasciati in chiaro - il resto sono
  campi operativi che devono restare leggibili. Un test di regressione
  ricontrolla entrambe le liste.
- **I metadati che portano identita' hanno la precedenza.** m_winlog_user_name,
  m_winlog_user_domain, m_winlog_user_identifier, m_host, m_computer_name,
  m_agent_hostname vengono mascherati; la regola generica sui m_* non deve
  vincere e lasciarli leggibili. m_message e m_event_original sono testo.
- **Nuove coperture**: password nei campi (src_password, new_password,
  old_password), credenziali fisiche (badge_id, card_num, door_name,
  safe_name), posizione (location_*, remote_location_*), zone di rete e
  gruppi, identita' ricostruibili (sid_history, subject_sid, from_user_at),
  etichette asset e wazuh_manager.
- **Le zone di rete vengono mascherate.** "corporate", "ACMESPA-DMZ",
  "Milano-LAN": sono nomi scelti dal cliente e descrivono la sua topologia.

## 0.25.1 - Event Log Windows: le identita' dentro il messaggio

Una query XQL che proietta solo i campi dell'Event Log - _time,
agent_hostname, action_evtlog_event_id, action_evtlog_provider_name,
action_evtlog_message ed Event_Data da to_json_string(...) - non veniva
mascherata quasi per niente. Tre difetti sovrapposti.

- **Nessuna regola per la famiglia action_evtlog_*.** Con sei sole colonne un
  unico fingerprint non bastava a far scattare il kit Cortex, quindi neppure
  agent_hostname veniva classificato. Aggiunte le regole della famiglia
  (messaggio, data_fields, computer, user/domain/SID, indirizzi, ed event_id
  e metadati operativi tenuti leggibili) e due fingerprint dedicati.
- **action_evtlog_event_id veniva mascherato.** Finiva sul catch-all
  .*_(id)$ e diventava id-xxxx: un event id e' un codice di prodotto, non un
  identificativo del cliente, e mascherarlo rende il log illeggibile.
  Le regole della famiglia ora precedono i catch-all generici.
- **Le identita' nel testo restavano in chiaro.** Nel messaggio di un evento
  Windows l'utente e' dichiarato come "Account Name: mrossi", nel JSON
  serializzato come "SubjectUserName": "mrossi": forme che il motore non
  riconosceva, perche' cercava user=..., DOMINIO\utente o @dominio. Ora nome
  utente, dominio e workstation dichiarati come chiave/valore vengono
  pseudonimizzati ovunque compaiano - la stessa fuga esisteva in Elastic
  (message), Wazuh (full_log) e Splunk (_raw), quindi la regola non e' legata
  a Cortex. I segnaposto dei log Windows ("-", "N/A", "0x0", "%%1833",
  localhost, SYSTEM) restano intatti: mascherarli sarebbe solo rumore.
- **Una colonna sconosciuta che contiene prosa o un blob JSON non e' piu'
  "keep".** Un campo rinominato a piacere in query (Event_Data,
  to_json_string(...)) portava dentro nomi utente, host e IP e usciva intatto.
  Ora viene mascherato come testo libero: gli identificativi diventano
  pseudonimi e il resto resta leggibile. Hash, id base64 e valori opachi non
  sono toccati - il criterio richiede piu' parole separate da spazi oppure un
  JSON che parsifica davvero.

In Safe mode il messaggio ora viene mascherato invece che eliso per intero:
perdere il testo dell'evento significa perdere l'evidenza, mascherarlo la
conserva.

## 0.25.0 - partita IVA / VAT e indirizzi, italiani e inglesi

Due dati che in un documento o in un'e-mail identificano il cliente in modo
diretto e che finora uscivano in chiaro.

- **Nuova categoria DLP "Partita IVA / VAT"** (pseudonimo vat-*, reversibile).
  Riconosce la P.IVA italiana etichettata o nuda, con controllo di Luhn, e i
  numeri VAT europei con prefisso nazionale (IT, DE, FR, ES, NL, BE, AT, PT,
  GB, CHE). Il Luhn non e' un dettaglio: 11 cifre di seguito, nei log, sono un
  record id molto piu' spesso che una partita IVA.
- **Indirizzi fisici italiani e inglesi.** Prima si riconosceva soltanto
  "indirizzo: via ..." con i due punti e i soli tipi di strada italiani. Ora:
  etichette IT/EN (address, billing/shipping/mailing address, sede legale,
  residenza...) anche con punto o spazio al posto dei due punti; forme non
  etichettate italiane ("Viale Europa 22", "loc. Casalino 7") e inglesi
  ("123 Main Street", "1600 Pennsylvania Avenue"); caselle postali (PO Box,
  casella postale). Nuovi nomi campo riconosciuti: vat/piva/partita_iva,
  billing_address, shipping_address, address_line1...
- **Attenzione ai falsi positivi, che qui sono il rischio maggiore.** In un log
  SOC "via" e' quasi sempre la preposizione - "Potential RMM Tool Installation
  via Uncommon Process", "traffic via proxy 8080", "esfiltrazione via DNS" - e
  mascherarla distruggerebbe ogni descrizione di alert. Le forme non
  etichettate esigono quindi un nome proprio (iniziale maiuscola, non un
  acronimo) piu' un numero civico, e i suffissi inglesi ambigui (Way, Drive,
  Place, Court, Square...) sono ammessi solo con etichetta esplicita.
  Verificato su righe reali: gli oggetti SOC restano intatti.

## 0.24.1 - audit di sicurezza: limiti sul contenuto decompresso

Audit completo di autenticazione, sessioni, CSRF, isolamento tenant, crypto,
XSS, path traversal e gestione file binari. Impianto solido; due difetti DoS
trovati e corretti, entrambi legati alla differenza fra byte COMPRESSI (su cui
agiva il limite upload) e byte DECOMPRESSI.

- **Zip bomb nei .docx.** Un documento da 200 KB poteva espandersi a centinaia
  di MB in memoria (misurato: picco 613 MB); con il limite upload a 64 MB si
  poteva confezionare un OOM del container. Ora vale un tetto sul decompresso
  (LOGMASK_DOCX_MAX_UNCOMPRESSED, default 256 MiB) con doppio controllo:
  somma dichiarata nell'indice zip, poi budget sui byte realmente letti,
  perche' l'indice puo' mentire. Una bomba dichiarata viene respinta in
  0 ms con HTTP 413 e un messaggio chiaro.
- **Estrazione PST senza tetto su disco.** Un .pst artefatto puo' far
  scrivere a readpst molti piu' byte di quelli caricati, fino a esaurire il
  disco. Ora l'estratto e' limitato (LOGMASK_PST_MAX_EXTRACTED, default
  1 GiB) e l'eccesso produce un errore esplicito.

Verificato e gia' a posto (nessuna modifica): cookie di sessione HttpOnly +
SameSite=strict + CSRF double-submit; tenant validati con regex, resolve e
authz per utente (niente path traversal, nemmeno nell'editor kit); AES-GCM
con nonce casuale per riga e chiave master a permessi 0600; argon2 per le
password e rate-limit sul login; reset vault solo admin e con archiviazione;
tutti gli innerHTML della SPA passano da esc(); l'espansione di entita' XML
(billion laughs) e' bloccata da expat; gli errori non espongono traccia.

Da sapere, non corretto qui: il bind di default e' 0.0.0.0 (LAN) - per uso
solo locale impostare LOGMASK_BIND=127.0.0.1; il container gira come root
(mitigato dai limiti sopra); readpst e' codice C di terze parti - il timeout
e il tetto ne limitano gli effetti, non le vulnerabilita' interne.

## 0.24.0 - policy URL a scelta multipla, come per gli IP

Nuovo selettore "Policy URL" nel pannello principale e nelle card .docx/.pst:

- **maschera tutti gli URL** (default) - il comportamento storico: host
  pseudonimizzato, valori di query non riconoscibili elisi.
- **solo host del cliente** - vengono mascherati soltanto gli host
  riconducibili al cliente (IP interni o delle reti tenant, FQDN gia' nel
  vault, nomi cliente); il resto dell'URL resta leggibile. E' il comportamento
  gia' usato per i campi IOC, ora disponibile come scelta globale.
- **non anonimizzare URL** - l'URL resta com'e'.

Con un'eccezione NON negoziabile, identica in tutti e tre i modi: credenziali
nell'URL (user:password@) e valori di query dichiaratamente sensibili (token=,
password=, session=, ...) vengono comunque trattati. Sono segreti, non
indirizzi: la policy URL decide quanto dell'indirizzo resta leggibile, non se
far uscire un segreto.

I campi IOC (Malicious URL, Indicator) continuano a vincere sulla policy
globale: quel valore e' contenuto di detection e resta leggibile anche con
"maschera tutti gli URL". Un IP nudo fuori da un URL segue sempre la policy
IP, non quella URL. La scelta viene registrata nell'audit.

## 0.23.5 - bug hunt: IBAN e telefoni in chiaro nella prosa

Due fughe trovate cercando, non segnalate da nessuno.

- **IBAN seguito da una parola restava in chiaro.** Lo spazio opzionale del
  pattern faceva proseguire il match dentro le parole successive:
  "IT60...456 poi" diventava un unico candidato, il mod-97 falliva sul blob
  esteso e l'IBAN vero non veniva MAI riesaminato, perche' la scansione
  riparte dopo il match. In prosa italiana ("bonifico su DE89... eseguito")
  l'IBAN sfuggiva quasi sempre. Ora, se il match esteso non valida, si riprova
  togliendo una parola alla volta da destra. Corretto in entrambi i motori di
  scansione (residui e DLP).
- **"tel. +39 335 1234567" non veniva mai rilevato.** L'etichetta richiedeva
  ":" o "=": la forma con il punto - quella delle firme italiane - e i numeri
  internazionali nudi non erano riconosciuti. Ora bastano punto o spazio dopo
  l'etichetta, e la forma "+CC ..." con almeno 9 cifre viene riconosciuta
  anche senza etichetta. Fusi orari (+0200, +02:00), stringhe di versione e
  numeri corti restano fuori.
- Il round-trip resta completo: IBAN e telefoni sono pseudonimi reversibili
  (iban-*, tel-*) sul tenant che li ha generati.

## 0.23.4 - lo spazio pseudonimi IPv4 finiva dopo 253 indirizzi

- **Con «preserva subnet» l'anonimizzazione moriva a 253 IP.** L'ottetto host
  veniva costruito con ``s[0] or 1``: 255 valori possibili per 256 ottetti
  reali, quindi un export che toccava tutti gli host di una subnet - cioe' un
  qualunque export di una rete vera - esauriva lo spazio per forza. Ora sono
  256 su 256: una /24 completa entra sempre. Misurato: 65.536 indirizzi
  (256 reti x 256 host) senza una collisione, contro i 253 di prima.
- **64 tentativi non bastavano.** Il salt e' un sondaggio casuale in una
  tabella: con 255 posti su 256 occupati, 64 sondaggi falliscono nel 78% dei
  casi PUR ESSENDOCI un posto libero. Ora sono 4096, e il costo si paga solo
  quando lo spazio e' quasi pieno.
- **Il limite vero viene spiegato.** «Preserva subnet» assegna una /24
  sintetica a ogni /24 reale e in 198.18.0.0/15 ce ne stanno 256 per ambito:
  superata quella soglia si dice cosa fare (disattivare l'opzione o usare un
  tenant separato) invece di uscire con "RuntimeError". Non si ripiega su un
  altro schema di indirizzi: rischierebbe di assegnare lo stesso indirizzo
  sintetico a due indirizzi reali diversi, fondendo due macchine in silenzio -
  molto peggio di un errore esplicito.

## 0.23.3 - export Elastic Discover con byte NUL

- **Un NUL in una cella faceva cadere l'anonimizzazione.** Il modulo csv di
  Python solleva "line contains NUL" e si ferma. Gli export Discover di eventi
  Windows contengono spesso NUL - residui di stringhe UTF-16 dentro
  winlog.event_data - quindi un export perfettamente normale non era
  processabile. Il NUL non ha alcun valore analitico: ora viene tolto in
  lettura e l'elaborazione prosegue, con il resto della cella intatto.
- **Gli errori imprevisti ora sono leggibili.** Un'eccezione non gestita
  usciva come TESTO ("Internal Server Error"): il browser non riusciva a
  interpretarla e la pagina mostrava soltanto "risposta non valida dal
  backend", cioe' nessuna diagnosi ne' per chi usa lo strumento ne' per chi
  legge la segnalazione. Ora ogni errore esce in JSON con il tipo
  dell'eccezione e il comando per leggere i log; la traccia completa resta nei
  log del container e non viene mai esposta al browser.

## 0.23.2 - in prosa non si sostituiscono parole comuni

Un oggetto di e-mail reale usciva cosi':

    [SOC] Segnalazione di Sicurezza - [Heuristic Attribute] Possible Masquerading Behavior
    [usr-lry4sswj] Segnalazione di DOM-4wf4ihxo - [Heuristic Attribute] id-v24z3wsg2g7m Masquerading Behavior

- **Causa.** Lo sweep sostituisce nel testo tutti gli originali che il vault
  gia' conosce. Il vault di un cliente accumula, job dopo job, valori
  classificati male: "SOC", "Sicurezza", "Windows", "gruppo", "File" finiti
  sotto user o windomain perche' in QUEL log occupavano quella posizione. Su un
  altro log strutturato la sostituzione non fa danno - quel campo contiene
  davvero un'identita'. In un oggetto o in un paragrafo si': il testo diventa
  illeggibile, per ogni messaggio, in modo retroattivo e senza alcun errore.
  Lo sweep sui .docx c'era dalla 0.22.0 e sui .pst e' arrivato con la 0.23.0.
- **Correzione.** Nei percorsi in linguaggio naturale (documenti, oggetti e
  corpi di e-mail) si sostituiscono solo gli originali che non possono essere
  parole comuni: quelli con una cifra o un separatore (m.rossi, srv-01,
  DOMINIO\utente, tizio@dominio) e le identita' composte da piu' parole
  ("Mario Rossi"). I log strutturati non cambiano comportamento.
- **Costo accettato:** un identificativo tutto-lettere isolato ("mrossi")
  non viene piu' sostituito in prosa. Resta mascherato ovunque compaia in un
  campo; distruggere il testo e' un danno peggiore che mancarne un'occorrenza
  descrittiva.

## 0.23.1 - PST: una colonna che si legge davvero

- **Due colonne al posto di `body`.** `completeHeader` conserva il messaggio
  come esce dall'archivio - MIME, HTML, header dei messaggi inoltrati e
  citati: niente viene perso. `body` contiene lo stesso contenuto ridotto a
  testo leggibile: niente tag, niente entita' HTML, niente blocchi <style> o
  <script>, spaziatura normalizzata e celle di tabella separate. Le catene di
  risposta e i messaggi inoltrati restano: in un'analisi sono spesso la prova.
  Entrambe le colonne vengono anonimizzate.
- **Correzione: i messaggi in solo HTML uscivano senza corpo.** Un messaggio
  non multipart veniva letto solo se dichiarato text/plain; tutto il resto -
  cioe' la maggior parte della posta reale, che e' HTML - produceva un corpo
  vuoto. Il contenuto spariva dall'export senza nessun errore, quindi senza
  che nessuno se ne accorgesse.

## 0.23.0 - documenti e posta: solo pseudonimi, nessuna elisione

In un log l'elisione va bene: il campo sparisce e l'analisi prosegue. In un
.docx o in un .pst e' un danno netto - il file restituito perde il testo e il
ripristino non puo' ricostruirlo, perche' non c'e' niente da invertire.

- **Niente piu' [ELIDED] nei .docx e nei .pst.** Credenziali, chiavi private e
  URL con token venivano elisi: ora diventano pseudonimi. Anche
  LOGMASK_CLIENT_TERM_MODE=elide/label viene ignorato su questi due percorsi.
- **I segreti non entrano mai nel vault.** Una password diventa
  secret-xxxxxxxxxxxx, deterministico per tenant (stesso segreto -> stesso
  token, le occorrenze restano correlabili) ma mai memorizzato: irreversibile.
  Lo strumento non deve diventare un deposito di password e chiavi private dei
  clienti. Vale ovunque, non solo per documenti e posta.
- **Il .pst ora ha la stessa copertura del .docx**: sweep del vault (lo stesso
  nome resta lo stesso pseudonimo in tutti i messaggi) e riconoscimento dei
  nomi di persona nei corpi delle e-mail, che prima mancavano.
- **Correzione: e-mail mascherate mascherate due volte.** Un indirizzo
  riconosciuto come nome di persona diventa person-xxxx@yyyy.masked, forma che
  non era riconosciuta come pseudonimo nostro: veniva quindi ri-mascherata e
  il ripristino restituiva un altro pseudonimo invece dell'indirizzo vero.
- Il conteggio "non risolti" del ripristino .docx non considera piu'
  secret-* e CLIENT-*, irreversibili per scelta: facevano apparire incompleto
  ogni ripristino di un documento contenente credenziali o nomi cliente.

## 0.22.7 - il file aperto in Outlook / Word non fallisce piu' in silenzio

- **Causa del "Failed to fetch" sul PST.** Se l'archivio e' ancora aperto in
  Outlook, l'applicazione continua a riscriverlo mentre il browser lo carica:
  Chrome annulla l'upload (ERR_UPLOAD_FILE_CHANGED) e `fetch` fallisce con un
  generico "Failed to fetch". Il server non riceveva mai la richiesta, quindi
  nessun messaggio di errore poteva spiegare l'accaduto. Ora il file viene
  letto in memoria PRIMA dell'invio: l'upload parte da una copia stabile e,
  se la lettura non riesce, compare "il file e' ancora aperto in un'altra
  applicazione (Outlook / Word). Chiudila oppure lavora su una copia".
  Vale anche per i .docx tenuti aperti da Word, stesso identico guasto.
- **readpst senza job paralleli (-j 0).** Con i job attivi libpst estrae una
  quantita' di posta diversa a ogni esecuzione e, se un processo figlio muore,
  il padre esce comunque con stato 0: messaggi persi senza alcun errore. Per
  un'anonimizzazione la perdita silenziosa e' il guasto peggiore, perche'
  nessuno se ne accorge. Se una build di readpst non conosce -j, si riprova
  senza, invece di fallire.
- Nuovi test di regressione sull'estrazione PST: errore dello strumento
  riportato all'utente, timeout rispettato, -j 0 richiesto, ripiego corretto e
  un errore vero mai scambiato per un'opzione mancante.

## 0.22.6 - PST: niente piu' "Failed to fetch"

- **readpst girava senza timeout.** Con un PST protetto da password o
  danneggiato lo strumento poteva restare in attesa all'infinito: la richiesta
  non tornava mai e il browser mostrava "Failed to fetch", cioe' nessuna
  diagnosi. Ora c'e' un timeout (LOGMASK_READPST_TIMEOUT, 300s di default) e
  lo standard input e' chiuso, cosi' readpst non puo' restare in attesa di
  input.
- **L'errore vero di readpst ora arriva all'utente.** Prima qualsiasi problema
  diventava un generico "file .pst non valido?"; ora viene mostrato il motivo
  riportato dallo strumento (es. "unable to open PST file: encrypted or
  corrupt"), che dice se il file e' cifrato, corrotto o in un formato non
  supportato.
- **L'estrazione non blocca piu' il server.** readpst e' un sottoprocesso
  bloccante e girava dentro l'endpoint asincrono: per tutta la durata
  dell'estrazione l'intero event loop era fermo e nessun'altra richiesta
  veniva servita. Ora viene eseguito su un thread separato.

## 0.22.5

- **Gli errori erano invisibili a chi lavorava in fondo alla pagina.** Il
  riquadro degli errori sta in cima: usando le card PST o DOCX, che sono piu'
  in basso, un fallimento veniva segnalato fuori dallo schermo e la situazione
  si leggeva come "premo il pulsante e non succede niente". Ora il messaggio
  compare ANCHE accanto al pulsante premuto, evidenziato, e in tutti gli altri
  casi la pagina scorre sul riquadro.
- Tradotto lo stato "Estrazione e anonimizzazione in corso...", che restava in
  italiano anche con interfaccia in inglese.

## 0.22.4

- **Il nome del file scelto non compariva mai.** L'aggancio degli indicatori
  era finito DENTRO la funzione di cambio lingua, quindi si attivava solo
  premendo EN/IT: caricando un .pst o un .docx l'etichetta restava "nessun file
  selezionato" anche a caricamento avvenuto. Ora l'aggancio e' al livello
  giusto e scatta all'avvio della pagina.
- **Il traduttore azzerava l'etichetta.** Al cambio lingua il testo dinamico
  veniva riportato al valore originale, cancellando il nome del file. Gli
  elementi aggiornati a runtime sono ora marcati e il traduttore li salta.

## 0.22.3

- **La card PST spariva invece di spiegarsi.** Se readpst (pst-utils) non e'
  disponibile nel container, la card "Archivio Outlook .pst" veniva nascosta
  del tutto: l'utente non trovava la funzione e non aveva modo di sapere
  perche'. Il sintomo tipico era "carico il file e premendo Anonimizza non
  succede niente", perche' il .pst finiva nell'uploader di testo, che non lo
  gestisce. Ora la card resta VISIBILE, con il pulsante disattivato e una
  spiegazione: manca pst-utils, ricostruire il container.
- **L'uploader principale riconosce .pst e .docx.** Prima venivano letti come
  testo e fallivano con un errore generico. Ora l'utente riceve un messaggio
  che indica la card giusta, e la pagina ci scorre sopra.
- **Nessuna conferma che il file fosse stato caricato.** Accanto a "Scegli
  .pst" / "Scegli .docx" non compariva nulla dopo la selezione: non si capiva
  se il file fosse stato preso, il che rendeva indistinguibile "non ho
  caricato" da "ho caricato ma non parte". Ora compare nome e dimensione del
  file selezionato, evidenziati; se si annulla la selezione torna "nessun file
  selezionato". Vale per PST, DOCX e ripristino DOCX.
- Il backend rispondeva gia' correttamente (501 con messaggio esplicito):
  il difetto era solo nell'interfaccia.

## 0.22.2 - copertura identita'

- **AccountName restava in chiaro fuori dai kit Microsoft.** Il campo era
  mascherato da microsoft_defender e microsoft_sentinel ma NON dal catalogo
  generico: con Cortex, ECS o senza kit rilevato usciva leggibile (nel
  catalogo c'era "account_name" con underscore, non "accountname"). Aggiunte
  anche le varianti SamAccountName, TargetAccountName, SubjectAccountName,
  UserAccount, AccountUpn, AccountDisplayName.
- **URL SharePoint/OneDrive personali.** In
  "https://azienda-my.sharepoint.com/personal/sara_virgili_azienda_it/..." il
  segmento e' l'indirizzo e-mail con "_" al posto di "@" e ".": non veniva
  toccato perche' parte di un URL. Ora viene mascherato come identita'
  (reversibile, stesso token per la stessa persona), lasciando leggibile il
  resto del percorso.
- **Cartelle profilo utente.** "\\srv\profili\virgili_sara\" non veniva
  riconosciuta: "/" e "\\" erano trattati come confini che invalidano una
  coppia nome-cognome, mentre delimitano un SEGMENTO di percorso ed e' proprio
  li' che stanno le cartelle profilo. Restano bloccanti @ . - _ , che indicano
  un token piu' grande (e-mail, FQDN, nome composto), quindi e-mail, FQDN e
  percorsi di sistema continuano a essere gestiti dalle loro regole.

## 0.22.1

- **Il ripristino .docx dice ora se e' COMPLETO.** "66/791 paragrafi
  ripristinati" da solo non distingue "solo 66 paragrafi contenevano
  pseudonimi" (normale in un report, dove la maggior parte del testo e'
  narrativa) da "alcuni token sono rimasti indietro". Ora vengono riportati i
  token pseudonimo trovati, quelli risolti e quelli NON risolti; se ne restano
  compare un avviso esplicito, perche' la causa e' quasi sempre che
  appartengono a un altro tenant o che il vault e' stato azzerato.
- Il conteggio usa solo le forme INCONFONDIBILI di pseudonimo (usr-, host-,
  id-, cf-, person-, ...). Le forme IP e MAC sono escluse di proposito: un IP
  sintetico e' indistinguibile da un IP reale ripristinato (10.0.0.1 e' sia una
  forma legacy sia un indirizzo vero), e contarle segnalava "non risolti"
  fantasma su un ripristino perfettamente riuscito.

## 0.22.0

- **Documenti Word .docx (nuovo)**: si carica un .docx e si riceve un .docx
  anonimizzato, non un estratto di testo. Stili, tabelle, intestazioni, pie' di
  pagina, numerazione, immagini e ogni altra parte del pacchetto restano dove
  sono: cambia solo il testo.
- **Il punto delicato: Word spezza il testo su piu' "run".** Un valore
  sensibile puo' essere memorizzato diviso ("mario" + ".rossi") e una
  sostituzione run-per-run lo mancherebbe - un leak silenzioso. Per ogni
  paragrafo si anonimizza prima il testo COMPLETO (nessun valore sfugge), poi
  anche run per run: se i due risultati coincidono si scrive il per-run e la
  formattazione interna (grassetto su una parola, colori, link) resta
  identica; se differiscono - cioe' un valore era spezzato - il paragrafo viene
  ricomposto nel primo run. Si perde la formattazione DENTRO quel paragrafo,
  mai il mascheramento. Il conteggio dei paragrafi ricomposti e' riportato.
- Vengono trattati anche intestazioni, pie' di pagina, note, commenti, i
  metadati del documento (autore, ultimo salvataggio, societa') e i nomi autore
  delle revisioni: tutti posti dove finiscono nomi di persone.
- Immagini e oggetti incorporati NON possono essere anonimizzati: se presenti
  viene mostrato un avviso esplicito, vanno verificati a mano.
- Disponibile da UI (card "Documento Word .docx", il file anonimizzato viene
  scaricato direttamente) e da API (POST /api/anonymize-docx, multipart; il
  documento torna in base64). Registrato nell'audit come anonymize-docx.
- **Ripristino .docx**: si ricarica il documento anonimizzato e si riottiene un
  .docx con i valori originali, struttura e stili invariati (card dedicata in
  "Ripristina", API POST /api/deanonymize-docx). Richiede il permesso di
  reverse ed e' tracciato nell'audit come deanonymize-docx. Round-trip
  verificato: docx -> anonimizzato -> docx ripristinato.
- Verificato che restino intatti tabelle (con i loro stili), indici e campi
  TOC, numerazione ed elenchi, stili dei titoli, hyperlink, numbering.xml e
  styles.xml. Il contenuto DENTRO le tabelle e nelle intestazioni viene
  comunque mascherato.
- Aggiunto il caricamento di data/person_terms.txt anche lato applicazione
  (prima era solo CLI/opzione): serve a mascherare i cognomi da soli nei
  documenti, dove i nomi di persona sono molto piu' frequenti che nei log.

## 0.21.6 - fix di integrita'

- **Vault "avvelenato": parole tecniche sostituite da pseudonimi host.** Se per
  un mascheramento passato il vault del tenant contiene valori che NON sono
  nomi macchina - parole di prodotto ("Windows", "Management"), nomi di
  processo ("WmiPrvSE.exe") - lo sweep li sostituiva in OGNI job successivo:
  "Windows 10" -> "host-xxxx 10", "Windows Management Instrumentation" ->
  "host-xxxx host-yyyy Instrumentation", nomi dei processi figlio mascherati
  come hostname. Danno persistente (resta nel vault), retroattivo (colpisce
  export futuri) e silenzioso: degrada la tracciabilita' forense senza
  segnalare nulla.
- **Correzione**: nel testo vengono sostituiti solo gli originali che hanno la
  FORMA di un nome macchina - contengono un punto e non sono un nome file
  (.exe/.dll/.ps1/...), oppure contengono una cifra o un trattino
  (WKS0421, srv-sso, DC01, web01.corp.local). Una parola puramente alfabetica
  non viene mai sostituita nel testo: e' il caso in cui il danno supera il
  beneficio. Il mascheramento nel CAMPO dedicato resta invariato, cambia solo
  la sostituzione nel testo libero.
- La correzione ripara anche i vault gia' avvelenati: non serve azzerarli.
- Applicata a entrambe le strategie di sweep (dal testo e dal vault), con un
  test che verifica che diano lo stesso risultato.
- Limite noto e accettato: un hostname puramente alfabetico e senza dominio
  (es. "kraken") non viene piu' sostituito nel testo libero. Resta mascherato
  nei campi che lo dichiarano host e tramite host_terms.

## 0.21.5 - fix di integrita'

- **Corruzione degli ID evento base64.** Le convenzioni di naming host
  (host_terms) fanno match su SOTTOSTRINGHE: un glob come *DC* o WKS* combacia
  con pezzi casuali dentro un identificativo base64 e li sostituisce con uno
  pseudonimo host. Esempi riprodotti:
  "6bI/+VVDCxxxxzz==:124:119:255" -> "6bI/+host-ermiznfs==:124:119:255",
  "WKSabcdefghijklmnop==:408:..." -> "host-a7robey7==:408:...".
  Il guasto e' SILENZIOSO: nessun errore, solo un _id sbagliato che rompe la
  deduplicazione, la correlazione evento-alert e ogni join su quella chiave.
- **Correzione**: un hostname puo' contenere solo lettere, cifre, punto e
  trattino. Se il carattere adiacente al match e' "+", "/" o "=" il match e'
  dentro un blob opaco (base64, ID evento) e viene ignorato. Vale sia per le
  convenzioni host sia per l'euristica dei nomi macchina nudi.
- I nomi macchina veri restano mascherati regolarmente e reversibili
  (WKS0421, KWX03, SRVDC01, JVXSRV, XL-nord, YBW12, FZR99: 7/7 verificati),
  e il guard sugli hash IOC della 0.21.3 resta attivo.
- **IMPATTO**: export prodotti con versioni <= 0.21.4 da tenant con host_terms
  larghi possono avere _id corrotti. I valori non sono recuperabili
  dall'output; vanno rigenerati dalla sorgente.
- Nota trovata durante il fix: in Python "" e' sottostringa di qualsiasi
  stringa, quindi il controllo del contesto va sempre protetto sul caso
  inizio/fine valore - altrimenti un hostname che occupa tutto il campo non
  verrebbe mai mascherato. C'e' una regressione dedicata.

## 0.21.4

- **Ripristino CSV/TSV: la prima riga non veniva de-anonimizzata.** In reverse,
  csv_deanonymize copiava la prima riga tale e quale, assumendola un header di
  nomi colonna. Un export SENZA header - una singola cella (un solo IP) o una
  lista di pseudonimi - non veniva mai ripristinato: l'unica riga era
  considerata header e restituita invariata ("risolti 0"). Ora tutte le righe
  vengono reversate. Il reverse e' mirato - sostituisce solo i valori presenti
  nel vault del tenant - quindi i veri nomi colonna, che non sono pseudonimi,
  restano comunque intatti. Nessun impatto sul caso normale header+dati.

## 0.21.3 - fix di sicurezza/utilita'

- **IOC distrutti: hash trasformati in pseudonimi host-*.** Un valore hash
  (MD5/SHA1/SHA256) poteva essere mascherato come "host-xxxx", cancellando
  proprio il valore su cui si fa pivot in un'indagine. Nei titoli degli alert
  compariva "IOC (host-xxxx)" al posto dell'hash.
- **Causa**: le convenzioni di naming host (host_terms) venivano applicate
  anche ai valori hash. Un glob "contains" come *DC* combacia con qualsiasi
  SHA256 che contenga "dc" (entrambe cifre esadecimali) e lo maschera come
  host. E poiche' i host_terms si applicano anche alle colonne mantenute in
  chiaro (v0.10.23), veniva mangiato anche il campo sha256 gia' classificato
  keep. Un MD5 senza "dc" sopravviveva - la firma esatta del problema.
- **Correzione**: una stringa esadecimale lunga (>= 16 caratteri) e' un IOC,
  mai un hostname. Ora le convenzioni host e le euristiche host non la toccano
  in nessun caso. Gli host veri, anche se contengono "DC" (SRVDC01, ...),
  continuano a essere mascherati regolarmente.
- **IMPATTO**: export prodotti con versioni <= 0.21.2 da tenant con host_terms
  che includono glob "contains"/"suffix" (*DC*, *QNS, ...) possono avere hash
  IOC distrutti in host-*. I valori NON sono recuperabili dall'output (il
  mapping e' verso un pseudonimo host); vanno rigenerati dagli alert originali.
- Consiglio di configurazione: un glob "contains" come *DC* combacia con
  qualsiasi valore che contenga "DC" (non solo hash). Dove possibile ancorarlo
  (DC*, *-DC, o un pattern piu' specifico) per ridurre gli accostamenti
  accidentali su altri campi di testo.
- Regressione dedicata con il set di host_terms reale del tenant.

## 0.21.2 - fix di sicurezza

- **Leak: codice fiscale in chiaro dentro i path.** Un CF incastonato in un
  segmento di percorso o in un nome file
  ("...\\Temp\\tmpxq_VRGSRA76B55H501Z\\",
  "modulo-ferie-VRGSRA76B55H501Z-2026.pdf") usciva IN CHIARO mentre lo username
  nello stesso path era correttamente pseudonimizzato. Il CF e' un
  identificativo piu' forte dell'username, quindi il dato usciva
  re-identificabile. Causa: il confine di parola \b non scattava perche' il CF
  era attaccato a un prefisso con "_" (che e' un word-char).
- **Correzione**: il codice fiscale viene ora riconosciuto anche quando e'
  incastonato in un token piu' grande, con confini "non lettera-non cifra" (che
  abbracciano _ . - ~ / \\). Ogni match resta validato col carattere di
  controllo del CF, quindi i falsi positivi restano nulli: hash SHA256, GUID e
  path normali non vengono toccati (verificato). La correzione e' applicata a
  entrambe le regex CF (motore principale e modulo DLP).
- **Reversibilita' simmetrica**: anche la de-anonimizzazione riconosce ora uno
  pseudonimo incastonato in un token, cosi' un "cf-..." dentro un path torna al
  valore originale. I token normali (usr-, host-, ...) restano invariati.
- **IMPATTO**: gli export prodotti con versioni <= 0.21.1 possono contenere
  codici fiscali in chiaro se comparivano dentro path o nomi file (percorsi
  temporanei, allegati). Verificare e rigenerare gli export gia' condivisi.
- Regressione dedicata sul caso reale (CF nei path temporanei SecureConnector,
  nel nome file, reversibilita', assenza di falsi positivi su hash/GUID/path).

## 0.21.1

- **Export verticale "campo -> valore" ora classificato invece che eliso.**
  Un singolo alert esportato da molte console (Cortex XSIAM/XDR, ma non solo) e'
  una tabella a due colonne: nome_campo, valore, un campo per riga. Letto come
  CSV normale, l'header diventava la prima riga ("action", "DETECTED"), i nomi
  campo veri finivano fra i valori e il kit non veniva rilevato: risultato,
  l'intera colonna dei valori elisa e output inutile.
- Ora, se la prima colonna identifica un kit vendor, l'input viene ribaltato in
  orizzontale prima dell'anonimizzazione, cosi' ogni campo riceve la sua regola
  (IP/host/utenti mascherati, hash/severity/MITRE in chiaro). Sull'esempio
  Cortex reale: da "tutto eliso" a 1 solo campo eliso.
- Gli array espansi con indici ("mitre_technique_id_and_name" seguito da righe
  "0", "1", ...) vengono ricomposti nel campo di origine, non trattati come
  campi a se'.
- **Fail-closed**: se la prima colonna NON identifica un kit, non si tocca
  nulla e il flusso resta identico a prima. Un CSV normale a due colonne
  (user/count, timestamp/message, src_ip/dst_ip) non viene mai ribaltato -
  c'e' una regressione dedicata. La sicurezza non cambia in nessun caso: cambia
  solo l'utilita' quando il formato viene riconosciuto.
- Nel risultato compare un avviso quando il ribaltamento e' avvenuto, cosi'
  l'operazione e' trasparente; si puo' sempre forzare il kit per disattivarlo.

## 0.21.0

- **Azzeramento del vault di un tenant** (scheda Amministrazione, solo admin).
  Serve a chiudere un rapporto con un cliente, a ripartire puliti dopo una
  configurazione sbagliata o a soddisfare una richiesta di cancellazione.
- **Il vault viene ARCHIVIATO, non cancellato**: il file e' rinominato con un
  timestamp accanto all'originale (`vault-20260722-101530.db`). E' l'unica cosa
  che rende reversibili gli export gia' condivisi, quindi un azzeramento per
  sbaglio sarebbe irrimediabile: cosi' invece si recupera rimettendo il file al
  suo posto. La cancellazione definitiva resta una scelta manuale.
- Protezioni: permesso admin, CSRF, e va ripetuto il nome del tenant (in UI
  anche una conferma esplicita). L'operazione finisce nell'audit
  (`vault_reset`) con il nome del file archiviato.
- **I token non cambiano**: la derivazione e' deterministica sulla master key
  del tenant, quindi lo stesso valore produce lo stesso pseudonimo anche dopo
  l'azzeramento e la correlazione con gli export precedenti si mantiene. Si
  perde soltanto la reversibilita' (c'e' un test che lo verifica in entrambe
  le direzioni).
- NOTA: azzerare il vault non serve piu' per le prestazioni. Dalla 0.20.3 il
  costo di un job non dipende dal numero di identita' accumulate.

## 0.20.3 - prestazioni sui vault gia' popolati

- **Un evento singolo diventava lentissimo man mano che il vault si riempiva.**
  Il costo non dipendeva dall'input ma dal numero di identita' gia' presenti:
  lo sweep leggeva TUTTO il vault e decifrava ogni originale per cercarlo nel
  testo. Su un tenant usato da giorni, un evento Elastic/Sysmon da 2,4 KB
  passava da 0,02 s a 2,5 s (20.000 identita'). Era il limite gia' annotato
  nella 0.18.2, di cui avevo sottovalutato l'effetto pratico: su un input
  piccolo il costo del vault domina tutto.
  Misura, stesso evento da 2,4 KB:
  1.000 identita' 0,15 -> 0,02s | 5.000: 0,68 -> 0,02s |
  20.000: 2,53 -> 0,02s (120x) | 50.000: 0,03s.
- **Come**: la ricerca va dal TESTO al vault. Si tokenizza l'input e per ogni
  token si calcola il blind index (deterministico) cercandolo nel vault:
  nessun decrypt, costo legato al testo e non al cliente. Vengono provate
  anche le coppie adiacenti, per gli originali che contengono uno spazio.
- **Strategia adattiva**: le due vie hanno costi opposti - dal testo costa
  quanto il testo, dal vault costa quanto il vault. Un evento singolo su un
  vault grande conviene dal testo; un export da milioni di token su un vault
  piccolo conviene dal vault. Viene scelta la piu' economica, con risultato
  identico (c'e' un test che confronta le due). Senza questa scelta il bulk
  peggiorava del 20%.
- **Label breve degli host**: ora viene registrata nel vault al momento del
  mascheramento, invece di essere ricavata rileggendo tutto. Effetto
  collaterale positivo sulla reversibilita': `host-xxxx` risolve a `web01` e
  `host-xxxx.masked.local` a `web01.corp.local` - prima il token breve
  ricadeva sull'FQDN completo. La correlazione (radice condivisa) resta.

## 0.20.2 - bug hunt: concorrenza

- **Anonimizzazione interrotta con piu' scritture sullo stesso vault.** Fra il
  controllo di collisione e l'INSERT, un'altra connessione poteva inserire la
  stessa riga: l'INSERT falliva con `IntegrityError: UNIQUE constraint failed`
  e l'operazione abortiva. Con 8 scritture simultanee sullo stesso vault ne
  fallivano 7. I dati restavano integri (nessun duplicato, nessun pseudonimo
  condiviso), ma il lavoro si interrompeva.
  Scenari reali: la CLI che gira mentre l'app web anonimizza, oppure uvicorn
  avviato con `--workers` - il lock applicativo e' per-processo e non copre
  nessuno dei due casi.
- **Correzione**: la corsa viene assorbita. Se nel frattempo il valore e' stato
  mappato da un'altra connessione si riusa quel pseudonimo (identico, perche'
  la derivazione e' deterministica); se invece a collidere e' solo il
  pseudonimo si passa al salt successivo. Aggiunto anche un timeout di 30s sul
  lock SQLite, per non fallire con "database is locked" sotto scritture
  sovrapposte. Dopo il fix: 8 thread, 0 errori, vault integro, reverse corretto.
- **File grandi: misurati, nessun leak.** Throughput ~0,7 MB/s e memoria ~64 MB
  fissi (interprete + liste nomi) piu' ~12,7 MB per ogni MB di input. Un upload
  al limite di 64 MiB richiede quindi circa 900 MB di RAM e ~90 s: con
  `LOGMASK_MAX_FILE_BYTES` alzato conviene dare al container memoria adeguata,
  oppure usare la sessione multi-file (che elabora un file per volta) o la CLI.
  Nessun dato in chiaro sopravvive nemmeno sugli export grandi.

## 0.20.1 - bug hunt

- **Leak: nomi non riconosciuti con i separatori reali.** La regola accettava
  solo il singolo spazio, quindi restavano IN CHIARO i nomi scritti come li
  scrivono gli export veri:
  - `Mario\tRossi` - tab, quindi ogni file TSV (formato supportato);
  - `Mario  Rossi` e tabelle allineate a piu' spazi;
  - `Rossi, Mario` - la forma "Cognome, Nome" di AD/LDAP.
  Ora sono tutti coperti. Restano esclusi il ritorno a capo (un nome non si
  spezza su due righe) e i separatori ripetuti ("..").
- **La virgola non trasforma gli elenchi in persone.** Serve al formato AD, ma
  e' anche il separatore delle liste: una coppia con una virgola subito prima o
  subito dopo viene considerata elenco e lasciata stare. Senza questo,
  "Costa, Monti, Riva sono nodi" e "Rossi, Bianchi, Verdi in elenco" venivano
  mascherati a meta'.
- Verifica dopo il fix: 9/9 formati riconosciuti, 0 falsi positivi su 16 righe
  tecniche (elenchi, prodotti, messaggi di sistema), mascheramento reversibile
  anche con tab e virgola. Costo: -2% (1.757 -> 1.719 record/s).

## 0.20.0

- **Formati dei nomi.** Oltre a "Mario Rossi" ora vengono riconosciuti anche
  `mario.rossi`, `mario_rossi`, `mario-rossi` e gli ordini invertiti
  (`rossi.mario`), che sono le forme piu' comuni negli username dei log.
- **Nomi non capitalizzati.** "utente mario rossi ha effettuato accesso" viene
  mascherato: i log scrivono spesso i nomi in minuscolo. Perdendo il segnale
  della maiuscola serviva una protezione in piu', perche' le liste
  internazionali contengono parole funzionali inglesi come nomi/cognomi
  (the, not, will, may, mark): e' stata aggiunta una lista di ~250 stopword
  (parole funzionali IT/EN + termini SOC ricorrenti) che non formano mai una
  coppia. Misura su 15 righe di log tecniche: 2 falsi positivi senza stopword
  ("not mark", "mark the"), 0 con.
- **"mrossi" (iniziale + cognome)**: ammesso SOLO con person_terms, mai dalle
  liste generiche. E anche li' con una distinzione: la forma con separatore
  (`m.rossi`, `m_rossi`) basta a se stessa, mentre quella attaccata (`mrossi`)
  richiede una parola di contesto prima (user/utente/account/login/owner/da/by).
  Senza questo vincolo, un cliente con un dipendente di cognome "Costa" avrebbe
  visto spezzare parole comuni come "scosta", "amare", "discosta": c'e' una
  regressione dedicata.
- **Confini**: la coppia non viene toccata quando e' incastonata in un'e-mail,
  un FQDN o un percorso (`mario.rossi@azienda.it`, `mario.rossi.corp.local`,
  `/home/mario.rossi/`), dove decidono le regole piu' specifiche.
- Due bug trovati e corretti in fase di test: lo spazio era finito fra i
  caratteri che invalidano la coppia (non veniva mascherato piu' nulla), e il
  controllo dei confini scartava ogni coppia a inizio/fine riga perche' in
  Python la stringa vuota risulta contenuta in qualsiasi stringa.
- Verifica finale con le liste reali (168.081 nomi + 114.274 cognomi):
  0 falsi positivi su 15 righe tecniche, tutti i formati riconosciuti,
  mascheramento reversibile. Costo: -1,2% (1.778 -> 1.757 record/s).

## 0.19.1

- **Fix: nome preceduto da una parola capitalizzata non veniva rilevato.**
  La regola valutava le coppie con una sostituzione diretta, quindi in
  "Contattare Giulia Ferrari" la coppia (Contattare, Giulia) veniva esaminata,
  scartata e CONSUMATA: "Ferrari" non era piu' accoppiabile e il nome restava
  in chiaro. Caso frequentissimo (inizio frase, dopo un punto). Ora le coppie
  si valutano con una finestra scorrevole: su 7 frasi con nomi veri il
  rilevamento passa da 5/7 a 7/7.
- **Caricamento liste piu' robusto e flessibile**: i file in `data/persons/`
  vengono riconosciuti per prefisso (`nomi*`, `first_names*`, `names*`,
  `given*` / `cognomi*`, `last_names*`, `surname*`), cosi' si puo' mantenere il
  nome originale del file scaricato. Il parser scarta righe di prosa
  (disclaimer), markup HTML e binario che finiscono in coda ai file scaricati
  dalla pagina invece che dal raw, e voci in alfabeti non latini.
- Verificato con liste reali (168.081 nomi + 114.274 cognomi, caricate in
  0,32s): su 26 righe di log tecniche 0 falsi positivi - restano intatte
  "Chase Bank", "Access Denied for Service Account", "Windows Defender
  Antivirus", "Palo Alto Networks", "Group Policy Object", "on August 14",
  "this rule will block". Costo: -1,3% rispetto alla sola lista di base.
- Regressioni aggiunte per entrambi i casi (nome dopo parola capitalizzata,
  coppie tecniche/prodotto da non mascherare).

## 0.19.0

- **Rilevamento nomi di persona (nuovo)**. Dalle liste generiche viene
  mascherata SOLO la coppia "Nome Cognome" adiacente e capitalizzata (anche
  invertita, "Rossi Mario"), che diventa un unico token person-*, reversibile.
  Il token singolo NON viene mai mascherato da lista: e' la scelta che rende la
  regola utilizzabile. Verificato su righe di log reali: "this rule will
  block", "on August 14", "did not mark the alert", "Chase Bank", "La costa
  adriatica" restano intatte, mentre "Mario Rossi", "Wei Chen" e "Andrzej
  Kowalski" vengono mascherati - quindi funziona anche sui nomi stranieri,
  senza bisogno che la lingua sia nella lista.
- **`data/person_terms.txt` (nuovo)**: le persone REALMENTE esistenti nel
  tenant. Qui il token singolo viene mascherato, perche' non e' un'ipotesi
  statistica ma un nome che esiste in quel cliente. Popolabile dall'export
  AD/Entra. Anche via LOGMASK_PERSON_TERMS.
- Liste di serie in `persons/` (nomi.txt, cognomi.txt): una BASE ridotta di
  ~100+100 voci, italiane e non. Per estenderle basta mettere le liste
  complete in `data/persons/` (LOGMASK_PERSONS_DIR): i file vengono UNITI a
  quelli di serie, non sostituiti.
- Conteggio `person_name` nel report.
- NOTA sulle liste generiche: piu' sono grandi, piu' contengono voci che sono
  anche parole comuni. E' il motivo per cui restano confinate alla regola della
  coppia; il token singolo resta appannaggio di person_terms.

## 0.18.2

- **Scalabilita' dello sweep sui tenant grandi.** La 0.18.1 costruiva una
  regex con UN'ALTERNATIVA PER OGNI voce di vault: il tempo cresceva col
  numero di identita' del cliente anche su testi piccoli, e il vault cresce a
  ogni job. Su un tenant da decine di migliaia di dipendenti il costo sarebbe
  peggiorato nel tempo. Ora il testo viene tokenizzato una volta sola e ogni
  token risolto con una lookup O(1): il criterio di match e' identico (la
  classe di caratteri del token combacia con i vecchi confini), i valori con
  spazi restano gestiti a parte.
  Misura con 2.000 record e vault crescente:
  500 identita' 0,02 -> 0,015s | 2.000: 0,08 -> 0,035s |
  10.000: 0,44 -> 0,16s | 30.000: 1,37 -> 0,48s.
- **Limite residuo, documentato**: dei 0,48s a 30.000 identita', 0,40s sono il
  decrypt AES degli originali (per cercarli nel testo bisogna decifrarli).
  Questa parte cresce ancora col vault. La via d'uscita e' invertire la
  ricerca - dal token del testo al vault tramite blind index, senza decifrare
  nulla - e rende il costo indipendente dalla dimensione del cliente: e' un
  intervento a se', non incluso qui.

## 0.18.1 - fix di sicurezza

- **Leak: identita' in chiaro nel testo grezzo.** Un utente mascherato nel suo
  campo dedicato (`user.name` -> `usr-...`) restava LEGGIBILE dentro `message`
  e simili, nello stesso documento e in quelli successivi. Sui campi
  descrittivi lo sweep del vault era disattivato del tutto, per non far
  corrompere il testo naturale da una parola comune finita nel vault per un
  falso positivo storico.
- **Correzione**: sweep finale sull'output completo del job, limitato ai kind
  IDENTITA' (user, email). Gli altri kind (fqdn/opaque) restano esclusi dal
  testo descrittivo, quindi il caso che la disattivazione proteggeva (es.
  "behavior" che diventa un host) non si ripresenta: c'e' una regressione
  dedicata. Lo sweep per-campo sui descrittivi resta spento com'era.
- **Indipendente da ordine e nome del campo.** Agendo sull'output completo,
  copre anche il campo grezzo che PRECEDE il proprio campo identita' (l'ordine
  delle chiavi JSON non e' garantito; in NDJSON l'identita' puo' comparire su
  un record successivo) e vale per QUALSIASI campo di testo grezzo senza
  mantenerne un elenco: verificato su `_raw` (Splunk), `full_log` e
  `previous_log` (Wazuh), `raw_message` (Cortex), `event.original` e `message`
  (ECS), `displayMessage` (Okta).
- `sweep_known` riscritta in UNA passata con alternation invece di una re.sub
  per voce di vault: il costo era O(voci x lunghezza_testo).
- **Costo: -4%** (1.918 -> 1.836 record/s su 4.000 record ECS).
- **IMPATTO**: gli export prodotti con versioni <= 0.18.0 possono contenere
  username o e-mail in chiaro nei campi di testo grezzo, anche quando lo stesso
  valore risulta mascherato nel proprio campo. Verificare e rigenerare gli
  export gia' condivisi.
- Limite invariato e voluto: un nome che non compare MAI in un campo identita'
  non e' riconoscibile e resta in chiaro (serve un campo/label esplicita o
  host_terms per le convenzioni di naming).

## 0.18.0

Due allineamenti fra il percorso "testo libero" e quello "strutturato", che
finora si comportavano in modo opposto sugli stessi dati.

- **Fail-open chiuso: passa solo cio' che riconosciamo come nostro.** Una
  stringa con la FORMA di uno pseudonimo (`host-abcd1234`, `usr-...`, `id-...`)
  non e' di per se' sicura: un host del cliente potrebbe chiamarsi davvero
  cosi', o un identificativo vendor puo' avere quella forma. Prima veniva
  lasciata passare in chiaro. Ora passa invariata solo se il token e' presente
  nel vault DI QUEL TENANT; altrimenti viene pseudonimizzata come qualsiasi
  altro dato. I token di un altro tenant non sono piu' considerati "gia'
  sicuri".
- **Output idempotente.** Ri-anonimizzare un export gia' trattato non cambia
  piu' i token (prima cambiavano tutti: chi aveva ricevuto la versione
  precedente non riusciva piu' a correlare, e il vault si riempiva di
  mappature pseudonimo->pseudonimo).
- **Stesso host = stesso token.** Un asset che compare sia come nome corto
  (`web01`) sia come FQDN (`web01.corp.local`) ora riceve un unico token anche
  nelle colonne, non solo nel testo libero. Se la stessa label esiste in PIU'
  domini (`web01.milano.local` e `web01.roma.local`) l'informazione per
  decidere non esiste nel dato: LogMask non indovina, il nome corto prende un
  token proprio e il caso viene contato come ambiguo. Questo elimina anche la
  vecchia risoluzione arbitraria del testo libero, che poteva attribuire
  silenziosamente il nome corto all'host sbagliato.
  Nota: il reverse di un nome corto collegato restituisce l'FQDN completo,
  cioe' l'entita' canonica.
- **Costo: -7% di throughput** (2.065 -> 1.918 record/s su 4.000 record ECS),
  dovuto al pre-pass che indicizza gli FQDN del documento e alla verifica dei
  token nel vault. Il pre-pass e' solo in-job: l'output resta determinato dal
  solo input, senza dipendere dalla storia del vault.

## 0.17.0

- **Prestazioni: ~+10% di throughput**, senza modifiche al modello di sicurezza
  (misurato su 4.000 record ECS: 1.869 -> 2.065 record/s). Due sprechi rimossi,
  individuati col profiler:
  - `normalize_dlp_policy` veniva ricalcolata per OGNI valore e per ogni testo
    scrubbato (4 volte per record) pur dipendendo solo dalla policy del job:
    ora una policy gia' validata viene riconosciuta in O(1). La validazione
    degli input esterni (API/CLI) resta piena e invariata.
  - il parsing degli IP (`is_internal_ip`, `is_tenant_ip`) rifaceva il lavoro
    per ogni occorrenza dello stesso indirizzo: ora e' memoizzato (cache
    limitata, solo in memoria, per la durata del processo).
- **Nota onesta sui limiti**: il grosso del tempo residuo (~36%) e' nel vault —
  ogni valore NUOVO costa SELECT + SELECT + INSERT + AES + HMAC. Ridurlo
  richiede un refactor del componente piu' critico per reversibilita' e
  unicita' degli pseudonimi: non e' incluso qui di proposito, va affrontato a
  parte con test dedicati. Anche `PRAGMA journal_mode=WAL` e' stato provato e
  scartato: nessun guadagno misurabile, quindi nessuna modifica lasciata nel
  vault senza beneficio dimostrato.
- Regressioni aggiunte a protezione delle ottimizzazioni: il fast-path non puo'
  aggirare la validazione della policy, la cache IP non altera le decisioni
  (interni/pubblici/tenant/valori non validi) e il mascheramento resta
  identico e reversibile.

## 0.16.1 - fix di sicurezza

- **Leak: nomi host in chiaro negli export Elasticsearch.** In un hit ES i campi
  identita' che dipendono da una regola ^-ancorata del kit (`host.name`,
  `agent.name`, `observer.name`, `winlog.computer_name`, `dns.question.name`)
  restavano IN CHIARO, sia in `_source` che nel blocco `fields`. Causa: i
  wrapper di trasporto `_source.` / `fields.` venivano provati per primi nel
  matching e catturati dalla regola catch-all `keep` del kit, prima che venisse
  tentata la forma logica del campo. I campi coperti da regole non ancorate
  (`.*\.hostname$`, `.*\.id$`, `.*\.domain$`) mascheravano comunque: da qui
  anche l'incoerenza fra `_source` e `fields` sullo stesso campo. Ora i due
  wrapper vengono spogliati PRIMA del matching (non hanno significato
  semantico e nessun kit vi si appoggia); i prefissi con semantica come
  `winlog.*` restano invariati.
- **IMPATTO**: gli export Elastic/ECS anonimizzati con le versioni <= 0.16.0
  possono contenere nomi host/asset del cliente in chiaro. Verificare gli
  export gia' condivisi e rigenerarli con questa versione.
- Regressione dedicata su forma reale di hit ES (`_source` + `fields`):
  nessun nome asset in chiaro, `_source` e `fields` coerenti, campi
  operativi (url.path, agent.type) invariati.

## 0.16.0

- **Interfaccia bilingue IT/EN (nuovo)**: pulsante EN/IT nell'header (anche
  nella pagina di login). Tradotta tutta la dashboard: schede, card, opzioni,
  placeholder, tooltip, report di copertura, verifiche, sessioni multi-file,
  dry-run kit, kit studio, messaggi di stato ed errori lato client. La scelta
  resta salvata nel browser (localStorage) e il cambio e' istantaneo, senza
  reload. Copertura verificata automaticamente: 0 stringhe statiche senza
  traduzione, 109 chiavi dinamiche tutte risolte. Restano in italiano: i
  messaggi di errore restituiti dal server, i commenti dei template YAML
  generati e il template operativo (contenuto di lavoro, non interfaccia).

## 0.15.0

- **Otto nuovi vendor kit** (ora 20 in totale): CrowdStrike Falcon
  (console + FDR), Wazuh/OSSEC (alert annidati), Microsoft Sentinel (export
  KQL: SecurityEvent/SecurityAlert), Splunk CIM (_raw incluso), Okta System
  Log, Proofpoint TAP, Zscaler ZIA e AWS CloudTrail. Per ognuno: rilevamento
  automatico, copertura completa dell'header tipico (0 campi elisi) e IOC
  preservati (hash, URL, file, regole); identita', host, IP e ID
  tenant/account mascherati.
- **Export Microsoft in italiano E inglese**: i portali Microsoft cambiano le
  intestazioni con la lingua. Il kit Entra ID ora copre anche gli export
  inglesi di sign-in e audit ("Username", "IP address", "Actor user principal
  name", ...) oltre a quelli italiani gia' supportati; il kit Defender copre
  gli export delle code avvisi/incidenti del portale in entrambe le lingue
  ("Impacted assets"/"Asset interessati" -> scrub, "Assigned to"/"Assegnato a"
  -> e-mail mascherata, gravita'/stati -> in chiaro).
- **Fix "session opened."**: le descrizioni in prosa tipo "Login session
  opened." (PAM/Wazuh) non vengono piu' mutilate in "session [ELIDED]". Il
  guard vale SOLO per la chiave nuda "session" seguita da una parola minuscola
  senza cifre: session token veri, password, cookie e ogni assegnazione con
  ":" o "=" restano mascherati come prima (fail-closed).

## 0.14.0

- **Kit studio in dashboard (nuovo)**: nuova scheda "Kit" (solo admin) per
  gestire i vendor kit senza toccare il filesystem. Lista di tutti i kit —
  di serie (sola lettura, "Apri copia" per estenderli/sostituirli) e utente
  (con stato: ok / avvisi / errori) — ed editor YAML con Template, Valida,
  Salva ed Elimina. Il salvataggio e' fail-closed: YAML malformato o senza id
  valido viene rifiutato (non scritto), le regole non valide vengono segnalate
  come avvisi con il motivo (action/kind sbagliati, regex non sicura). Ogni
  salvataggio ricarica il registro a caldo (subito attivo su anonimizzazione e
  dry-run) e viene tracciato nell'audit (kit_write/kit_delete). API:
  GET/PUT/DELETE /api/kits/files[/nome], GET /api/kits/bundled/<id>,
  POST /api/kits/validate. Nomi file confinati alla cartella kit utente
  (niente path traversal); i kit di serie non sono modificabili.

## 0.13.1

- **Preparazione pubblicazione**: aggiunti `LICENSE` (MIT, (c) 2026 Mattia
  Papini) e `SECURITY.md` (threat model: cosa protegge, cosa no, come segnalare
  vulnerabilita' — mai con log reali). README: sezione "Limiti attuali"
  aggiornata (PST solo estrazione, priorita' regole kit utente, progetto non
  auditato) e nuova sezione "Licenza e sicurezza". Nessun cambiamento
  funzionale.

## 0.13.0

- **Test kit in dashboard (dry-run, nuovo)**: nuova card "Test kit" nella
  pagina di anonimizzazione. Incolli i nomi colonna di un export (nessun valore
  viene letto o salvato) e vedi: kit rilevato con confidenza, tabella per campo
  con azione/kind/origine, e quali campi la Safe mode eliderebbe. Per i campi
  FUORI kit viene generata una proposta YAML pronta da copiare in
  data/kits/<kit>_extra.yaml (default prudente mask/opaque, con TODO da
  rivedere). Nel report post-anonimizzazione il box "campi fuori kit" ha ora il
  bottone "Proponi regole YAML" che precompila e lancia l'analisi con l'header
  appena processato. Chiude il giro: campi fuori kit -> regola -> hot reload.

## 0.12.2

- **Template per la config runtime**: aggiunti `examples/data/*.txt.example`
  (client_terms, host_terms, tenant_networks, keep_fields) con contenuto
  fittizio e formato documentato, sul modello di `.env.example`. I file reali
  vivono solo in `data/` (gitignorata, mai nelle release); nel README la nuova
  sezione "Config runtime in data/". Nessun cambiamento funzionale.

## 0.12.1

- **Bonifica sorgenti (pre-pubblicazione)**: tutti gli esempi e le fixture di
  test che usavano nomi reali di clienti sono stati sostituiti con nomi fittizi
  (ClienteAlfa/Beta/Gamma, AcmeCalcio, Ente Esempio; tenant di esempio
  "acme"/"globex"). Nessun cambiamento funzionale. La configurazione runtime in
  data/ (client_terms.txt ecc.) non e toccata e resta fuori da ogni release.

## 0.12.0

- **Kit in YAML + kit utente (nuovo)**: tutti i vendor kit sono stati migrati da
  Python a file YAML in ./kits (comportamento identico, stesse regole, nessuna
  regola persa). Per aggiungere o modificare un kit non serve piu toccare il
  codice: basta mettere un file *.yaml nella cartella dei kit utente
  (LOGMASK_KITS_DIR, default <LOGMASK_DATA>/kits). Un kit utente puo AGGIUNGERne
  uno nuovo, oppure ESTENDERE o SOSTITUIRE un kit di serie (mode: extend|replace);
  le regole utente hanno priorita. I file vengono ricaricati a caldo quando
  cambiano su disco. Validazione fail-safe: azioni/kind non validi vengono
  scartati, i pattern pericolosi (ReDoS) rifiutati, lo YAML malformato saltato
  senza mai bloccare il rilevamento.
- **Dry-run kit (anteprima, nessun dato mascherato)**: si puo classificare un
  header PRIMA di anonimizzare e vedere quale kit viene rilevato, azione/kind per
  campo e quali campi la modalita Safe eliderebbe. Da CLI
  (logmask test-kit "col1,col2,..." [--catalog fam]) e da API
  (POST /api/kit-dry-run, {columns, family?, safe_mode?}). Nessun valore viene
  letto o mascherato: solo i nomi delle colonne.

## 0.11.0

- **Ingest Outlook .pst (nuovo)**: si puo caricare un archivio .pst e ottenere i
  messaggi anonimizzati in NDJSON/CSV (una riga per messaggio). L'estrazione usa
  readpst (pacchetto pst-utils, aggiunto all'immagine Docker); la RISCRITTURA di
  un PST non e supportata (nessun writer open-source affidabile). Per ogni
  messaggio: mittente/destinatari ridotti alle sole e-mail (i display name
  vengono SCARTATI, non solo mascherati - niente fuga di "Mario Rossi"), oggetto
  e corpo scrubbati come testo (e-mail costanti per dominio, IP/host/message-id/
  nomi cliente mascherati), data/cartella/flag allegati come metadato. Lo stesso
  mittente e lo stesso pseudonimo in tutti i messaggi (vault del tenant),
  reversibile. Disponibile da UI (se pst-utils presente), da API
  (POST /api/anonymize-pst, multipart) e da CLI
  (logmask anonymize-pst file.pst --tenant T --format ndjson|csv). Limite
  dimensione = LOGMASK_MAX_FILE_BYTES.

## 0.10.32

- **Dominio e-mail costante per dominio**: prima il dominio mascherato di
  un'e-mail era derivato dall'intera e-mail, quindi due indirizzi sullo stesso
  dominio (mario@contoso.com, anna@contoso.com) ricevevano domini mascherati
  DIVERSI. Ora il dominio mascherato e derivato dal solo dominio: tutti gli
  indirizzi @contoso.com condividono lo stesso dominio mascherato
  (*@abc123.masked), mentre la parte locale resta unica per indirizzo. Si puo
  quindi vedere quali e-mail appartengono allo stesso dominio senza rivelarlo.
  Reversibilita invariata (l'e-mail completa resta nel vault). Coerente con il
  mascheramento UPN (user@AZIENDA), gia costante per dominio.

## 0.10.31

- **Export Microsoft Graph / O365 email (msft_o365_emails_raw) rilevato**: i
  campi mail (from, toRecipients, ccRecipients, internetMessageHeaders,
  mailboxOwner, inferenceClassification, hasAttachments, n) non erano
  riconosciuti e finivano quasi tutti [ELIDED] (comprese le e-mail). Aggiunti i
  fingerprint Graph-mail: ora rileva Cortex e classifica -- mittente/destinatari
  e header grezzi scrubbati come testo (e-mail, IP, host e message-id
  mascherati), mailboxOwner mascherato come e-mail, enum/booleani e conteggio n
  in chiaro. Zero campi elisi. Nota: nei blob JSON grezzi di Graph i display
  name dei destinatari ("name":"...") restano visibili -- le e-mail sono
  mascherate ma i nomi no; se serve azzerarli, questi campi si possono impostare
  come opaque.

## 0.10.30

- **Export Cortex "authentication_story" rilevato**: un export con auth_service,
  auth_identity, auth_client, n non veniva riconosciuto (score 3) e cadeva nel
  generico, dove auth_service/auth_client/n finivano [ELIDED] e auth_identity,
  trattato come e-mail, elideva le 91 identita in forma DOMINIO\utente (non
  e-mail). Aggiunti i fingerprint auth_service/auth_client: ora rileva Cortex,
  auth_identity e mascherato come utente (gestisce e-mail, UPN e DOMINIO\utente
  senza fallire), auth_service/auth_client restano enum leggibili e n (alias di
  conteggio XQL) resta in chiaro. Zero campi elisi.

## 0.10.29

- **Export xdr_data piccoli (auth/actor) ora rilevati -- chiusa una fuga di
  username**: un export Cortex con poche colonne (_time, auth_identity,
  dst_actor_effective_username, action_remote_ip, action_country, _product,
  _vendor, insert_timestamp) non veniva riconosciuto (score 0) e cadeva nel
  generico: auth_identity finiva [ELIDED] e -- soprattutto --
  dst_actor_effective_username (uno username) restava IN CHIARO. Aggiunti i
  fingerprint per questi campi: ora l'export rileva Cortex e le identita sono
  mascherate (auth_identity / *_actor_effective_username -> utente,
  action_remote_ip -> IP), mentre i metadati (action_country, _product, _vendor,
  timestamp) restano leggibili. Zero campi elisi.

## 0.10.28

- **Prestazioni: anonimizzazione molto piu veloce su file grandi**. Due
  ottimizzazioni, nessun cambiamento di output:
  - Cache di classificazione per-colonna (JSON/NDJSON/structured): la decisione
    del campo veniva ricalcolata per OGNI cella (migliaia di valutazioni delle
    regole kit per riga). Ora e calcolata una volta per colonna. Export 500x200
    da ~15,5s a ~5,5s.
  - Cache passthrough (tutti i formati): i valori che una colonna keep o text
    lascia INVARIATI (enum, timestamp, numeri, ripetuti migliaia di volte) ora
    costano O(1) sulle ripetizioni. Sul percorso TSV/CSV un export 703x200 passa
    da diversi secondi a ~0,8s. Solo le celle invariate sono cache-ate: le
    statistiche restano corrette e i valori mascherati restano mascherati.

## 0.10.27

- **Kit Elastic ECS esteso: schemi nidificati e arricchimenti**: gli export ECS
  con AWS Security Hub nidificato (json.*), O365 audit (o365audit.*) e campi
  custom (enrichment.*, organization.*, watcher.*, cloud.*, device.*, email.*,
  source.ip2proxy.*, ...) prima lasciavano decine/centinaia di campi [ELIDED],
  timestamp compresi. Ora: le famiglie identificative del cliente sono mascherate
  (customer_prefix/organization_name/company_name/tenant_name -> opaque,
  group/device/instance name -> endpoint, nomi/percorsi file, oggetti e mittenti
  e-mail, posizione/ruolo utente, resource_arn/name -> testo); ID -> opaque;
  timestamp ed enum operativi (cloud, geo, ASN, O365 audit, compliance) in chiaro.
  source.as.organization.name (ISP, non il cliente) resta in chiaro. Un campo
  nidificato (con namespace x.y) in un export ECS riconosciuto va di default a
  keep; un campo sconosciuto SENZA namespace resta fail-closed ([ELIDED]). Zero
  campi elisi sugli schemi di riferimento.

## 0.10.26

- **Nuovo kit Microsoft Entra ID (Azure AD)**: log di accesso (sign-in) e di
  audit, inclusi gli export con intestazioni in italiano ("Data (UTC)",
  "Utente", "Nome utente", "Metodo di autenticazione", "Accesso condizionale",
  "Risultato dell'autenticazione a piu fattori", "Actor/Target..."). Prima non
  venivano riconosciuti da nessun kit e finivano quasi tutti [ELIDED] (inclusi
  i timestamp). Ora: rilevamento automatico dei tre formati; timestamp ed enum
  operativi (stato, metodo, browser, SO, localita, ASN, latenza, conditional
  access, tipo utente/token, ...) tenuti in chiaro; identita mascherate --
  Utente/*DisplayName come utente, Nome utente/*UserPrincipalName come e-mail,
  IP mascherati, ID come opaque, nome tenant/entita servizio come opaque; valori
  liberi (*NewValue/*OldValue, Motivo dell'errore, Dettagli, AdditionalDetail
  *Value, Applicazione, Risorsa) scrubbati come testo. Zero campi elisi sugli
  schemi di riferimento.

## 0.10.25

- **UPN / e-mail con dominio a etichetta singola (senza TLD pubblico)**: valori
  come `user125@ClienteGamma` o `jdoe@INTERNAL` ora vengono riconosciuti e
  pseudonimizzati completamente, invece di lasciare in chiaro la parte locale
  (`user125@CLIENT-xxxx`) o finire `[ELIDED]` in Safe mode (i "2 valori elisi").
  La parte locale diventa `usr-xxxx` (reversibile); il dominio, se e un nome
  cliente, diventa il token `CLIENT-xxxxxx` (visibile, irreversibile), altrimenti
  un host mascherato reversibile. Vale in testo libero e in tutte le colonne
  (comprese quelle `keep`). Le e-mail con TLD reale restano invariate
  (`usr-xxxx@yyyy.masked`). Il reverse recupera la parte locale (e l'host non
  cliente); il token cliente resta non reversibile.

## 0.10.24

- **host_terms: jolly `*` in qualsiasi posizione**: le convenzioni di naming
  host ora accettano `*` come jolly ovunque, non solo come prefisso finale.
  Funzionano `srv-*` (prefisso), `*QNS` (suffisso), `KDA*QNS` (in mezzo),
  `*.WORKGROUP` e `*ZCORP.DOM` (suffisso di dominio) e combinazioni. Prima
  solo `prefisso*` era valido: voci come `*QNS`, `*.WORKGROUP`,
  `*ZCORP.DOM`, `KDA*QNS` venivano trattate come letterali e non
  mascheravano nulla. Un `*` isolato viene ignorato (non maschera tutto); i
  nomi letterali senza `*` restano invariati. Nota: le convenzioni configurate
  coprono anche i nomi con numeri lunghi (es. `WKS04417`) che l'euristica
  automatica -- limitata a 1-3 cifre dopo il prefisso -- non rileva da sola.

## 0.10.23

- **Host terms applicati anche ai campi tenuti in chiaro**: le convenzioni di
  naming host configurate (`host_terms` / `data/host_terms.txt`, es. `XWS*`,
  `srv-*`, `KWX*`) prima venivano applicate solo al testo libero e alle
  colonne di tipo testo. Ora un nome macchina che corrisponde a una convenzione
  viene pseudonimizzato (host reversibile) anche quando compare in una colonna
  `keep` — inclusi i campi tenuti in chiaro dai kit vendor. Stessa cosa per i
  nomi cliente (`client_terms`): ora vengono sostituiti con il token generico
  anche nelle colonne `keep`, chiudendo una possibile fuga in modalita non-Safe
  o nei campi vendor-keep. L'euristica "fuzzy" (dc01, server-sso senza
  configurazione) resta limitata al testo libero per evitare falsi positivi
  sugli enum. Config invariata: un valore per riga, prefisso con `*`.

## 0.10.22

- **Kit Bitdefender GravityZone — export console (nomi visualizzati)**: oltre
  allo schema API a punti (v0.10.14), il kit ora riconosce e classifica anche
  l'export della console con intestazioni leggibili ("Action taken",
  "Threat name", "SHA256", "Endpoint name", "Command-line", "Detecting
  technology", "Fileless attack", "Container host", ...). Rilevamento
  automatico via nuovi fingerprint. IOC (`SHA256`, `Threat name`) ed enum
  operativi (azione, tipo minaccia, moduli, tecnologia, tipo endpoint,
  timestamp) tenuti in chiaro; `Endpoint name`/`Container host` mascherati;
  `Company` (cliente MSP) mascherato come opaque; `Command-line`, `Tag`,
  `Details`, `Eventi` scrubbati come testo; `IP`/`User` mascherati. Zero campi
  elisi sui 15 segnalati (copertura vendor 100%).

## 0.10.21

- **Nomi cliente: pseudonimo generico invece di `[ELIDED]`**: quando un nome
  configurato in `client_terms.txt` compare nel testo, non viene piu eliso ma
  sostituito con un token generico deterministico `CLIENT-xxxxxx`. Il testo
  resta leggibile, clienti diversi restano distinguibili (token diverso), lo
  stesso cliente ha sempre lo stesso token (anche tra varianti "AcmeCalcio" /
  "Acme Calcio" / "acme-calcio"). Il token e derivato dalla chiave del tenant
  (clienti uguali -> token diversi su tenant diversi) e **irreversibile**: non
  entra nel vault, quindi il nome reale non e recuperabile e la lista di nomi
  noti non e forzabile senza la chiave del tenant. Configurabile via
  `LOGMASK_CLIENT_TERM_MODE`: `pseudonymize` (default) | `elide` (vecchio
  comportamento `[ELIDED]`) | `label` (etichetta fissa `LOGMASK_CLIENT_TERM_LABEL`,
  default `[CLIENTE]`).

## 0.10.20

- **Famiglia file/processo xdr_data non piu elisa**: `action_file_size` (e i
  contatori numerici `*_size`/`*_bytes`/`*_length`, upload/download, pacchetti)
  restano leggibili come metadato analitico. Coperti anche i nomi di processo
  (`actor_process_image_name`, `*_process_image_name`, `*_process_name`) tenuti
  in chiaro come IOC, e i nomi file (`action_file_name`, `*_file_name`)
  scrubbati come testo ma sempre visibili (decisione D3). I path immagine
  (`*_process_image_path`) restano testo con l'utente mascherato. Nessuna
  regressione: `image_name`/`container_name` restano opaque, identita/host/IP
  invariati.

## 0.10.19

- **Export `saas_audit_logs` completo (schema XDM esteso)**: classificati gli
  ultimi campi che finivano `[ELIDED]` nell'export completo. `domain_name`
  (dominio del tenant) mascherato come FQDN reversibile; `identity_normalized`
  mascherato come utente; `backtrace_identities` scrubbato per-identita (ogni
  UPN/email pseudonimizzata singolarmente). Arricchimento IP del chiamante:
  `caller_ip_asn` in chiaro (metadato di routing), `caller_ip_asn_org`,
  `caller_ip_enrichment` e `caller_ip_geolocation` scrubbati (ISP/geo leggibili
  come valore IOC, IP interni/di tenant e host mascherati); `user_agent_data`
  in chiaro come `user_agent`. Zero campi elisi sui 42 dello schema completo;
  `raw_log` resta scrubbato come testo (mai in chiaro).

## 0.10.18

- **Export `saas_audit_logs` (O365/SaaS audit XDM) non piu eliso**: lo schema
  degli audit SaaS di Cortex XDM (`operation_name`, `service_type`,
  `identity_type`, `referenced_resource`, `*_orig`, ...) ora viene rilevato
  automaticamente come kit Cortex invece di cadere nel generico (dove finiva
  quasi tutto `[ELIDED]`). Gli enum operativi (`operation_name`/`_orig`,
  `operation_status`, `service_type`/`_sub_type`, `resource_type`/`_orig`,
  `identity_type`/`_sub_type`) restano leggibili come metadato analitico;
  l'identita (`identity_name`, `identity_orig`) resta mascherata e reversibile;
  `referenced_resource` diventa opaque, `referenced_resource_name` testo
  scrubbato, `caller_ip` segue la policy IP. Zero campi elisi sui 24 dello
  schema di riferimento.

## 0.10.17

- **TSV senza tabulazioni: fallback automatico a Testo (invece dell'errore)**:
  se in modalita CSV l'input collassa in un'unica colonna (tabulazioni perse),
  l'app ora lo elabora automaticamente come testo — IP, host, utenti, email
  e nomi cliente restano mascherati — e mostra un avviso che l'analisi
  per-colonna richiede un file .tsv/.csv o il TSV con le tabulazioni. Niente piu
  vicolo cieco ne rischio di riga tenuta in chiaro.

## 0.10.16

- **TSV senza tabulazioni: errore chiaro invece di silenzio**: se un TSV perde
  le tabulazioni (es. copiato da una tabella renderizzata) e in modalita CSV
  collassa in un'unica colonna, l'app ora rifiuta l'input con un messaggio
  esplicito invece di trattare l'intera riga come una sola colonna (che, se
  classificata `keep`, avrebbe lasciato i dati in chiaro). Soluzione: incollare
  il TSV con le tabulazioni, caricare il file, o usare la modalita Testo. Su un
  vero TSV/CSV la separazione in colonne funziona regolarmente.

## 0.10.15

- **`auth_outcome` e famiglia auth non piu elisi**: gli enum di autenticazione
  (`auth_outcome`, `auth_method`, `auth_result`, `auth_type`, `authentication_outcome`,
  `auth_outcome_reason`, ...) sono metadato analitico e restano leggibili anche in
  Safe mode. L'identita che autentica (`auth_identity`/`auth_user`/...) resta
  mascherata come utente.

## 0.10.14

Nuovo kit Bitdefender GravityZone + hardening SID/registro:

- **Kit Bitdefender GravityZone**: schema a punti (`alert.*`, `network.*`,
  `email.*`, `other.*`, `registry.*`, `resource.*`). MITRE ATT&CK ed enum
  operativi in chiaro; ID -> opaque; sensor -> endpoint; domini -> fqdn; email
  mascherate; nomi/oggetti/chiavi di registro come testo scrubbato. I 24 campi
  segnalati ora classificati (0 fuori kit); rilevamento automatico del kit.
- **SID mai deturpati dal match DOMINIO\\utente**: un SID (es. in
  `HKU\\S-1-5-21-...`) non viene piu inghiottito dal match `DOMINIO\\utente`;
  lo gestisce il matcher SID (dominio pseudonimizzato, RID in chiaro).
- **Hive di registro preservati**: `HKLM\\SOFTWARE\\...` resta leggibile invece
  di essere interpretato come `DOMINIO\\utente`.

## 0.10.13

QA da export Cortex xdr_data (NETWORK_DATAGRAM_STATISTICS / NETWORK_STREAM):

- **`dns_resolutions` non piu eliso**: il campo con gli IP risolti dalle query
  DNS non era classificato e in Safe mode finiva `[ELIDED]`. Ora e trattato
  come testo libero: gli IP interni/di tenant vengono mascherati, le
  risoluzioni pubbliche (valore IOC) restano leggibili. Coperti anche
  `dns_response_names` / `dns_answers`; `dns_resolutions_time` e gli enum DNS
  restano invariati.
- **Verifica path Windows**: confermato con il motore tabellare reale che
  `C:\Program Files\Google\...` resta integro (nessun `DOMINIO\utente`).
  Se in produzione vedi ancora `C:\Program DOM-xxxx\usr-xxxx\...`, il
  container gira un `logmask.py` vecchio: ricostruisci con `--no-cache`.

## 0.10.12

QA da export Cortex raw xdr_data ridotto (pochi campi, copertura 0%):

- **Auto-detect kit su export piccoli**: aggiunti fingerprint per le famiglie
  xdr_data molto specifiche di Cortex (actor_process_image_*,
  action_process_image_command_line, action_file_path, ...), cosi un export
  con pochi campi rileva comunque il kit invece di cadere nel generico.
- **Enum DNS operativi** (`dns_reply_code`, `dns_query_type`, `dns_op_code`,
  `dns_record_type`, ...): tenuti in chiaro come metadato analitico.
- **Allow-list campi custom** (`LOGMASK_KEEP_FIELDS` / `data/keep_fields.txt`):
  l'operatore puo dichiarare campi custom sempre da mantenere in chiaro (es.
  contatori come `numero_richieste`). La DLP resta attiva su questi campi
  (IBAN/CF/segreti vengono comunque elisi), quindi non usarli per campi che
  potrebbero contenere PII.
- **Path Windows non piu deturpati**: "Program Files\Google" e simili non
  vengono piu interpretati come DOMINIO\utente; i veri DOMINIO\utente e i
  path utente (C:\Users\<nome>) restano mascherati.

## 0.10.11

- **Modalita Sessioni** (nuova scheda): piu sessioni nominate per login,
  ciascuna con piu voci (incolla e/o file) come input separati, output e
  report per voce, export ZIP di sessione, tutto in memoria.
- Refactor: `anonRequestBody()` unica sorgente delle opzioni di anonimizzazione.

## 0.10.10

Decisions D1-D6 closed with the analyst (URLs and file names are IOC):

- **IOC URL fields stay readable** (D2): `Malicious URLs`, `Indicator(s)`,
  `Clicked URLs`, Defender `RemoteUrl`/`DomainName`/`DnsQuery`, FortiGate
  `url`/`uri` use the new `ioc` text kind — the attacker URL keeps host, path
  and query. Token-like parameters (`token=`, `sig=`, ...) are still elided,
  and hosts that are demonstrably the tenant's (internal/tenant-network IPs,
  vault-known FQDNs, client names) are still masked. Console/portal links
  (`External URL`, `alertWebUrl`, workbench, Kibana) keep the full hardening.
  Safe-mode residual scan no longer elides URL-attached hosts in IOC fields.
- **UI toggle for tenant networks**: new checkbox next to the IP policy
  ("Maschera reti pubbliche del tenant", default on) wired to the new
  `mask_tenant_networks` API parameter. The existing IP policy select is
  unchanged (D4).
- File names confirmed always readable (D3, current behaviour); hashes,
  rule IDs and titles/tags confirmed as in v0.10.9 (D1, D5, D6).

## 0.10.9

QA fixes from a live XSOAR "Events Investigation" paste (M365 Defender/Sentinel):

- **Tenant public networks** (`LOGMASK_TENANT_NETWORKS` / `data/tenant_networks.txt`):
  egress/NAT ranges owned by the customer are masked even with
  `ip_mode=internal` — a clear-text egress IP identifies the organization.
  New `ip_strict` kind for fields that always mask (`lastExternalIpAddress`,
  `*external_ip*` in the Defender and Cortex kits).
- **Bare hostname protection**: machine names pasted in evidence tables with
  no labeling key ("server-sso") are now masked reversibly via (1) configured
  naming conventions (`LOGMASK_HOST_TERMS` / `data/host_terms.txt`, literal or
  `prefix*`), (2) a conservative infra-vocabulary heuristic (anchored
  prefix/suffix + digit rules; prose like "web-based" is not touched), and
  (3) short-label sweep: an FQDN masked anywhere also protects its bare label.
- **Labeled Defender identifiers in pasted text** (`WorkspaceName`,
  `Data Sources`, `mdeDeviceId`, `SystemAlertId`, `detectorId`, `AlertType`,
  `azureAdDeviceId`): vaulted as opaque; same fields covered in the
  microsoft_defender kit for structured input, plus `hostName`,
  `deviceDnsName`, `dnsDomain`, `ntDomain`.
- **Well-known AD GUID allowlist**: documented schema/control-access GUIDs
  (DS-Replication-*, User-Change-Password, object classes, ...) are detection
  content and stay readable in KQL instead of becoming `cloud-*`.
- **Residual FQDN false positives**: dotted code identifiers such as
  `$left.SubjectLogonId` in KQL joins are no longer elided — the residual
  scanner now requires a real TLD.

## 0.10.8

- Cortex kit 2026.07.3 — closed the 10 residual fields from the first live
  coverage run (90.5% vendor): `Playbook`/`Policy Recommendation` scrubbed as
  text, `Policy Type`/`Policy Remediable`/`Prisma Attack Techniques`/
  `Source Identity User Type` kept (with generic `*_type`, `*_remediable`,
  `*attack_techniques` keeps), `Source/Target Host Ipv4/Ipv6 Addresses`
  masked as IP, `Source Instance` vaulted as opaque.
- `Issue Domain` is the XSIAM domain enum (Security/IT/Health): now kept
  readable instead of being masked as a Windows domain.

## 0.10.7

- Reimplemented on the v0.10.4 codebase the hardening that shipped in the lost
  v0.10.5/v0.10.6 builds: full-URL anonymization pass and customer-name denylist.
- **URL hardening**: URLs are processed atomically. Host always pseudonymized
  (any TLD, internal ones included); 24-64 hex, UUID and `WB-*` identifiers in
  path and fragments vaulted as reversible `id-*`; query values elided unless
  timestamp/number/boolean; `ref=`, `index=` and token-like parameters always
  `[ELIDED]`; SPA fragments handled as nested routes; credentials in the
  authority elided. Runs before DLP and Safe-mode residual checks, so a masked
  URL no longer blocks the output when Safe mode is off.
- **Customer-name denylist**: names configured via `LOGMASK_CLIENT_TERMS` or
  `data/client_terms.txt` are ALWAYS elided from free text (case-insensitive,
  tolerant to spacing/camel-case variants), irreversibly. Configuration only,
  never hardcoded in the shipped sources.
- **Palo Alto Cortex kit 2026.07.2**: coverage of XSIAM incident *display name*
  exports ("Host FQDN", "Initiator CMD", "CGO SHA256", `Mitre ATT&CK *`, ...):
  the 142 previously-unknown fields of the reference tenant are now classified
  (IOC hashes/signers/MITRE kept, cmdline/path/URL/free text scrubbed, hosts,
  users, e-mail, IP/MAC masked, tenant ids and resources vaulted as opaque).
  New display-name fingerprints; vendor auto-detection now also matches
  space-separated field names. `tags` moved from keep to text.
- New regression suite: display-name kit, URL hardening (spec reference URL,
  idempotence, sensitive keys, SPA fragments, IP policy, credentials), client
  denylist (variants, irreversibility, structured fields) and a full
  Fortigate/XSIAM display export replay with zero fields outside the kit.
- Portability: the engine now also runs on Python 3.10 (f-string quoting,
  possessive-quantifier emulation with identical semantics); the runtime
  target remains `python:3.12-slim`.

## 0.10.4

- Added SOC workflow template **Valutazione campi** for anonymization/field-quality review.
- Tuned Trend Vision One nested payload handling: indicator values are treated as text so command lines are sanitized instead of fully elided where possible.
- Reduced over-aggressive host pseudonymization in descriptive fields such as descriptions, messages, reasons and matched rule names.
- Added Workbench/alert ID detection (`WB-*`) as reversible opaque identifiers inside URLs and text.
- Added workflow-specific handling for `data_stream.namespace` in external AI analysis: pseudonymized as opaque instead of always kept.
- Added regression tests for field quality template, command-line preservation and descriptive-text stability.

## 0.10.3

- Elastic/Kibana signal wrapper + nested Trend Micro Vision One field kit.
