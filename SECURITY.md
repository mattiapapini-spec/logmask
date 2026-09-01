# Sicurezza e threat model

LogMask e' uno strumento self-hosted che pseudonimizza log SOC prima della
condivisione (vendor, ticket, AI esterne). Questo documento dice cosa
protegge, cosa NON protegge, e come segnalare una vulnerabilita'.

**Il progetto non ha ricevuto un audit di sicurezza indipendente.** Usalo come
livello di difesa aggiuntivo, non come unica barriera: rivedi sempre l'output
prima di condividerlo.

## Cosa protegge

- Pseudonimizzazione deterministica per tenant (HMAC su chiave derivata dalla
  master key): stesso valore -> stesso token, correlazione preservata,
  reversibile solo da chi ha il vault del tenant.
- Vault cifrato AES-GCM su SQLite; chiavi per-tenant derivate, mai condivise
  tra tenant.
- Safe mode fail-closed: i campi non classificati vengono elisi, non esposti.
- Nomi cliente configurati: token irreversibile (CLIENT-xxxxxx), mai nel vault.
- Verifica residui: l'output viene bloccato se contiene valori sensibili noti.

## Cosa NON protegge (leggere prima dell'uso)

- Chi ha accesso alla cartella `data/` (master key + vault) puo' invertire gli
  pseudonimi: proteggi il volume (permessi, cifratura disco, backup cifrati).
- Non e' una DLP completa: un secret non etichettato e senza forma
  riconoscibile puo' sfuggire; testo libero anomalo puo' contenere PII non
  rilevata.
- La pseudonimizzazione deterministica conserva la correlazione: un
  avversario con conoscenza esterna puo' fare inferenze statistiche
  (frequenze, pattern) anche senza invertire i token.
- Le regole utente in `data/kits/` hanno priorita': un `action: keep` sbagliato
  espone il campo. Rivedi i TODO delle proposte generate.
- Nessun TLS integrato: esporre solo dietro reverse proxy HTTPS, mai su rete
  non fidata.
- Il container gira come root e master key/vault condividono il volume:
  hardening pianificato, non ancora implementato.

## Segnalare una vulnerabilita'

Segnalazione privata: e-mail a mattia.papini@gmail.com (oppure il private
vulnerability reporting di GitHub, se abilitato sul repo). Non aprire issue
pubbliche con dettagli sfruttabili e **non includere mai log reali o dati di
clienti** nelle segnalazioni. Verra' corretta sull'ultima release; le versioni
precedenti non ricevono patch.
