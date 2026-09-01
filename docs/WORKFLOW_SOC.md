# Workflow SOC

LogMask v0.10.1 aggiunge profili operativi pensati per i flussi SOC quotidiani. I profili applicano preset a formato, policy IP, Safe mode e DLP, ma non disattivano mai i controlli fail-closed.

## Profili inclusi

| Profilo | Uso | IP | DLP |
|---|---|---|---|
| Ticket cliente | Segnalazioni e ticket esterni | solo IP interni pseudonimizzati | segreti elisi, PII reversibile |
| Analisi AI esterna | Incolla verso LLM esterni | solo IP interni pseudonimizzati | segreti, IBAN e indirizzi elisi |
| Threat hunting interno | Analisi interna e correlazione | IP non pseudonimizzati | segreti elisi, PII reversibile |
| Report / allegato | Evidenze e report minimizzati | tutti gli IP pseudonimizzati | segreti, IBAN e indirizzi elisi |

## Funzioni UI

- selettore `Workflow SOC`;
- template operativo automatico per ticket, AI, hunting e report;
- confronto riga-per-riga originale/anonimizzato;
- approvazione in sessione dei campi ambigui;
- archivio temporaneo delle lavorazioni della sessione browser;
- download con nome coerente: `logmask-<tenant>-<workflow>...`.

## Note di sicurezza

I campi ambigui approvati in sessione non bypassano il motore di anonimizzazione. L'approvazione serve a documentare che l'analista ha visto e accettato la classificazione nel template operativo. L'output resta governato dai controlli del backend.
