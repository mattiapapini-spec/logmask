# Vendor kits — LogMask 0.7.0

I kit vendor sono cataloghi versionati di nomi campo. Non sostituiscono il controllo finale fail-closed e non costituiscono una promessa che ogni possibile versione o integrazione del prodotto usi gli stessi campi.

Per ogni input LogMask mostra:

- kit rilevato o forzato;
- confidenza del rilevamento;
- percentuale dei campi popolati coperti direttamente dal kit;
- percentuale complessiva classificata anche tramite regole generiche e value sniffing;
- lista dei campi fuori kit;
- valori elisi e trasformazioni fallite.

Un campo popolato non riconosciuto viene sostituito con `[ELIDED]` quando Safe mode è attivo. Senza Safe mode, l'output viene bloccato.

## Kit inclusi

| ID | Prodotto | Versione catalogo | Ambiti principali |
|---|---|---|---|
| `cortex` | Palo Alto Cortex XDR / XSIAM / XSOAR | 2026.07 | xdr_data, alert export, incident fields |
| `microsoft_defender` | Microsoft Defender XDR / Entra ID / M365 | 2026.07 | Advanced Hunting, sign-in e Unified Audit |
| `trend_vision_one` | Trend Micro Vision One / Apex One | 2026.07 | Search/App export, alert ed endpoint events |
| `elastic_ecs` | Elastic Common Schema | ECS 9.4 compatible | ECS, Beats e Elastic Agent |
| `fortinet` | FortiGate / FortiEDR | 2026.07 | FortiOS key=value e FortiEDR exports |
| `sentinelone` | SentinelOne Singularity | 2026.07 | agent, storyline e threat events |
| `sophos` | Sophos Central / XDR | 2026.07 | endpoint e threat events |
| `cisco_secure_endpoint` | Cisco Secure Endpoint / SecureX | 2026.07 | connector, computer e trajectory events |
| `darktrace_exabeam` | Darktrace / Exabeam | 2026.07 | model breach, risk e session events |
| `acronis` | Acronis Cyber Protect / EDR | 2026.07 | machine, alert e process events |

## Azioni di campo

- `mask`: pseudonimizzazione reversibile, inclusi ID opachi come GUID/UUID tramite pseudonimi `id-…`.
- `text`: scansione interna del testo e controllo residui.
- `keep`: metadato operativo esplicitamente ammesso dal kit, per esempio severity, action, porte, hash e identificativi tecnici non direttamente identificativi.
- `redact`: campo fuori catalogo eliso in Safe mode.

## Rilevamento

Il rilevamento usa fingerprint pesati. Sono richiesti almeno due segnali indipendenti oppure un punteggio elevato. Per CEF e LEEF vengono considerati anche vendor e product dell'header. È sempre possibile forzare il kit dalla UI o tramite `--catalog`.

## Aggiornamento dei kit

Le regole sono definite in `vendor_kits.py`. Ogni modifica deve includere:

1. esempio fittizio o sanitizzato;
2. test di detection;
3. test delle azioni mask/text/keep;
4. test su almeno un campo sconosciuto;
5. aggiornamento della versione del kit.

## Riferimenti primari usati

- Microsoft Defender XDR Advanced Hunting: [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) e [AlertInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table).
- Elastic Common Schema: [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference), versione 9.4.0 al momento della stesura.
- Per gli altri vendor, il catalogo combina nomi campo pubblici, formati standard CEF/LEEF/Syslog e campioni operativi sanitizzati. Le integrazioni OEM, i collector e i parser SIEM possono rinominare i campi; il report di copertura è quindi obbligatorio.

## Elastic/Kibana wrappers with nested vendor payloads

From v0.10.3, LogMask normalizes Elastic wrapper prefixes such as `_source.`, `fields.`, `signal.*` and `kibana.alert.original_*` before kit matching. If a branch contains `trend_micro_vision_one.alert.*`, the Trend Micro Vision One kit is applied to that branch even when the outer document is detected as Elastic ECS.

This prevents account fields such as `impact_scope.entities[].value.account_value` and user fields such as `kibana.alert.rule.updated_by` from remaining in clear, while keeping operational SOC metadata readable.
