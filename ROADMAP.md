# Roadmap

## Prossimo intervento raccomandato: hardening e key management

- Docker Secrets per master key.
- Separazione fisica tra vault e chiave.
- Container non-root.
- Filesystem read-only salvo directory dati.
- Healthcheck e limiti runtime.
- Rotazione chiavi e backup/restore verificati.

## Release successive

- Governance: retention per tenant, cancellazione mapping, export audit firmato.
- Workflow SOC avanzato: batch cross-tenant controllato, template personalizzabili da admin, export PDF/Markdown.
- Validazione produzione: fuzzing parser, SBOM, scansione dipendenze, runbook DR.


## 0.10.4

- Field-quality workflow template and regression fixes for Trend/ECS wrappers.
