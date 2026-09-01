# LogMask — Documentation

Technical documentation for LogMask 0.27.2, in English and Italian.

| Language | Markdown source | |
|---|---|---|
| English | [`en/TECHNICAL_DOCUMENTATION.md`](en/TECHNICAL_DOCUMENTATION.md) | Full operator + developer + regulatory guide |
| Italiano | [`it/DOCUMENTAZIONE_TECNICA.md`](it/DOCUMENTAZIONE_TECNICA.md) | Guida completa operatore + sviluppatore + normativa |

A paginated bilingual PDF built from these sources is at
[`LogMask_Technical_Documentation_EN_IT.pdf`](LogMask_Technical_Documentation_EN_IT.pdf).

## Contents (both languages)

Overview · Core concepts · Architecture · Installation & deployment ·
Configuration · User guide · Supported formats · Pseudonymization engine ·
Token shapes · Vendor kits · DLP categories & Safe mode · API reference ·
Security model · Operations & troubleshooting · **Regulatory considerations
(EU / Italy, AI use)** · Extending LogMask.

## Regenerating the PDF

The PDF is built from the two Markdown files with `python-markdown` + PyMuPDF
(`build_pdf.py`, kept out of the image). Editing the `.md` files and rerunning
the build regenerates it. The `.md` files are the source of truth.

Older topic notes: [`DLP_POLICY.md`](DLP_POLICY.md), [`VENDOR_KITS.md`](VENDOR_KITS.md),
[`WORKFLOW_SOC.md`](WORKFLOW_SOC.md).
