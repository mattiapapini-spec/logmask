# Policy DLP e PII — LogMask 0.8

Il livello DLP viene applicato **oltre** ai parser strutturati e ai kit vendor. Un campo classificato come operativo o `keep` non esclude quindi il controllo DLP.

## Azioni

Ogni categoria può usare una delle seguenti azioni:

| Azione | Effetto | Reversibile |
|---|---|---:|
| `pseudonymize` | sostituisce il valore con un token deterministico salvato nel vault tenant | sì |
| `redact` | sostituisce il valore con `[ELIDED]` senza inserirlo nel vault | no |
| `block` | lascia il testo nell'anteprima ma marca il risultato `BLOCCATO`; copia e download restano disabilitati | n/d |
| `keep` | mantiene intenzionalmente il valore e non lo considera una violazione del gate DLP | n/d |

`keep` va usato soltanto quando il titolare del trattamento ha stabilito che quella categoria può essere condivisa.

## Categorie e valori predefiniti

| Categoria | Default | Rilevamento |
|---|---|---|
| `credentials` | `redact` | password, secret, API key, OAuth token, bearer/basic auth, JWT, cookie e session token |
| `private_key` | `redact` | chiavi private PEM e certificati PEM incorporati |
| `tax_id` | `pseudonymize` | codice fiscale italiano con controllo del carattere finale |
| `iban` | `pseudonymize` | IBAN con validazione MOD-97 |
| `phone` | `pseudonymize` | telefono in campo o testo esplicitamente etichettato |
| `person_name` | `pseudonymize` | nome/cognome in campo o testo esplicitamente etichettato |
| `address` | `pseudonymize` | indirizzo in campo o testo esplicitamente etichettato |
| `cloud_id` | `pseudonymize` | UUID/GUID, Azure Resource ID, AWS ARN/account ID e identificativi cloud etichettati |
| `sensitive_url` | `redact` | valori di token, key, password, code e sessione nella query string |

Per evitare falsi positivi, nomi, telefoni e indirizzi non vengono estratti da qualunque frase naturale: è richiesto un campo o una label riconoscibile, ad esempio `full_name`, `telefono`, `address` o `indirizzo`.

## Pseudonimi

I valori reversibili usano forme riconoscibili:

```text
cf-xxxxxxxxxxxx
iban-xxxxxxxxxxxx
tel-xxxxxxxxxxxx
person-xxxxxxxxxxxx
addr-xxxxxxxxxxxx
cloud-xxxxxxxxxxxx
secret-xxxxxxxxxxxx   # solo se l'operatore forza pseudonymize sui segreti
```

La policy predefinita non salva mai credenziali e chiavi private nel vault.

## Web

Aprire **Policy DLP / PII avanzata** nel pannello Anonimizza e scegliere l'azione per categoria. Il report mostra conteggi per categoria e azione senza riportare il valore originale dei secret bloccati.

## API

Metadati:

```http
GET /api/dlp-categories
```

Esempio richiesta:

```json
{
  "tenant": "acme",
  "format": "json",
  "safe_mode": true,
  "text": "{\"billing\":{\"iban\":\"IT60X0542811101000000123456\"}}",
  "dlp_policy": {
    "iban": "pseudonymize",
    "credentials": "redact",
    "private_key": "block"
  }
}
```

Le categorie omesse assumono il valore predefinito.

## CLI

Override singoli:

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant acme --format auto --safe `
  --dlp iban=block --dlp person_name=pseudonymize `
  input.json -o output.json
```

File JSON:

```json
{
  "credentials": "redact",
  "private_key": "block",
  "tax_id": "pseudonymize",
  "iban": "pseudonymize",
  "phone": "pseudonymize",
  "person_name": "pseudonymize",
  "address": "pseudonymize",
  "cloud_id": "pseudonymize",
  "sensitive_url": "redact"
}
```

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant acme --safe --dlp-policy .\dlp-policy.json `
  input.log -o output.log
```

## Limiti

- Il rilevamento PII non sostituisce un prodotto DLP enterprise o un motore NER revisionato sul proprio dominio.
- I formati nazionali diversi dal codice fiscale italiano non sono ancora validati con algoritmi specifici.
- Un secret non etichettato e privo di una forma riconoscibile può non essere rilevato.
- I certificati pubblici vengono trattati insieme al materiale PEM per prudenza; la policy può essere modificata se il caso d'uso richiede di mantenerli.
