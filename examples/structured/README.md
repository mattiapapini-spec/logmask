# Esempi parser strutturati

I file contengono esclusivamente dati fittizi. Dalla CLI:

```powershell
python logmask.py --key data/master.key --vault data/vault.db anonymize `
  --tenant laboratorio --format auto --safe examples/structured/sample.json `
  -o output.json
```

Per il reverse usare lo stesso tenant:

```powershell
python logmask.py --key data/master.key --vault data/vault.db deanonymize `
  --tenant laboratorio --format auto output.json -o restored.json
```
