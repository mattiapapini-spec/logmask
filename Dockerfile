FROM python:3.12-slim

WORKDIR /app
# readpst (pst-utils) extracts .pst archives for the mail anonymizer.
RUN apt-get update && apt-get install -y --no-install-recommends pst-utils \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY logmask.py structured.py auth.py app.py vendor_kits.py dlp.py workflows.py pst_anon.py docx_anon.py pdf_anon.py ./
COPY kits ./kits
COPY persons ./persons
COPY static ./static

ENV LOGMASK_DATA=/data \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
VOLUME /data
# Label in fondo, DOPO i layer apt/pip: cosi' il bump di versione a ogni
# release non invalida la cache delle dipendenze e un rebuild senza modifiche
# ai requirements resta interamente servito dalla cache (niente rete).
LABEL org.opencontainers.image.title="logmask-web" \
      org.opencontainers.image.version="0.27.8"
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
