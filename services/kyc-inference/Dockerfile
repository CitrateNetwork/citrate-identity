# VERI KYC inference service (self-hosted, US infra). CPU by default; for GPU use an
# onnxruntime-gpu base + CUDAExecutionProvider. Models are fetched into /models —
# either at build (uncomment the RUN) or mounted as a volume + `download_models.sh`
# at runtime (preferred: keeps large binaries out of image layers, pins by hash).
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr libgl1 libglib2.0-0 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py download_models.sh verify_models.sh ./
ENV KYC_MODELS_DIR=/models

# Option A (reproducible image): fetch at build. Pass the pinned URL/hash as args.
# ARG KYC_BUFFALO_L_SHA256
# ARG KYC_ANTISPOOF_URL
# ARG KYC_ANTISPOOF_SHA256
# RUN bash download_models.sh
# Option B (default): mount a /models volume + run download_models.sh once on the host.

EXPOSE 8000
# Fail-closed boot (AV-S1): verify model integrity against MODELS.lock BEFORE serving.
# A missing lock / missing file / hash mismatch aborts startup — the service never
# serves against unverified weights. Health: GET /health → {ok:true} only when loaded.
CMD ["bash", "-c", "bash verify_models.sh && exec uvicorn app:app --host 0.0.0.0 --port 8000"]
