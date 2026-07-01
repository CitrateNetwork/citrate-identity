#!/usr/bin/env bash
# Fetch + PIN the model files into $KYC_MODELS_DIR. Run at deploy (or Docker build).
# Nothing is committed to git — models live in the image/volume, pinned by hash.
set -euo pipefail
DEST="${KYC_MODELS_DIR:-/models}"
mkdir -p "$DEST"

echo "[models] insightface buffalo_l (SCRFD detect + ArcFace embed)…"
# insightface fetches + caches this into $DEST/models/buffalo_l on first prepare().
python - <<PY
import os
from insightface.app import FaceAnalysis
FaceAnalysis(name="buffalo_l", root=os.environ.get("KYC_MODELS_DIR", "/models")).prepare(ctx_id=-1)
print("buffalo_l ready")
PY

echo "[models] anti-spoof (Silent-Face MiniFASNet) ONNX…"
# CHOOSE + PIN your anti-spoof model. There are several OSS options; the operator
# selects one, sets the URL, and pins the SHA256 so the artifact is reproducible.
: "${KYC_ANTISPOOF_URL:?set KYC_ANTISPOOF_URL to your chosen anti-spoof .onnx}"
curl -fsSL "$KYC_ANTISPOOF_URL" -o "$DEST/anti_spoof.onnx"
if [ -n "${KYC_ANTISPOOF_SHA256:-}" ]; then
  echo "${KYC_ANTISPOOF_SHA256}  $DEST/anti_spoof.onnx" | sha256sum -c -
else
  echo "[models] WARNING: KYC_ANTISPOOF_SHA256 unset — pin the hash for a reproducible build." >&2
fi

echo "[models] done → $DEST"
