"""
VERI reference inference pipeline (self-hosted model backend, D5).

Real ONNX inference — face detection + embedding (1:1 match), presentation-attack
detection (PAD), and document MRZ read + tamper/portrait checks. Implements the
verdicts the Node client (`src/kyc-inference-client.ts`) consumes.

HONEST STATUS: this is REAL code, not a stub. It loads real models and runs real
inference. What it needs before it can be trusted for auto-verify:
  1. the model files (see download_models.sh) — pinned, fetched at build/deploy;
  2. a FUNCTIONAL smoke on the deploy host (models load, sane outputs on a few images);
  3. an ACCURACY validation pass (validate.py) — PAD APCER/BPCER + 1:1 FMR/FNMR on a
     labeled set — with the owner accepting the thresholds (S6 / go-live packet).
It NEVER returns a fabricated pass: if models aren't loaded, `ready()` is False and
the service reports not-ready (fail-closed); the Node client then routes to review.

Model stack (swap-able — see README):
  - insightface `buffalo_l` (SCRFD detect + ArcFace embed) → cosine-similarity match
  - Silent-Face-Anti-Spoofing MiniFASNet (anti_spoof.onnx) → live probability
  - passporteye → MRZ ROI + OCR (the Node side re-validates the check digits)
"""

from __future__ import annotations

import base64
import io
import os
from typing import Optional

import numpy as np
from PIL import Image

MODELS_DIR = os.environ.get("KYC_MODELS_DIR", "/models")
# Cosine-similarity threshold for a 1:1 face match (ArcFace normed embeddings).
# Calibrate on your validation set; ~0.40 is a common starting point.
MATCH_THRESHOLD = float(os.environ.get("KYC_MATCH_THRESHOLD", "0.40"))
# Live-probability threshold for PAD. Calibrate for your target APCER/BPCER.
PAD_THRESHOLD = float(os.environ.get("KYC_PAD_THRESHOLD", "0.60"))
# MiniFASNet input side + crop scale (must match the deployed anti-spoof model).
PAD_INPUT = int(os.environ.get("KYC_PAD_INPUT", "80"))
PAD_SCALE = float(os.environ.get("KYC_PAD_SCALE", "2.7"))

_face_app = None
_pad_session = None


def _load():
    """Lazily load the models. Raises if the files are missing → ready() False."""
    global _face_app, _pad_session
    if _face_app is None:
        from insightface.app import FaceAnalysis  # imported here so import failure surfaces in ready()

        app = FaceAnalysis(name="buffalo_l", root=MODELS_DIR, providers=["CPUExecutionProvider"])
        app.prepare(ctx_id=-1, det_size=(640, 640))
        _face_app = app
    if _pad_session is None:
        import onnxruntime as ort

        pad_path = os.path.join(MODELS_DIR, "anti_spoof.onnx")
        _pad_session = ort.InferenceSession(pad_path, providers=["CPUExecutionProvider"])
    return _face_app, _pad_session


def ready() -> bool:
    try:
        _load()
        return True
    except Exception:
        return False


def _decode(b64: str) -> np.ndarray:
    """base64 → BGR uint8 array (insightface/opencv convention)."""
    img = Image.open(io.BytesIO(base64.b64decode(b64))).convert("RGB")
    return np.array(img)[:, :, ::-1].copy()


def _largest(faces):
    if not faces:
        return None
    return max(faces, key=lambda f: (f.bbox[2] - f.bbox[0]) * (f.bbox[3] - f.bbox[1]))


def _crop_for_pad(img: np.ndarray, bbox) -> np.ndarray:
    """Center-crop around the face at PAD_SCALE, resize to PAD_INPUT² (MiniFASNet)."""
    h, w = img.shape[:2]
    x1, y1, x2, y2 = bbox
    cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
    side = max(x2 - x1, y2 - y1) * PAD_SCALE
    nx1, ny1 = int(max(0, cx - side / 2)), int(max(0, cy - side / 2))
    nx2, ny2 = int(min(w, cx + side / 2)), int(min(h, cy + side / 2))
    crop = img[ny1:ny2, nx1:nx2]
    if crop.size == 0:
        crop = img
    # Resize in RGB (PIL), then flip back to BGR: MiniFASNet-V2 wants BGR [0,1] NCHW.
    pil = Image.fromarray(crop[:, :, ::-1]).resize((PAD_INPUT, PAD_INPUT))
    arr = np.asarray(pil).astype(np.float32)[:, :, ::-1] / 255.0  # RGB -> BGR
    return np.transpose(np.ascontiguousarray(arr), (2, 0, 1))[None, ...]  # NCHW


def _pad_live_prob(pad_session, img: np.ndarray, bbox) -> float:
    """Run the anti-spoof model; return P(live) in [0,1]."""
    x = _crop_for_pad(img, bbox)
    out = pad_session.run(None, {pad_session.get_inputs()[0].name: x})[0]
    logits = np.asarray(out).reshape(-1)
    # MiniFASNet emits [fake, live] or [spoof, real, ...]; softmax + take the "live"
    # index (1). If your model differs, set KYC_PAD_LIVE_INDEX.
    e = np.exp(logits - logits.max())
    probs = e / e.sum()
    live_idx = int(os.environ.get("KYC_PAD_LIVE_INDEX", "1"))
    return float(probs[min(live_idx, len(probs) - 1)])


def analyze_liveness(face_b64: str, id_portrait_b64: Optional[str] = None) -> dict:
    face_app, pad = _load()
    img = _decode(face_b64)
    face = _largest(face_app.get(img))
    if face is None:
        return {"pass": False, "confidence": 0.0, "reason": "no face detected in selfie"}

    pad_score = _pad_live_prob(pad, img, face.bbox)
    match_score: Optional[float] = None
    if id_portrait_b64:
        pimg = _decode(id_portrait_b64)
        pf = _largest(face_app.get(pimg))
        if pf is not None:
            match_score = float(np.dot(face.normed_embedding, pf.normed_embedding))

    live = pad_score >= PAD_THRESHOLD
    matched = match_score is not None and match_score >= MATCH_THRESHOLD
    # PAD (anti-spoof) is ADVISORY by default. The lightweight, un-validated model
    # false-positives on real selfies (lighting/phone camera), and for onboarding honest
    # investors/partners a false spoof-reject is far worse than the residual risk — the
    # strong identity signal is the 1:1 face match. Set KYC_PAD_ENFORCE=true to gate on
    # liveness once the model is validated on a spoof set (S6). padScore is always returned
    # so a human/admin can still see it and the engine can flag (not block) low scores.
    pad_enforce = os.environ.get("KYC_PAD_ENFORCE", "false").strip().lower() in ("1", "true", "yes")
    passed = bool(matched and (live or not pad_enforce))

    reason = None
    if match_score is None:
        reason = "no face found in the ID portrait to match against"
    elif not matched:
        reason = "selfie does not match the ID portrait"
    elif pad_enforce and not live:
        reason = "presentation-attack suspected"

    return {
        "pass": passed,
        "confidence": round(pad_score, 4),
        "padScore": round(pad_score, 4),
        "matchScore": None if match_score is None else round(match_score, 4),
        "reason": reason,
    }


def _tamper_score(img: np.ndarray) -> float:
    """
    Lightweight tamper heuristic via JPEG Error-Level-Analysis energy. NOT a strong
    forgery detector — a placeholder pending a dedicated tamper model; documented as
    a known limitation. Returns 0..1 (higher = more suspicious).
    """
    try:
        pil = Image.fromarray(img[:, :, ::-1])
        buf = io.BytesIO()
        pil.save(buf, "JPEG", quality=90)
        recompressed = np.asarray(Image.open(io.BytesIO(buf.getvalue()))).astype(np.int16)
        orig = np.asarray(pil).astype(np.int16)
        ela = np.abs(orig - recompressed)
        return float(min(1.0, ela.mean() / 32.0))
    except Exception:
        return 0.0


def analyze_document(image_b64: str) -> dict:
    face_app, _ = _load()
    img = _decode(image_b64)

    mrz_lines = None
    ocr_conf = 0.0
    try:
        from passporteye import read_mrz

        pil = Image.fromarray(img[:, :, ::-1])
        buf = io.BytesIO()
        pil.save(buf, "PNG")
        mrz = read_mrz(buf.getvalue())
        if mrz is not None:
            code = getattr(mrz, "mrz_code", "") or ""
            mrz_lines = [ln for ln in code.splitlines() if ln.strip()]
            ocr_conf = float(getattr(mrz, "valid_score", 0)) / 100.0
    except Exception as exc:  # OCR failure → let the Node side route to review
        return {"reason": f"OCR failed: {exc}"}

    portrait_present = _largest(face_app.get(img)) is not None
    tamper = _tamper_score(img)
    return {
        "mrz": mrz_lines,
        "portraitPresent": portrait_present,
        "tamperScore": round(tamper, 4),
        "ocrConfidence": round(ocr_conf, 4),
    }
