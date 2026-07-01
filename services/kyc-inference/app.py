"""
VERI KYC inference service — FastAPI front for the model pipeline (D5).

Implements the exact contract the Node client (`src/kyc-inference-client.ts`) and
`.agentile/compliance/VERI-inference-service.md` specify. Bearer-auth, JSON.
Runs on US infra; the images it receives are already DEK-decrypted by the caller.

Fail-closed: if the models are not loaded, /v1/* returns 503 → the Node client
routes the case to needs-review. It never returns a fabricated pass.
"""

import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

import inference

TOKEN = os.environ.get("KYC_INFERENCE_TOKEN", "")

app = FastAPI(title="VERI KYC inference", version="1")


def _auth(authorization: str) -> None:
    if not TOKEN:
        raise HTTPException(status_code=503, detail="KYC_INFERENCE_TOKEN not configured")
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")


def _require_ready() -> None:
    if not inference.ready():
        # Models not loaded → fail closed. The caller treats this as needs-review.
        raise HTTPException(status_code=503, detail="models not loaded")


class LivenessReq(BaseModel):
    face: str
    idPortrait: Optional[str] = None


class DocumentReq(BaseModel):
    image: str


@app.get("/health")
def health():
    """200 with {ok:true} only when the models are loaded and serving."""
    ok = inference.ready()
    return {"ok": ok, "service": "veri-kyc-inference"}


@app.post("/v1/liveness")
def liveness(req: LivenessReq, authorization: str = Header(default="")):
    _auth(authorization)
    _require_ready()
    return inference.analyze_liveness(req.face, req.idPortrait)


@app.post("/v1/document")
def document(req: DocumentReq, authorization: str = Header(default="")):
    _auth(authorization)
    _require_ready()
    return inference.analyze_document(req.image)
