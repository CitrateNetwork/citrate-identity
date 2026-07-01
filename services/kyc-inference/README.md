# VERI KYC inference service (reference)

The self-hosted model backend the VERI verification engine calls (planset D5). It runs
the ONNX models — face detect + embed (1:1 match), presentation-attack detection (PAD),
and document OCR/MRZ — behind the exact HTTP contract the Node client
(`../../src/kyc-inference-client.ts`) speaks. Runs on **US infrastructure**; images it
receives are already DEK-decrypted by the caller.

## The gap, precisely (what "you can't just download it" meant)
Three things get lumped into "download, bundle, validate" — only part of one is real:

| Step | Blocker? | Reality |
|---|---|---|
| **Download** | No | `download_models.sh` fetches + hash-pins the models. The deploy host runs it; whether a coding sandbox has internet is irrelevant. |
| **Bundle** | No — *shouldn't* | Do **not** commit 100MB+ binaries to git. Fetch at build/deploy into `/models`, pinned by SHA256. |
| **Validate — functional** | Partial | A smoke ("models load, sane output") can only run *where the models + onnxruntime + a GPU/CPU exist* = the deploy host, not here. |
| **Validate — accuracy** | **Yes, and it's yours** | "Does the PAD catch spoofs? does 1:1 discriminate?" needs a **labeled dataset + metrics + a human threshold decision**. That's `validate.py`, and it's the S6 / go-live gate you own. |

So the code is **real, not a stub**. What it can't do until deployed is *prove its
accuracy* — which is exactly the validation you offered to run.

## What's here
- `app.py` — FastAPI: `POST /v1/liveness`, `POST /v1/document`, `GET /health`. Bearer
  auth (`KYC_INFERENCE_TOKEN`). **Fail-closed**: models not loaded → 503 → the Node
  client routes the case to needs-review. Never a fabricated pass.
- `inference.py` — the real pipeline: insightface (SCRFD detect + ArcFace embed →
  cosine 1:1 match), Silent-Face MiniFASNet PAD, passporteye MRZ read + a portrait +
  tamper check. The Node side re-validates the MRZ check digits locally.
- `download_models.sh` — fetch + pin the models.
- `Dockerfile` / `requirements.txt` — containerized, tesseract for OCR.
- `validate.py` — the **accuracy + adversarial validation harness** (APCER/BPCER,
  FMR/FNMR). This is the S6 gate.

## Deploy (US host)
```bash
# 1. Build
docker build -t veri-kyc-inference services/kyc-inference
# 2. Fetch models into a /models volume (pin the anti-spoof URL + hash)
docker run --rm -v veri-models:/models \
  -e KYC_ANTISPOOF_URL="<your chosen anti-spoof .onnx>" \
  -e KYC_ANTISPOOF_SHA256="<sha256>" \
  veri-kyc-inference bash download_models.sh
# 3. Run
docker run -d -p 8000:8000 -v veri-models:/models \
  -e KYC_INFERENCE_TOKEN="<same token you set on the identity service>" \
  veri-kyc-inference
# 4. Point the identity service at it
#    KYC_INFERENCE_URL=https://<this host>   KYC_INFERENCE_TOKEN=<token>
#    (config gate requires a non-local https origin in prod)
```
`curl -s localhost:8000/health` → `{"ok":true}` once models are loaded. Until
`KYC_INFERENCE_URL` is set on the identity service, the engine **fails closed to
needs-review** — nothing auto-verifies.

## Validation you run (the S6 / go-live gate)
```bash
# PAD: how often are attacks accepted (APCER) / genuine rejected (BPCER)?
python validate.py pad --live_dir ./data/live --attack_dir ./data/print --attack_type print
python validate.py pad --live_dir ./data/live --attack_dir ./data/replay --attack_type replay
python validate.py pad --live_dir ./data/live --attack_dir ./data/deepfake --attack_type deepfake
# 1:1 match: FMR / FNMR on genuine+impostor pairs
python validate.py match --pairs ./data/pairs.csv   # selfie,id,label(1 genuine/0 impostor)
```
**Datasets (you supply):** an in-house captured live set + PAD attack sets
(print/replay/mask, e.g. CASIA-FASD / Replay-Attack style) + a **deepfake/synthetic**
set. Tune `KYC_PAD_THRESHOLD` / `KYC_MATCH_THRESHOLD` on a held-out split.

**Acceptance (owner + counsel, in the legal packet):** report APCER **per attack
type**. Suggested pilot bar: APCER ≤ 2–5% at a usable BPCER, FMR ≤ 0.1% at an
acceptable FNMR — tighten before any high-value flow. **Until validated, run
review-only** (treat engine `verified` as a strong prior for a human approver rather
than an auto-grant).

## Honest limitations (say so in the packet)
- OSS PAD is **not iBeta/ISO-30107-3 certified** — the validation above is *your*
  evidence, not a certificate.
- The tamper heuristic (`_tamper_score`) is a lightweight ELA placeholder, not a
  strong forgery detector — a dedicated tamper model is a follow-up; NFC ePassport
  read (where available) is the stronger authenticity path.
- Model input shapes (PAD crop/scale, `KYC_PAD_LIVE_INDEX`) must be confirmed against
  the *specific* anti-spoof model you pin — verify with the functional smoke.
