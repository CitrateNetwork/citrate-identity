"""
VERI inference accuracy + adversarial validation harness (S6-WP1 / the go-live gate).

Runs the deployed model pipeline against LABELED datasets and reports the metrics the
owner + counsel must accept BEFORE auto-verify is enabled (planset D8):

  PAD (presentation-attack detection) at KYC_PAD_THRESHOLD:
    APCER = attacks accepted as live   (lower is better; the security-critical number)
    BPCER = genuine rejected as spoof  (lower is better; the friction number)
  1:1 face match at KYC_MATCH_THRESHOLD:
    FMR   = impostor pairs accepted    (false match)
    FNMR  = genuine pairs rejected     (false non-match)

You supply the datasets (none ship here). Recommended sources: an in-house captured
set + public PAD sets (e.g. CASIA-FASD / Replay-Attack style: print, replay, mask)
and — critically for 2026 — a DEEPFAKE/synthetic-face set. Report APCER per attack
type. Acceptance thresholds are the owner's call (start: APCER ≤ 2–5% at a usable
BPCER for pilot scale; tighten before high-value flows).

Usage:
  python validate.py pad   --live_dir DIR --attack_dir DIR [--attack_type print]
  python validate.py match --pairs pairs.csv     # rows: selfie_path,id_path,label(1=genuine,0=impostor)
"""

from __future__ import annotations

import argparse
import base64
import csv
import glob
import os
import sys

import inference

IMG_EXT = ("*.jpg", "*.jpeg", "*.png", "*.bmp", "*.webp")


def _b64(path: str) -> str:
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def _images(d: str):
    for ext in IMG_EXT:
        yield from glob.glob(os.path.join(d, "**", ext), recursive=True)


def run_pad(args):
    if not inference.ready():
        sys.exit("models not loaded — set KYC_MODELS_DIR + run download_models.sh")
    thr = float(os.environ.get("KYC_PAD_THRESHOLD", "0.60"))
    live = list(_images(args.live_dir))
    attack = list(_images(args.attack_dir))
    if not live or not attack:
        sys.exit("need images in both --live_dir and --attack_dir")

    def pad_scores(paths):
        out = []
        for p in paths:
            r = inference.analyze_liveness(_b64(p), None)  # PAD only (no portrait)
            out.append(r.get("padScore", 0.0))
        return out

    live_scores = pad_scores(live)
    attack_scores = pad_scores(attack)
    # APCER: attacks with padScore >= threshold (wrongly accepted as live).
    apcer = sum(1 for s in attack_scores if s >= thr) / len(attack_scores)
    # BPCER: genuine with padScore < threshold (wrongly rejected).
    bpcer = sum(1 for s in live_scores if s < thr) / len(live_scores)
    print(f"PAD @ threshold {thr}  (attack_type={args.attack_type or 'all'})")
    print(f"  live samples   : {len(live_scores)}")
    print(f"  attack samples : {len(attack_scores)}")
    print(f"  APCER (attacks accepted) : {apcer:.4f}")
    print(f"  BPCER (genuine rejected) : {bpcer:.4f}")


def run_match(args):
    if not inference.ready():
        sys.exit("models not loaded")
    thr = float(os.environ.get("KYC_MATCH_THRESHOLD", "0.40"))
    genuine, impostor = [], []
    with open(args.pairs) as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            selfie, idimg, label = row[0].strip(), row[1].strip(), row[2].strip()
            r = inference.analyze_liveness(_b64(selfie), _b64(idimg))
            score = r.get("matchScore")
            if score is None:
                continue
            (genuine if label == "1" else impostor).append(score)
    if not genuine or not impostor:
        sys.exit("need both genuine (label 1) and impostor (label 0) pairs with detectable faces")
    fmr = sum(1 for s in impostor if s >= thr) / len(impostor)
    fnmr = sum(1 for s in genuine if s < thr) / len(genuine)
    print(f"1:1 match @ threshold {thr}")
    print(f"  genuine pairs  : {len(genuine)}")
    print(f"  impostor pairs : {len(impostor)}")
    print(f"  FMR  (impostor accepted) : {fmr:.4f}")
    print(f"  FNMR (genuine rejected)  : {fnmr:.4f}")


def main():
    ap = argparse.ArgumentParser(description="VERI inference validation harness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pad")
    p.add_argument("--live_dir", required=True)
    p.add_argument("--attack_dir", required=True)
    p.add_argument("--attack_type", default=None)
    p.set_defaults(fn=run_pad)
    m = sub.add_parser("match")
    m.add_argument("--pairs", required=True)
    m.set_defaults(fn=run_match)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
