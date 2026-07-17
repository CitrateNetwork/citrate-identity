import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

/**
 * AV-S1 model supply-chain gate (planset 2026-07-16-kyc-autoverify).
 *
 * verify_models.sh is the fail-closed boot gate for the inference service: it re-checks
 * every model file against MODELS.lock before uvicorn serves. These tests pin that
 * behavior so a regression (e.g. reverting to warn-and-continue) fails CI. They exercise
 * the real shell script — not a re-implementation — via a temp $KYC_MODELS_DIR.
 */

const SCRIPT = join(process.cwd(), 'services/kyc-inference/verify_models.sh');
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');

let dir: string;

function runVerify(modelsDir: string) {
  return spawnSync('bash', [SCRIPT], {
    env: { ...process.env, KYC_MODELS_DIR: modelsDir },
    encoding: 'utf8',
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'veri-models-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('verify_models.sh — fail-closed model integrity gate (AV-S1)', () => {
  it('exits 0 when every file matches MODELS.lock', () => {
    const anti = Buffer.from('fake-anti-spoof-onnx-bytes');
    writeFileSync(join(dir, 'anti_spoof.onnx'), anti);
    mkdirSync(join(dir, 'models', 'buffalo_l'), { recursive: true });
    const det = Buffer.from('fake-buffalo-det-onnx');
    writeFileSync(join(dir, 'models', 'buffalo_l', 'det_10g.onnx'), det);
    writeFileSync(
      join(dir, 'MODELS.lock'),
      `# lock\n${sha256(anti)}  anti_spoof.onnx\n${sha256(det)}  models/buffalo_l/det_10g.onnx\n`,
    );
    const r = runVerify(dir);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/all 2 model file\(s\) verified/);
  });

  it('FAIL-CLOSED: exits non-zero on a hash mismatch (tampered weights)', () => {
    const anti = Buffer.from('genuine-bytes');
    writeFileSync(join(dir, 'anti_spoof.onnx'), anti);
    // Lock records the genuine hash…
    writeFileSync(join(dir, 'MODELS.lock'), `${sha256(anti)}  anti_spoof.onnx\n`);
    // …but the on-disk file is then swapped for a different artifact.
    writeFileSync(join(dir, 'anti_spoof.onnx'), Buffer.from('SWAPPED-malicious-bytes'));
    const r = runVerify(dir);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/MISMATCH|refusing to start/);
  });

  it('FAIL-CLOSED: exits non-zero when MODELS.lock is absent', () => {
    writeFileSync(join(dir, 'anti_spoof.onnx'), Buffer.from('bytes'));
    const r = runVerify(dir);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/no .*MODELS\.lock/);
  });

  it('FAIL-CLOSED: exits non-zero when a locked file is missing from the volume', () => {
    writeFileSync(join(dir, 'MODELS.lock'), `${sha256(Buffer.from('x'))}  anti_spoof.onnx\n`);
    const r = runVerify(dir);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/MISSING|refusing to start/);
  });
});
