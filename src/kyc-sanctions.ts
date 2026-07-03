/**
 * VERI sanctions ingest (VERI-S3-WP3 → production).
 *
 * Fetches the official screening feed, parses it into {@link SanctionsEntry}[], caches
 * it in Postgres (one snapshot row), and hands a live {@link SanctionsScreener} to the
 * verification engine — replacing the empty-list stub.
 *
 * SOURCE (Rule 7 — named): the U.S. **trade.gov Consolidated Screening List (CSL)**, a
 * single feed that consolidates OFAC's SDN + non-SDN lists, the BIS Entity/Denied-Persons
 * lists, and the State Dept lists. Overridable via `SANCTIONS_CSL_URL`. The feed changes
 * multiple times/week, so we refresh daily and at boot (best-effort — a fetch failure
 * never blocks boot; the last snapshot keeps serving).
 *
 * Load path: boot → load the DB snapshot into memory (fast, no network) → if empty/stale,
 * fetch + persist. A daily timer re-fetches. `getSanctionsScreener()` returns the cached
 * screener; the engine screens every case against it.
 */

import { Pool } from 'pg';
import { SanctionsScreener, loadSanctionsList, type SanctionsEntry } from './kyc-screening.js';

const CSL_URL_DEFAULT =
  'https://data.trade.gov/downloadable_consolidated_screening_list/v1/consolidated.csv';
/** Refresh cadence + staleness window. */
const REFRESH_MS = 24 * 60 * 60 * 1000;
const STALE_MS = 36 * 60 * 60 * 1000;

let cached: SanctionsScreener = loadSanctionsList([], 'uninitialized');
let cachedMeta: { version: string; count: number; ingestedAt: number } | null = null;
let pool: Pool | null = null;
let refreshTimer: NodeJS.Timeout | undefined;

/** The live screener the engine uses. Empty (everyone clears) only until first load. */
export function getSanctionsScreener(): SanctionsScreener {
  return cached;
}

/** Snapshot metadata for the admin/status surface. */
export function sanctionsStatus(): { loaded: boolean; version: string; count: number; ingestedAt: number } {
  return {
    loaded: cachedMeta !== null,
    version: cachedMeta?.version ?? 'uninitialized',
    count: cachedMeta?.count ?? 0,
    ingestedAt: cachedMeta?.ingestedAt ?? 0,
  };
}

// ── CSV parsing (RFC-4180-ish: quoted fields, embedded commas/quotes/newlines) ──
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n') {
      row.push(field); field = ''; rows.push(row); row = [];
    } else if (c === '\r') {
      // swallow; \n handles the row break
    } else field += c;
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

/** Parse the CSL CSV into SanctionsEntry[] (maps columns by header name — order-robust). */
export function parseCsl(csv: string): SanctionsEntry[] {
  const rows = parseCsv(csv);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = (name: string) => header.indexOf(name);
  const iName = col('name');
  const iAlt = col('alt_names');
  const iType = col('type');
  const iPrograms = col('programs');
  const iSource = col('source');
  if (iName < 0) return [];
  const out: SanctionsEntry[] = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const name = (row[iName] ?? '').trim();
    if (!name) continue;
    const altRaw = iAlt >= 0 ? (row[iAlt] ?? '') : '';
    const aliases = altRaw
      .split(/;|\n/)
      .map((s) => s.trim())
      .filter((s) => s && s.toLowerCase() !== name.toLowerCase());
    const typeRaw = (iType >= 0 ? row[iType] ?? '' : '').trim().toLowerCase();
    const type: SanctionsEntry['type'] = typeRaw.startsWith('individual') ? 'individual' : 'entity';
    const programs = (iProgramsVal(row, iPrograms) || [])
      .map((p) => p.trim())
      .filter(Boolean);
    const source = (iSource >= 0 ? row[iSource] ?? '' : '').trim() || 'CSL';
    out.push({ name, ...(aliases.length ? { aliases } : {}), type, programs, source });
  }
  return out;
}

function iProgramsVal(row: string[], i: number): string[] {
  if (i < 0) return [];
  return (row[i] ?? '').split(/;|,/).map((s) => s.trim()).filter(Boolean);
}

// ── fetch ──
/** Fetch + parse the CSL feed. Throws on network/HTTP failure (caller is best-effort). */
export async function fetchCsl(
  env: NodeJS.ProcessEnv = process.env,
  now: number = Date.now(),
): Promise<{ entries: SanctionsEntry[]; version: string }> {
  const url = env.SANCTIONS_CSL_URL?.trim() || CSL_URL_DEFAULT;
  const res = await fetch(url, { signal: AbortSignal.timeout(90_000) });
  if (!res.ok) throw new Error(`CSL fetch failed: HTTP ${res.status}`);
  const csv = await res.text();
  const entries = parseCsl(csv);
  if (entries.length === 0) throw new Error('CSL parse produced 0 entries (feed format change?)');
  const version = `CSL-${new Date(now).toISOString().slice(0, 10)}`;
  return { entries, version };
}

// ── snapshot store (one row) ──
async function ensureSchema(p: Pool): Promise<void> {
  await p.query(`CREATE TABLE IF NOT EXISTS sanctions_snapshot (
    id int PRIMARY KEY DEFAULT 1,
    version text NOT NULL,
    entries jsonb NOT NULL,
    ingested_at bigint NOT NULL,
    CONSTRAINT sanctions_snapshot_singleton CHECK (id = 1)
  )`);
}

async function saveSnapshot(p: Pool, entries: SanctionsEntry[], version: string, now: number): Promise<void> {
  await p.query(
    `INSERT INTO sanctions_snapshot (id, version, entries, ingested_at) VALUES (1, $1, $2, $3)
     ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version, entries = EXCLUDED.entries, ingested_at = EXCLUDED.ingested_at`,
    [version, JSON.stringify(entries), now],
  );
}

async function loadSnapshot(p: Pool): Promise<{ entries: SanctionsEntry[]; version: string; ingestedAt: number } | null> {
  const r = await p.query('SELECT version, entries, ingested_at FROM sanctions_snapshot WHERE id = 1');
  if (r.rows.length === 0) return null;
  const row = r.rows[0] as { version: string; entries: SanctionsEntry[]; ingested_at: string };
  return { entries: row.entries, version: row.version, ingestedAt: Number(row.ingested_at) };
}

function install(entries: SanctionsEntry[], version: string, ingestedAt: number): void {
  cached = loadSanctionsList(entries, version);
  cachedMeta = { version, count: entries.length, ingestedAt };
}

/** Fetch the feed + persist + install it. Best-effort; logs + swallows on failure. */
export async function refreshSanctions(now: number = Date.now()): Promise<boolean> {
  if (!pool) return false;
  try {
    const { entries, version } = await fetchCsl(process.env, now);
    await saveSnapshot(pool, entries, version, now);
    install(entries, version, now);
    // eslint-disable-next-line no-console
    console.log(`[kyc] sanctions list refreshed: ${entries.length} entries (${version})`);
    return true;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[kyc] sanctions refresh failed (keeping last snapshot): ${(err as Error).message}`);
    return false;
  }
}

/**
 * Boot the sanctions screener: load the DB snapshot into memory (fast), then refresh if
 * it's missing or stale. Starts a daily refresh timer (unref'd — never holds the process
 * open). Never throws — screening degrades to the last snapshot (or empty) on any failure.
 */
export async function initSanctionsFromEnv(
  databaseUrl: string,
  now: number = Date.now(),
): Promise<void> {
  pool = new Pool({ connectionString: databaseUrl });
  try {
    await ensureSchema(pool);
    const snap = await loadSnapshot(pool);
    if (snap) {
      install(snap.entries, snap.version, snap.ingestedAt);
      // eslint-disable-next-line no-console
      console.log(`[kyc] sanctions snapshot loaded: ${snap.entries.length} entries (${snap.version})`);
    }
    const stale = !snap || now - snap.ingestedAt > STALE_MS;
    if (stale) await refreshSanctions(now);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[kyc] sanctions init failed (screening starts empty): ${(err as Error).message}`);
  }
  if (!refreshTimer) {
    refreshTimer = setInterval(() => void refreshSanctions(Date.now()), REFRESH_MS);
    refreshTimer.unref?.();
  }
}

/** Test seam: install entries directly (bypass DB/network). */
export function _installForTest(entries: SanctionsEntry[], version = 'test'): void {
  install(entries, version, Date.now());
}
