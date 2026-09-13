/**
 * Auth-store abstractions + in-memory implementations + env init
 * (WP-6 slice B of EW-S1).
 *
 * Mirrors the {@link KycStore} pattern in src/kyc.ts:
 *
 *   - One small interface per store so the in-memory dev impl is a true
 *     drop-in for the Postgres-backed prod impl.
 *   - One process-wide singleton per store, swapped at boot by
 *     {@link initAuthStoresFromEnv}.
 *   - `pg` is imported lazily inside the env init so the in-memory path
 *     never pulls in the driver.
 *
 * Used by mountPasswordRoutes + mountWebauthnRoutes to look up / persist
 * users + WebAuthn credentials without caring whether the backing is a
 * Map (dev) or a Postgres table (prod).
 */
import { randomUUID } from 'node:crypto';

import { type PgLike, type UserRecord } from './users-pg.js';
import { type WebAuthnCredentialRecord } from './webauthn-pg.js';

/** User store shape used by the password + webauthn + google HTTP routes. */
export interface UserStore {
  createWithEmailPassword(args: {
    email: string;
    passwordHash: string;
  }): Promise<UserRecord>;
  createWithGoogle(args: {
    googleSub: string;
    email?: string;
  }): Promise<UserRecord>;
  /**
   * Create a user from a non-Google federation (GitHub/Discord/X, FWA #87.3).
   * The email binds (email_verified=true) ONLY when proven — a provider with no
   * proven email (X) creates an email-less account, mirroring createWithGoogle.
   */
  createWithFederated(args: {
    provider: string;
    providerSub: string;
    email?: string;
  }): Promise<UserRecord>;
  /** Look up a user by a federated (provider, providerSub) pair. */
  findByFederated(
    provider: string,
    providerSub: string,
  ): Promise<UserRecord | undefined>;
  /** Link a federated (provider, providerSub) onto an existing user. */
  linkFederated(
    userId: string,
    provider: string,
    providerSub: string,
  ): Promise<void>;
  /**
   * Create a brand-new account with no email/password/Google federation,
   * intended for a first-time passkey signup (WP-A). The caller is
   * expected to immediately insert a WebAuthn credential bound to the
   * returned user id; until that succeeds the row is dangling.
   */
  createWithPasskey(): Promise<UserRecord>;
  findById(id: string): Promise<UserRecord | undefined>;
  findByEmail(email: string): Promise<UserRecord | undefined>;
  findByGoogleSub(googleSub: string): Promise<UserRecord | undefined>;
  /** Link a Google sub to an existing email-only user (used at OAuth
   * callback when the Google account matches an existing email but
   * has no `google_sub` yet). */
  linkGoogleSub(id: string, googleSub: string): Promise<void>;
  /** Bind an explicit wallet address to the user (proven canonical link, or
   * dashboard enrollment); overrides the predicted smart-wallet address in
   * claims. `null` CLEARS the binding so the prediction resumes — pass null
   * rather than an empty string: `account-routes` and `kyc-routes` read this
   * with `??`, and `''` is not nullish, so an empty string would suppress the
   * fallback and yield a blank address instead of the predicted one. */
  setPrimaryWallet(id: string, walletAddress: string | null): Promise<void>;
  /** Record the method of the most recent successful sign-in
   * (`email-pw` | `passkey` | `google`) — surfaced as the
   * `signing_method` OIDC claim (EW-S1 WP-6). */
  setLastSigningMethod(id: string, method: string): Promise<void>;
  /** Flip `email_verified` true. The SOLE caller is the email-verification
   * flow (FWA #87.1) after a Resend OTP is confirmed — an email never binds /
   * provisions / matches a grant until this runs (mirrors the Google guard). */
  markEmailVerified(id: string): Promise<void>;
  /** Set/replace the Argon2id password hash. Used by the verify flow to attach
   * the pending signup password once ownership is proven, and as the
   * email-proven password-reset path. */
  rotatePasswordHash(id: string, passwordHash: string): Promise<void>;
}

/** WebAuthn credential store shape used by the webauthn HTTP routes. */
export interface WebAuthnCredentialStore {
  insertCredential(args: {
    userId: string;
    credentialId: Buffer;
    publicKeyCose: Buffer;
    signCount?: bigint;
    transports?: string[];
    aaguid?: string;
    deviceLabel?: string;
  }): Promise<WebAuthnCredentialRecord>;
  findByCredentialId(
    credentialId: Buffer,
  ): Promise<WebAuthnCredentialRecord | undefined>;
  listByUserId(userId: string): Promise<WebAuthnCredentialRecord[]>;
  recordAssertion(credentialId: Buffer, newSignCount: bigint): Promise<void>;
}

// ─────────────────────────────────────────────────────────────────────
//  In-memory implementations (dev/test) — see KycStore's InMemoryKycStore
//  for the precedent: a Map is correct for single-instance, and production
//  swaps in the Pg variant via {@link initAuthStoresFromEnv}.
// ─────────────────────────────────────────────────────────────────────

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export class InMemoryUserStore implements UserStore {
  private readonly byId = new Map<string, UserRecord>();
  private readonly byEmail = new Map<string, string>();
  private readonly byGoogleSub = new Map<string, string>();
  /** key = `${provider}:${providerSub}` → user id (FWA #87.3). */
  private readonly byFederated = new Map<string, string>();

  async createWithEmailPassword(args: {
    email: string;
    passwordHash: string;
  }): Promise<UserRecord> {
    const id = randomUUID();
    const email = normalizeEmail(args.email);
    if (this.byEmail.has(email)) {
      throw new Error('email already registered');
    }
    const now = new Date();
    const rec: UserRecord = {
      id,
      email,
      emailVerified: false,
      passwordHash: args.passwordHash,
      createdAt: now,
      updatedAt: now,
    };
    this.byId.set(id, rec);
    this.byEmail.set(email, id);
    return rec;
  }

  async createWithGoogle(args: {
    googleSub: string;
    email?: string;
  }): Promise<UserRecord> {
    if (this.byGoogleSub.has(args.googleSub)) {
      throw new Error('google sub already registered');
    }
    const id = randomUUID();
    const email = args.email ? normalizeEmail(args.email) : undefined;
    if (email && this.byEmail.has(email)) {
      throw new Error('email already registered');
    }
    const now = new Date();
    const rec: UserRecord = {
      id,
      ...(email !== undefined ? { email } : {}),
      // FWA-C6-01: an email reaches createWithGoogle ONLY after the caller has
      // confirmed `email_verified === true` on the id_token (see
      // resolveGoogleUser / trustedEmailFromIdToken). A signed id_token alone
      // does NOT prove email ownership, so the presence of an email here is the
      // *verified* signal — an account created with no email is unverified.
      emailVerified: email !== undefined,
      googleSub: args.googleSub,
      createdAt: now,
      updatedAt: now,
    };
    this.byId.set(id, rec);
    if (email) this.byEmail.set(email, id);
    this.byGoogleSub.set(args.googleSub, id);
    return rec;
  }

  async createWithFederated(args: {
    provider: string;
    providerSub: string;
    email?: string;
  }): Promise<UserRecord> {
    const key = `${args.provider}:${args.providerSub}`;
    if (this.byFederated.has(key)) {
      throw new Error('federated identity already registered');
    }
    const id = randomUUID();
    const email = args.email ? normalizeEmail(args.email) : undefined;
    if (email && this.byEmail.has(email)) {
      throw new Error('email already registered');
    }
    const now = new Date();
    const rec: UserRecord = {
      id,
      ...(email !== undefined ? { email } : {}),
      // Same posture as createWithGoogle: the presence of an email here is the
      // *proven* signal; an email-less federation (X) is unverified.
      emailVerified: email !== undefined,
      createdAt: now,
      updatedAt: now,
    };
    this.byId.set(id, rec);
    if (email) this.byEmail.set(email, id);
    this.byFederated.set(key, id);
    return rec;
  }

  async findByFederated(
    provider: string,
    providerSub: string,
  ): Promise<UserRecord | undefined> {
    const id = this.byFederated.get(`${provider}:${providerSub}`);
    return id ? this.byId.get(id) : undefined;
  }

  async linkFederated(
    userId: string,
    provider: string,
    providerSub: string,
  ): Promise<void> {
    const key = `${provider}:${providerSub}`;
    if (this.byFederated.has(key)) throw new Error('federated identity already linked');
    if (!this.byId.has(userId)) return;
    this.byFederated.set(key, userId);
  }

  async createWithPasskey(): Promise<UserRecord> {
    const id = randomUUID();
    const now = new Date();
    const rec: UserRecord = {
      id,
      emailVerified: false,
      createdAt: now,
      updatedAt: now,
    };
    this.byId.set(id, rec);
    return rec;
  }

  async findById(id: string): Promise<UserRecord | undefined> {
    return this.byId.get(id);
  }

  async findByEmail(email: string): Promise<UserRecord | undefined> {
    const id = this.byEmail.get(normalizeEmail(email));
    return id ? this.byId.get(id) : undefined;
  }

  async findByGoogleSub(googleSub: string): Promise<UserRecord | undefined> {
    const id = this.byGoogleSub.get(googleSub);
    return id ? this.byId.get(id) : undefined;
  }

  async linkGoogleSub(id: string, googleSub: string): Promise<void> {
    const rec = this.byId.get(id);
    if (!rec) return;
    if (rec.googleSub !== undefined) {
      throw new Error('user already has a google sub');
    }
    rec.googleSub = googleSub;
    rec.emailVerified = true;
    rec.updatedAt = new Date();
    this.byGoogleSub.set(googleSub, id);
  }

  async setPrimaryWallet(id: string, walletAddress: string | null): Promise<void> {
    const rec = this.byId.get(id);
    if (!rec) return;
    if (walletAddress === null) delete rec.primaryWallet;
    else rec.primaryWallet = walletAddress.toLowerCase();
    rec.updatedAt = new Date();
  }

  async setLastSigningMethod(id: string, method: string): Promise<void> {
    const rec = this.byId.get(id);
    if (!rec) return;
    rec.lastSigningMethod = method;
    rec.updatedAt = new Date();
  }

  async markEmailVerified(id: string): Promise<void> {
    const rec = this.byId.get(id);
    if (!rec) return;
    rec.emailVerified = true;
    rec.updatedAt = new Date();
  }

  async rotatePasswordHash(id: string, passwordHash: string): Promise<void> {
    const rec = this.byId.get(id);
    if (!rec) return;
    rec.passwordHash = passwordHash;
    rec.updatedAt = new Date();
  }
}

export class InMemoryWebAuthnCredentialStore
  implements WebAuthnCredentialStore
{
  private readonly byCredentialId = new Map<string, WebAuthnCredentialRecord>();

  async insertCredential(args: {
    userId: string;
    credentialId: Buffer;
    publicKeyCose: Buffer;
    signCount?: bigint;
    transports?: string[];
    aaguid?: string;
    deviceLabel?: string;
  }): Promise<WebAuthnCredentialRecord> {
    const key = args.credentialId.toString('base64url');
    if (this.byCredentialId.has(key)) {
      throw new Error('credential already registered');
    }
    const rec: WebAuthnCredentialRecord = {
      id: randomUUID(),
      userId: args.userId,
      credentialId: args.credentialId,
      publicKeyCose: args.publicKeyCose,
      signCount: args.signCount ?? 0n,
      transports: args.transports ?? [],
      ...(args.aaguid !== undefined ? { aaguid: args.aaguid } : {}),
      ...(args.deviceLabel !== undefined ? { deviceLabel: args.deviceLabel } : {}),
      createdAt: new Date(),
    };
    this.byCredentialId.set(key, rec);
    return rec;
  }

  async findByCredentialId(
    credentialId: Buffer,
  ): Promise<WebAuthnCredentialRecord | undefined> {
    return this.byCredentialId.get(credentialId.toString('base64url'));
  }

  async listByUserId(userId: string): Promise<WebAuthnCredentialRecord[]> {
    return Array.from(this.byCredentialId.values()).filter(
      (c) => c.userId === userId,
    );
  }

  async recordAssertion(
    credentialId: Buffer,
    newSignCount: bigint,
  ): Promise<void> {
    const rec = this.byCredentialId.get(credentialId.toString('base64url'));
    if (!rec) return;
    rec.signCount = newSignCount;
    rec.lastUsedAt = new Date();
  }
}

// ─────────────────────────────────────────────────────────────────────
//  Process-wide singletons + env init.
// ─────────────────────────────────────────────────────────────────────

let userStore: UserStore = new InMemoryUserStore();
let webauthnStore: WebAuthnCredentialStore =
  new InMemoryWebAuthnCredentialStore();

/** The live user store the auth routes read/write. */
export function getUserStore(): UserStore {
  return userStore;
}

/** Swap the live user store (production wiring / tests). */
export function setUserStore(store: UserStore): void {
  userStore = store;
}

/** The live WebAuthn credential store the auth routes read/write. */
export function getWebAuthnStore(): WebAuthnCredentialStore {
  return webauthnStore;
}

/** Swap the live WebAuthn credential store (production wiring / tests). */
export function setWebAuthnStore(store: WebAuthnCredentialStore): void {
  webauthnStore = store;
}

/**
 * Install the right user + credential stores for the running environment.
 * Mirrors {@link initKycStoreFromEnv}:
 *
 *   - `DATABASE_URL` set  → Postgres-backed {@link PgUserStore} +
 *     {@link PgWebAuthnCredentialStore}; both share a single `pg.Pool`.
 *     `ensureSchema()` runs idempotently so the tables exist.
 *   - `DATABASE_URL` unset → in-memory dev stores with a one-line warning.
 *     In PRODUCTION an unset `DATABASE_URL` never reaches here:
 *     `assertProductionConfig` throws first (TD-1).
 *
 * The `pg` driver is imported lazily inside the DATABASE_URL branch so the
 * in-memory path never pulls it in.
 */
export async function initAuthStoresFromEnv(
  env: { DATABASE_URL?: string } = process.env,
): Promise<void> {
  const databaseUrl = env.DATABASE_URL;
  if (databaseUrl && databaseUrl.trim() !== '') {
    const { Pool } = await import('pg');
    const { PgUserStore } = await import('./users-pg.js');
    const { PgWebAuthnCredentialStore } = await import('./webauthn-pg.js');
    const pool = new Pool({ connectionString: databaseUrl });
    const u = new PgUserStore(pool as unknown as PgLike);
    const w = new PgWebAuthnCredentialStore(pool as unknown as PgLike);
    await u.ensureSchema();
    await w.ensureSchema();
    setUserStore(u);
    setWebAuthnStore(w);
    return;
  }
  // eslint-disable-next-line no-console
  console.warn(
    '[citrate-identity] DATABASE_URL unset — using the in-memory user + ' +
      'webauthn-credential stores (records are lost on restart and not shared ' +
      'across instances). Set DATABASE_URL to back auth with Postgres ' +
      '(required in production).',
  );
  setUserStore(new InMemoryUserStore());
  setWebAuthnStore(new InMemoryWebAuthnCredentialStore());
}
