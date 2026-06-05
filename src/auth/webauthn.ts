/**
 * Server-side WebAuthn (passkey) registration + assertion helpers
 * (WP-6 of EW-S1).
 *
 * Wraps `@simplewebauthn/server` with Citrate-flavoured defaults:
 *
 * - **Relying Party**: `auth.citrate.ai` (configurable for dev / staging).
 * - **Origin**: matched against `ISSUER_URL` so passkeys registered on
 *   a dev origin don't validate against a prod one.
 * - **Algorithms**: ES256 (P-256) and EdDSA. Aligns with WebAuthn
 *   Level 3 PRF guidance + the on-chain P-256 verifier in the wallet
 *   stack (`ADR-2026-06-05-ew-wallet-stack`).
 * - **User verification**: required by default — the on-chain
 *   `WebAuthnP256Validator` reads the same flag at install time, so
 *   the OS will always enforce a biometric/PIN.
 */

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';

/** Relying-party identity Citrate's WebAuthn uses. */
export interface RelyingPartyConfig {
  /** Public hostname of the issuer — the WebAuthn "rpID". */
  rpId: string;
  /** Display name shown to the user during the prompt. */
  rpName: string;
  /** Allowed origin(s) — typically a single ISSUER_URL. */
  expectedOrigin: string | string[];
}

const ALGORITHMS = [-7, -8, -257] as const; // ES256 (-7), EdDSA (-8), RS256 (-257) as fallback

/**
 * Generate registration options to start a navigator.credentials.create()
 * flow. Caller persists `options.challenge` in the user's interaction
 * session so the subsequent `verifyRegistration` can replay it.
 */
export async function buildRegistrationOptions(args: {
  rp: RelyingPartyConfig;
  /** Citrate user UUID. */
  userId: string;
  /** Human-readable label (email or display name). */
  userName: string;
  /** Optional display name distinct from `userName`. */
  userDisplayName?: string;
  /** Credentials we already know about — prevents re-registering one. */
  excludeCredentialIds?: Buffer[];
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
  return generateRegistrationOptions({
    rpID: args.rp.rpId,
    rpName: args.rp.rpName,
    userID: Buffer.from(args.userId, 'utf8'),
    userName: args.userName,
    userDisplayName: args.userDisplayName ?? args.userName,
    attestationType: 'none',
    excludeCredentials: (args.excludeCredentialIds ?? []).map((id) => ({
      id: id.toString('base64url'),
      transports: undefined,
    })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    // Use SHA-256 to align with the on-chain WebAuthn verifier.
    supportedAlgorithmIDs: [...ALGORITHMS],
  });
}

/** Verify a registration response and extract the credential record we persist. */
export async function verifyRegistration(args: {
  rp: RelyingPartyConfig;
  expectedChallenge: string;
  response: RegistrationResponseJSON;
}): Promise<{
  ok: true;
  credentialId: Buffer;
  publicKeyCose: Buffer;
  signCount: bigint;
  transports: string[];
  aaguid?: string;
}> {
  const verified = await verifyRegistrationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    requireUserVerification: true,
  });

  if (!verified.verified || !verified.registrationInfo) {
    throw new Error('webauthn: registration verification failed');
  }

  const info = verified.registrationInfo;
  const credId = Buffer.from(info.credential.id, 'base64url');

  return {
    ok: true,
    credentialId: credId,
    publicKeyCose: Buffer.from(info.credential.publicKey),
    signCount: BigInt(info.credential.counter),
    transports: (info.credential.transports ?? []) as string[],
    aaguid: info.aaguid && info.aaguid !== '00000000-0000-0000-0000-000000000000'
      ? info.aaguid
      : undefined,
  };
}

/** Generate authentication options to start a navigator.credentials.get() flow. */
export async function buildAuthenticationOptions(args: {
  rp: RelyingPartyConfig;
  allowCredentialIds?: Buffer[];
}): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({
    rpID: args.rp.rpId,
    userVerification: 'required',
    allowCredentials: (args.allowCredentialIds ?? []).map((id) => ({
      id: id.toString('base64url'),
      transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'] as AuthenticatorTransportFuture[],
    })),
  });
}

/** Verify an authentication assertion against a stored credential. */
export async function verifyAuthentication(args: {
  rp: RelyingPartyConfig;
  expectedChallenge: string;
  response: AuthenticationResponseJSON;
  storedCredential: {
    credentialId: Buffer;
    publicKeyCose: Buffer;
    signCount: bigint;
  };
}): Promise<{ ok: true; newSignCount: bigint }> {
  const verified = await verifyAuthenticationResponse({
    response: args.response,
    expectedChallenge: args.expectedChallenge,
    expectedOrigin: args.rp.expectedOrigin,
    expectedRPID: args.rp.rpId,
    requireUserVerification: true,
    credential: {
      id: args.storedCredential.credentialId.toString('base64url'),
      publicKey: new Uint8Array(args.storedCredential.publicKeyCose),
      counter: Number(args.storedCredential.signCount),
    },
  });

  if (!verified.verified) {
    throw new Error('webauthn: authentication verification failed');
  }
  return { ok: true, newSignCount: BigInt(verified.authenticationInfo.newCounter) };
}

/** Compute the RP id from an issuer URL — strips scheme + port. */
export function rpIdFromIssuer(issuerUrl: string): string {
  const u = new URL(issuerUrl);
  return u.hostname;
}
