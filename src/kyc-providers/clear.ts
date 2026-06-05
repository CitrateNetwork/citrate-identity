/**
 * ClearKycProvider — typed stub.
 *
 * Per `ADR-2026-06-05-kyc-vendor-order`, the CLEAR adapter ships as a
 * typed stub in the COMP-S1 sprint so that:
 *
 *   1. The `KycProvider` interface gets a second implementation point
 *      from day one (compile-checked).
 *   2. Production refuses to boot with `KYC_PROVIDER=clear` until the
 *      partnership closes and a real implementation lands.
 *   3. Caller code never branches on adapter identity; the factory in
 *      `./index.ts` is the only place vendor selection happens.
 *
 * When the partnership closes, fill in the methods, run the contract
 * tests, and remove this banner.
 */

import type {
  KycEvent,
  KycProvider,
  KycProviderBaseConfig,
  KycStatus,
} from './types.js';

/** Construction config — placeholder; real fields land with the impl. */
export interface ClearKycProviderConfig extends KycProviderBaseConfig {
  clientId?: string;
  clientSecret?: string;
  webhookBearerToken?: string;
  baseUrl?: string;
}

/** Thrown by every method until the adapter is implemented. */
export class ClearAdapterNotImplementedError extends Error {
  constructor(method: string) {
    super(
      `ClearProvider.${method} is not yet implemented — see ` +
        `citrate-federation/.agentile/adrs/ADR-2026-06-05-kyc-vendor-order.md`,
    );
    this.name = 'ClearAdapterNotImplementedError';
  }
}

export class ClearKycProvider implements KycProvider {
  // The constructor is allowed to succeed so the type system sees a
  // concrete instance. Per the ADR, the factory refuses to bind this
  // adapter in production via assertProductionConfig; in development
  // the instance is loadable but every method throws.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_config: ClearKycProviderConfig) {}

  async createApplicant(): Promise<{ applicantId: string }> {
    throw new ClearAdapterNotImplementedError('createApplicant');
  }

  async mintClientSession(): Promise<{
    token: string;
    expiresAt: number;
    redirectUrl?: string;
  }> {
    throw new ClearAdapterNotImplementedError('mintClientSession');
  }

  verifyWebhook(): boolean {
    throw new ClearAdapterNotImplementedError('verifyWebhook');
  }

  async parseWebhookEvent(): Promise<KycEvent> {
    throw new ClearAdapterNotImplementedError('parseWebhookEvent');
  }

  async getApplicantStatus(): Promise<KycStatus> {
    throw new ClearAdapterNotImplementedError('getApplicantStatus');
  }

  async deleteApplicant(): Promise<void> {
    throw new ClearAdapterNotImplementedError('deleteApplicant');
  }
}
