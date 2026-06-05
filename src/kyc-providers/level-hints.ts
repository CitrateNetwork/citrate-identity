/**
 * Vendor-neutral level taxonomy. Callers pass one of these constants to
 * {@link KycProvider.createApplicant} via `levelHint`; adapters resolve
 * the string to their own taxonomy (Sumsub dashboard `levelName`, CLEAR
 * Project id).
 *
 * **This is the only place vendor-specific strings should be
 * mapped from.** If a vendor string appears anywhere else in
 * `citrate-identity`, that's a leak — fix it before merge.
 *
 * Adding a new level here is cheap. Adding it without also adding the
 * mapping in every adapter is a compile error (each adapter's
 * resolution map is exhaustive-checked at construction).
 */

export const KYC_LEVELS = {
  /**
   * The default individual KYC for Citrate T2 actions:
   * government-issued ID + selfie + liveness check. Triggers the
   * Sumsub AML add-on (person sanctions screen) on the Level we
   * configured in the Sumsub dashboard.
   */
  BASIC_INDIVIDUAL: 'basic-individual',

  /**
   * Reserved for higher-friction onboarding (address proof + AML
   * monitoring); not used at COMP-S1. Adapters MAY return a
   * NotConfigured error until COMP-S4.
   */
  ENHANCED_INDIVIDUAL: 'enhanced-individual',

  /**
   * Entity / business verification (KYB). Configured on the Sumsub
   * side at COMP-S4. The constant ships here so the interface is
   * forward-compatible; current adapters MUST throw a clear error
   * if asked to resolve it before that sprint.
   */
  KYB_ENTITY: 'kyb-entity',
} as const;

/** Allowed `levelHint` strings, narrowed via a string-literal union. */
export type KycLevel = (typeof KYC_LEVELS)[keyof typeof KYC_LEVELS];

/**
 * Type guard that lets adapter resolution maps stay exhaustive-checked
 * without runtime cost.
 */
export function isKycLevel(s: string): s is KycLevel {
  return (Object.values(KYC_LEVELS) as string[]).includes(s);
}
