/** Exact-origin public RPs for the Orchard launch. No wildcards or offline access. */
export const ORCHARD_CLIENTS = {
  'citrate-orchard-preview': ['http://127.0.0.1:3100', 'http://localhost:3100'],
  'citrate-orchard-web': ['https://citrate.ai', 'https://www.citrate.ai'],
  'citrate-orchard-smb': ['https://smb.citrate.ai'],
  'citrate-orchard-enterprise': ['https://enterprise.citrate.ai'],
  'citrate-orchard-schools': ['https://schools.citrate.ai'],
  'citrate-orchard-partnerships': ['https://partnerships.citrate.ai'],
} as const;
/** The landing page a signed-out member returns to (registered post-logout URI path). */
export const ORCHARD_SIGNED_OUT_PATH = '/join?signed_out=1';
export const ORCHARD_CLIENT_IDS: ReadonlySet<string> = new Set(Object.keys(ORCHARD_CLIENTS));
export function buildOrchardProofMessage(args: { authority: string; sub: string; clientId: string; address: string; nonce: string; chainId: number }) {
  return [
    `${args.authority} requests a gas-free proof for the Orchard waitlist.`, '',
    'This signature does not send a transaction, transfer funds, or change your linked wallets.',
    `Identity: ${args.sub}`, `Client: ${args.clientId}`, `Wallet: ${args.address.toLowerCase()}`,
    `Chain ID: ${args.chainId}`, `Nonce: ${args.nonce}`, 'Version: citrate-orchard-proof-1',
  ].join('\n');
}
