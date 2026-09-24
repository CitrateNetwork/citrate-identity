/**
 * Package provenance (2026-09-24 pre-bounty audit, PBA-L6-004): every
 * publishable package must name its canonical source so consumers can audit
 * what they install. @citrate/oidc-client declared no repository at all.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const pkg = JSON.parse(
  readFileSync(join(__dirname, '..', 'packages', 'oidc-client', 'package.json'), 'utf8'),
);

describe('@citrate/oidc-client provenance', () => {
  it('points at github.com/CitrateNetwork/citrate-identity with its real subpath', () => {
    expect(pkg.repository?.url).toBe('git+https://github.com/CitrateNetwork/citrate-identity.git');
    expect(pkg.repository?.directory).toBe('packages/oidc-client');
  });
});
