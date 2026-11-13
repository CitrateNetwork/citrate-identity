/**
 * A software WebAuthn authenticator for tests: real P-256 keys, a real
 * `none`-format attestation and real ECDSA assertions, so the server's
 * @simplewebauthn verification runs unmodified. It behaves like a platform
 * passkey store: credentials are discoverable (resident), keyed by RP ID, and
 * carry the user handle the RP set at registration.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

interface StoredCredential {
  id: Buffer;
  rpId: string;
  userHandle: Buffer;
  userName: string;
  privateKey: KeyObject;
  signCount: number;
}

const b64u = (b: Buffer | Uint8Array): string => Buffer.from(b).toString('base64url');
const sha256 = (b: Buffer | string): Buffer => createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  readonly credentials: StoredCredential[] = [];

  /** navigator.credentials.create() */
  create(options: PublicKeyCredentialCreationOptionsJSON, origin: string): RegistrationResponseJSON {
    const rpId = options.rp.id ?? new URL(origin).hostname;
    for (const ex of options.excludeCredentials ?? []) {
      if (this.credentials.some((c) => b64u(c.id) === ex.id)) throw new Error('InvalidStateError');
    }
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    const cose = new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, Buffer.from(jwk.x, 'base64url')],
      [-3, Buffer.from(jwk.y, 'base64url')],
    ]);
    const id = randomBytes(32);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(id.length);
    const authData = Buffer.concat([
      sha256(rpId),
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4), // signCount 0
      Buffer.alloc(16), // aaguid
      idLen,
      id,
      Buffer.from(isoCBOR.encode(cose as never)),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]) as never,
    );
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }),
    );
    this.credentials.push({
      id,
      rpId,
      userHandle: Buffer.from(options.user.id, 'base64url'),
      userName: options.user.name,
      privateKey,
      signCount: 0,
    });
    return {
      id: b64u(id),
      rawId: b64u(id),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    };
  }

  /**
   * navigator.credentials.get(). With an empty allowCredentials (discoverable
   * sign-in) the "user" picks the credential named `pick`, else the first one
   * for the RP. Throws NotAllowedError when nothing matches, as a browser does.
   */
  get(
    options: PublicKeyCredentialRequestOptionsJSON,
    origin: string,
    pick?: (c: StoredCredential) => boolean,
  ): AuthenticationResponseJSON {
    const rpId = options.rpId ?? new URL(origin).hostname;
    const allowed = new Set((options.allowCredentials ?? []).map((c) => c.id));
    const cred = this.credentials.find(
      (c) => c.rpId === rpId && (allowed.size === 0 || allowed.has(b64u(c.id))) && (!pick || pick(c)),
    );
    if (!cred) throw new Error('NotAllowedError');
    cred.signCount += 1;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(cred.signCount);
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x05]), count]); // UP | UV
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }),
    );
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), cred.privateKey);
    return {
      id: b64u(cred.id),
      rawId: b64u(cred.id),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: b64u(cred.userHandle),
      },
      clientExtensionResults: {},
    };
  }
}
