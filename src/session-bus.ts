/**
 * Session bus (IDP-S2 / TD-5).
 *
 * "One login everywhere" is only honest if logout is also everywhere: when a user
 * logs out of one relying party, the authority must tell the OTHERS so they drop
 * their local session too. The bus is that fan-out channel. `/logout` (see
 * logout-routes.ts) publishes a `logout` event for a `sub`; relying parties (or a
 * server-side fan-out like our SSE endpoint `/sessions/events`) subscribe and
 * reflect logged-out state.
 *
 * SEAM (not a TODO): this in-process {@link SessionBus} is a Node EventEmitter,
 * correct for the single authority instance. For a multi-instance / HA deployment
 * the SAME `publish`/`subscribe` shape is backed by Redis pub/sub (or another
 * broker) so an event published on instance A reaches subscribers on instance B.
 * The interface is deliberately small so that swap is a drop-in — exactly the same
 * pattern as the NonceStore seam (siwe.ts) and the KycStore seam (kyc.ts). A
 * `RedisSessionBus implements SessionBusLike` lands when the authority goes HA.
 */
import { EventEmitter } from 'node:events';

/** The kinds of session-lifecycle events the bus carries. Only logout for now. */
export type SessionEventType = 'logout';

/**
 * A session-lifecycle event. Closed shape — `sub` is the subject (wallet address)
 * the event is about, `sid` the optional session id that was ended, and `at` the
 * epoch-ms the event was published. No PII; just identifiers + a timestamp.
 */
export interface SessionEvent {
  type: SessionEventType;
  /** The subject (OIDC `sub` = wallet address) the event concerns. */
  sub: string;
  /** The session id that ended, when the logout targeted a specific session. */
  sid?: string;
  /** Epoch-ms the event was published. */
  at: number;
}

/** Handler invoked for every published event. */
export type SessionEventHandler = (event: SessionEvent) => void;

/** Unsubscribe function returned by {@link SessionBus.subscribe}. */
export type Unsubscribe = () => void;

/**
 * The bus contract. {@link SessionBus} is the in-process implementation; a future
 * `RedisSessionBus` implements the same shape for multi-instance fan-out.
 */
export interface SessionBusLike {
  publish(sub: string, event: Omit<SessionEvent, 'sub'>): void;
  subscribe(handler: SessionEventHandler): Unsubscribe;
}

/** The single channel name used on the underlying emitter. */
const CHANNEL = 'session';

export class SessionBus implements SessionBusLike {
  private readonly emitter = new EventEmitter();

  constructor() {
    // Logout fan-out can have many listeners (one per SSE client + RP webhooks).
    // The default cap of 10 would warn under load; lift it (0 = unlimited) since
    // we add/remove listeners deliberately and never leak them.
    this.emitter.setMaxListeners(0);
  }

  /**
   * Publish an event for `sub`. The `sub` is supplied separately so callers
   * cannot accidentally publish an event whose body disagrees with its subject.
   */
  publish(sub: string, event: Omit<SessionEvent, 'sub'>): void {
    const full: SessionEvent = { ...event, sub };
    this.emitter.emit(CHANNEL, full);
  }

  /**
   * Subscribe to every published event. Returns an unsubscribe function; call it
   * to detach (e.g. when an SSE client disconnects) so listeners never leak.
   */
  subscribe(handler: SessionEventHandler): Unsubscribe {
    this.emitter.on(CHANNEL, handler);
    return () => {
      this.emitter.off(CHANNEL, handler);
    };
  }
}

/**
 * Process-wide session bus singleton. Like the KYC store, the bus is a module
 * singleton because the route handlers (logout publisher, SSE subscriber) live in
 * different modules and must share ONE channel. Tests can swap it via
 * {@link setSessionBus} to assert published events in isolation.
 */
let sessionBus: SessionBusLike = new SessionBus();

/** The live session bus the authority publishes logout events on. */
export function getSessionBus(): SessionBusLike {
  return sessionBus;
}

/** Swap the live session bus (multi-instance wiring / tests). */
export function setSessionBus(bus: SessionBusLike): void {
  sessionBus = bus;
}
