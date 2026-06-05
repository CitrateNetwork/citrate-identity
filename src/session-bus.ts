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
 * SEAM: this in-process {@link SessionBus} is a Node EventEmitter, correct for the
 * single authority instance. For a multi-instance / HA deployment the SAME
 * `publish`/`subscribe` shape is backed by Redis pub/sub ({@link RedisSessionBus}),
 * selected by `REDIS_URL`, so an event published on instance A reaches subscribers
 * on instance B (the logout cascade has to cross instances). The interface is
 * deliberately small so the swap is a drop-in — the same pattern as the NonceStore
 * seam (siwe.ts) and the KycStore seam (kyc.ts).
 */
import { EventEmitter } from 'node:events';
import type { RedisLike } from './redis.js';

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

/** The Redis pub/sub channel logout events are published on, cluster-wide. */
const REDIS_CHANNEL = 'citrate:session';

/**
 * Redis pub/sub session bus (HA / multi-instance).
 *
 * Backs the EXISTING {@link SessionBusLike} seam with Redis pub/sub so a `logout`
 * published on instance A reaches the `/sessions/events` SSE subscribers attached
 * to instance B — the cascade is only honest if it crosses instances.
 *
 * Redis pub/sub requires a DEDICATED subscriber connection (a client in
 * subscribe mode cannot issue normal commands), so we take the shared client as
 * the PUBLISHER and `duplicate()` it for the SUBSCRIBER. Local handlers are kept
 * in a Set and fanned out from the single `message` listener; `publish` is a
 * fire-and-forget `PUBLISH` (matching the void in-memory shape — a logout must
 * not block the HTTP response on a broker round-trip), and a `subscribe` failure
 * surfaces on the publisher's error channel rather than throwing into the caller.
 */
export class RedisSessionBus implements SessionBusLike {
  private readonly subscriber: RedisLike;
  private readonly handlers = new Set<SessionEventHandler>();
  private subscribed = false;

  /** @param publisher the shared {@link RedisLike}; a duplicate is the subscriber. */
  constructor(private readonly publisher: RedisLike) {
    this.subscriber = publisher.duplicate();
    // One message listener fans out to every local handler. Set up before the
    // SUBSCRIBE so no early message is missed.
    this.subscriber.on('message', (...args: unknown[]) => {
      const [channel, raw] = args as [string, string];
      if (channel !== REDIS_CHANNEL) return;
      let event: SessionEvent;
      try {
        event = JSON.parse(raw) as SessionEvent;
      } catch {
        // A malformed message is not actionable; drop it rather than crash the
        // listener (which would silence the whole cascade on this instance).
        return;
      }
      for (const handler of this.handlers) handler(event);
    });
  }

  /** Establish the SUBSCRIBE once (idempotent). Awaited at boot wiring time. */
  async start(): Promise<void> {
    if (this.subscribed) return;
    this.subscribed = true;
    await this.subscriber.subscribe(REDIS_CHANNEL);
  }

  /**
   * Publish an event for `sub`. Fire-and-forget `PUBLISH` so the logout HTTP
   * response is not blocked on the broker. `sub` is supplied separately so the
   * body can never disagree with its subject (mirrors {@link SessionBus}).
   */
  publish(sub: string, event: Omit<SessionEvent, 'sub'>): void {
    const full: SessionEvent = { ...event, sub };
    void this.publisher.publish(REDIS_CHANNEL, JSON.stringify(full));
  }

  /**
   * Subscribe to every published event. Returns an unsubscribe function; call it
   * (e.g. when an SSE client disconnects) so handlers never leak. The underlying
   * Redis SUBSCRIBE stays up for the bus's lifetime — handlers are multiplexed
   * over the one connection.
   */
  subscribe(handler: SessionEventHandler): Unsubscribe {
    this.handlers.add(handler);
    // Lazily ensure the SUBSCRIBE is live even if start() wasn't called (defensive
    // for direct construction in tests); idempotent.
    void this.start();
    return () => {
      this.handlers.delete(handler);
    };
  }

  /** Close the dedicated subscriber connection (process shutdown). */
  async close(): Promise<void> {
    await this.subscriber.quit();
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
