import { afterEach, describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import {
  RedisSessionBus,
  type SessionEvent,
} from '../src/session-bus.js';
import type { RedisLike } from '../src/redis.js';

/**
 * RedisSessionBus (HA): the logout cascade backed by Redis pub/sub so a `logout`
 * published on one authority instance reaches the `/sessions/events` SSE
 * subscribers on a DIFFERENT instance. Runs against `ioredis-mock`, whose pub/sub
 * is shared across clients in-process — exactly the cross-instance topology.
 */

function freshRedis(): RedisLike {
  return new RedisMock() as unknown as RedisLike;
}

/** Resolve once `handler` receives an event, or reject after a short timeout. */
function nextEvent(
  bus: RedisSessionBus,
  timeoutMs = 1000,
): Promise<SessionEvent> {
  return new Promise<SessionEvent>((resolve, reject) => {
    const unsubscribe = bus.subscribe((event) => {
      unsubscribe();
      resolve(event);
    });
    setTimeout(() => {
      unsubscribe();
      reject(new Error('timed out waiting for a session event'));
    }, timeoutMs);
  });
}

describe('RedisSessionBus (cross-instance logout fan-out)', () => {
  const buses: RedisSessionBus[] = [];

  afterEach(async () => {
    for (const b of buses.splice(0)) await b.close();
  });

  it('publish on instance A → a subscriber on instance B receives the logout event', async () => {
    // Two SEPARATE mock clients = two authority instances sharing one Redis.
    const publisherA = new RedisSessionBus(freshRedis());
    const subscriberB = new RedisSessionBus(freshRedis());
    buses.push(publisherA, subscriberB);
    await publisherA.start();
    await subscriberB.start();

    const received = nextEvent(subscriberB);

    // Instance A publishes a logout for a wallet; instance B must hear it.
    publisherA.publish('0xWALLET', {
      type: 'logout',
      sid: 'session-123',
      at: 1_700_000_000_000,
    });

    const event = await received;
    expect(event).toEqual({
      type: 'logout',
      sub: '0xWALLET',
      sid: 'session-123',
      at: 1_700_000_000_000,
    });
  });

  it('unsubscribe stops delivery (no leak)', async () => {
    const bus = new RedisSessionBus(freshRedis());
    buses.push(bus);
    await bus.start();

    let count = 0;
    const unsubscribe = bus.subscribe(() => {
      count += 1;
    });
    unsubscribe();

    bus.publish('0xABC', { type: 'logout', at: Date.now() });
    await new Promise((r) => setTimeout(r, 50));
    expect(count).toBe(0);
  });

  it('a malformed message on the channel does not crash the listener', async () => {
    const redis = freshRedis();
    const bus = new RedisSessionBus(redis);
    buses.push(bus);
    await bus.start();

    let delivered = 0;
    bus.subscribe(() => {
      delivered += 1;
    });

    // Inject a non-JSON message straight onto the channel.
    await redis.publish('citrate:session', 'not-json{');
    await new Promise((r) => setTimeout(r, 50));
    // No handler fired, and a subsequent VALID publish still works.
    expect(delivered).toBe(0);

    const ok = new Promise<void>((resolve) => {
      const un = bus.subscribe(() => {
        un();
        resolve();
      });
    });
    bus.publish('0xDEF', { type: 'logout', at: Date.now() });
    await ok;
  });
});
