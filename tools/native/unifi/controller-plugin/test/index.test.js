// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Unit tests for the pure event-translation function. We avoid
// network here; postJson is integration-tested separately.

const test = require('node:test');
const assert = require('node:assert/strict');

const { eventToDecideRequest, DEFAULT_CONFIG } = require('../src/index.js');

test('client.connected → host actor + named action + network target', () => {
  const r = eventToDecideRequest(
    {
      kind: 'client.connected',
      client: { mac: 'aa:bb:cc:dd:ee:ff' },
      network: { name: 'guest' },
    },
    DEFAULT_CONFIG,
  );
  assert.deepEqual(r, {
    actor: 'tf:actor:host:unifi/aa:bb:cc:dd:ee:ff',
    action: 'unifi.client.connected',
    target: 'guest',
  });
});

test('switch.port.blocked → admin actor + sw-mac:port target', () => {
  const r = eventToDecideRequest(
    {
      kind: 'switch.port.blocked',
      admin: { actor: 'tf:actor:user:alice' },
      switch: { mac: '00:11:22:33:44:55' },
      port: { idx: 7 },
    },
    DEFAULT_CONFIG,
  );
  assert.equal(r.actor, 'tf:actor:user:alice');
  assert.equal(r.action, 'unifi.switch.port.blocked');
  assert.equal(r.target, '00:11:22:33:44:55:7');
});

test('guest.voucher.requested → host actor + portal target', () => {
  const r = eventToDecideRequest(
    {
      kind: 'guest.voucher.requested',
      client: { mac: 'de:ad:be:ef:00:00' },
      portal: { site: 'tf:actor:device:unifi/site-cafe' },
    },
    DEFAULT_CONFIG,
  );
  assert.equal(r.action, 'unifi.guest.voucher.requested');
  assert.equal(r.target, 'tf:actor:device:unifi/site-cafe');
});

test('unknown kind → null (plugin ignores it)', () => {
  const r = eventToDecideRequest({ kind: 'whatever.else' }, DEFAULT_CONFIG);
  assert.equal(r, null);
});

test('missing fields fall back to defaults without throwing', () => {
  const r = eventToDecideRequest({ kind: 'client.connected' }, DEFAULT_CONFIG);
  assert.equal(r.actor, 'tf:actor:host:unifi/unknown');
  assert.equal(r.target, DEFAULT_CONFIG.site_actor);
});
