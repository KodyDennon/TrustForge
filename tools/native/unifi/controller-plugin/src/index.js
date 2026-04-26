// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// trustforge-unifi-plugin — UniFi Network Controller plugin that
// brokers controller events through the local TrustForge daemon.
//
// Each subscribed event is translated into a /v1/decide call shaped:
//
//   POST <daemon_url>/v1/decide
//   { "actor": "<unifi-actor-uri>", "action": "<unifi.kind>", "target": "<unifi-target>" }
//
// The plugin honours the verdict by calling back into the controller's
// REST API: e.g. on `client.connected` + `decision: deny` it issues a
// `cmd: block-sta` to the controller. On daemon error it fails closed
// (or open, if `fail_closed: false` is set in plugin config).
//
// Status: Draft (Phase 0). Reference target is the UniFi Network
// Application 8.x event-bus shape; older controllers expose a slightly
// different shape (see README "Compatibility").

'use strict';

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

const DEFAULT_CONFIG = {
  daemon_url: 'http://127.0.0.1:8787',
  fail_closed: true,
  site_actor: 'tf:actor:device:unifi/site-default',
  decide_timeout_ms: 2000,
};

/**
 * Minimal HTTP POST that doesn't depend on `fetch` (UniFi controllers
 * still ship Node 18 LTS which has fetch, but several deployments are
 * pinned to Node 16 by the closed-source Java sidecar; the raw http
 * module always works).
 */
function postJson(urlString, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const lib = url.protocol === 'https:' ? https : http;
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const req = lib.request(
      {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + (url.search || ''),
        headers: {
          'content-type': 'application/json',
          'content-length': body.length,
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`daemon ${res.statusCode}: ${raw}`));
          }
          try {
            resolve(JSON.parse(raw));
          } catch (e) {
            reject(new Error(`decode: ${e.message}: ${raw}`));
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Translate a controller event into (actor, action, target).
 * Exported for unit tests; pure function.
 */
function eventToDecideRequest(event, config) {
  switch (event.kind) {
    case 'client.connected':
    case 'client.authorized':
      return {
        actor: `tf:actor:host:unifi/${event.client?.mac ?? 'unknown'}`,
        action: `unifi.${event.kind}`,
        target: event.network?.name ?? config.site_actor,
      };
    case 'firewall.rule.added':
    case 'firewall.rule.removed':
      return {
        actor: event.admin?.actor ?? config.site_actor,
        action: `unifi.${event.kind}`,
        target: event.rule?.id ?? 'unknown',
      };
    case 'switch.port.blocked':
    case 'switch.port.unblocked':
      return {
        actor: event.admin?.actor ?? config.site_actor,
        action: `unifi.${event.kind}`,
        target: `${event.switch?.mac ?? 'unknown'}:${event.port?.idx ?? 0}`,
      };
    case 'guest.voucher.requested':
      return {
        actor: `tf:actor:host:unifi/${event.client?.mac ?? 'unknown'}`,
        action: 'unifi.guest.voucher.requested',
        target: event.portal?.site ?? config.site_actor,
      };
    default:
      return null;
  }
}

/**
 * Apply the daemon's verdict by calling back into the controller's
 * REST API. The `controller` argument is the controller-supplied
 * client object; the plugin SDK injects this at activate() time.
 */
async function applyDecision(controller, event, decision, log) {
  if (decision === 'allow') return; // no-op; default action is allow
  if (decision === 'deny') {
    switch (event.kind) {
      case 'client.connected':
      case 'client.authorized':
        await controller.api.cmd('stamgr', {
          cmd: 'block-sta',
          mac: event.client?.mac,
        });
        log.warn(`blocked client ${event.client?.mac} per TrustForge deny`);
        return;
      case 'switch.port.unblocked':
        await controller.api.cmd('devmgr', {
          cmd: 'set-port-overrides',
          mac: event.switch?.mac,
          port_idx: event.port?.idx,
          port_override: { poe_mode: 'off', portconf_id: 'blocked' },
        });
        log.warn(`re-blocked port ${event.switch?.mac}:${event.port?.idx} per TrustForge deny`);
        return;
      case 'guest.voucher.requested':
        await controller.api.cmd('hotspot', {
          cmd: 'reject-voucher',
          mac: event.client?.mac,
        });
        log.warn(`rejected voucher for ${event.client?.mac} per TrustForge deny`);
        return;
      case 'firewall.rule.added':
        await controller.api.firewall.rules.delete(event.rule?.id);
        log.warn(`reverted firewall.rule.added ${event.rule?.id} per TrustForge deny`);
        return;
      default:
        log.warn(`no remediator for kind=${event.kind}; deny verdict ignored`);
    }
  }
  if (decision === 'ask') {
    log.info(`TrustForge asked operator confirmation for ${event.kind}; controller default=allow`);
  }
}

class TrustForgePlugin {
  constructor(controller, userConfig = {}) {
    this.controller = controller;
    this.config = { ...DEFAULT_CONFIG, ...userConfig };
    this.log = controller?.log ?? console;
  }

  async activate() {
    const events = [
      'client.connected',
      'client.authorized',
      'firewall.rule.added',
      'firewall.rule.removed',
      'switch.port.blocked',
      'switch.port.unblocked',
      'guest.voucher.requested',
    ];
    for (const kind of events) {
      this.controller.events.on(kind, (ev) => {
        // Inject the kind so the translator gets a single shape.
        this.handle({ ...ev, kind }).catch((e) => this.log.error(`handle ${kind}: ${e.message}`));
      });
    }
    this.log.info(`trustforge-unifi-plugin activated; daemon=${this.config.daemon_url}`);
  }

  async handle(event) {
    const req = eventToDecideRequest(event, this.config);
    if (!req) {
      this.log.debug(`ignoring unknown event kind=${event.kind}`);
      return;
    }
    let decision = 'deny';
    try {
      const resp = await postJson(
        `${this.config.daemon_url}/v1/decide`,
        req,
        this.config.decide_timeout_ms,
      );
      decision = resp.decision || (this.config.fail_closed ? 'deny' : 'allow');
      this.log.debug(
        `decide actor=${req.actor} action=${req.action} target=${req.target} -> ${decision}`,
      );
    } catch (e) {
      this.log.warn(`decide failed: ${e.message}; fail_closed=${this.config.fail_closed}`);
      decision = this.config.fail_closed ? 'deny' : 'allow';
    }
    await applyDecision(this.controller, event, decision, this.log);
  }
}

module.exports = {
  TrustForgePlugin,
  // Exported for unit tests.
  eventToDecideRequest,
  postJson,
  DEFAULT_CONFIG,
};

// When loaded directly by the controller, register a default instance.
// The controller plugin loader passes `controller` and the user-config
// blob from the controller UI's plugin pane.
if (require.main === module) {
  // Stand-alone smoke test: target a mock controller logger and a
  // local daemon, log decisions, exit.
  const mock = {
    events: { on: (_, __) => {} },
    api: {
      cmd: async () => ({}),
      firewall: { rules: { delete: async () => ({}) } },
    },
    log: console,
  };
  const p = new TrustForgePlugin(mock, {
    daemon_url: process.env.TF_DAEMON_URL || DEFAULT_CONFIG.daemon_url,
  });
  p.activate().then(() =>
    console.log('plugin activated against mock controller; exiting smoke test'),
  );
}
