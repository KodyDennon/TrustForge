import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http_testing;
import 'package:shelf/shelf.dart' as shelf;
import 'package:test/test.dart';

import 'package:trustforge/trustforge.dart';
import 'package:trustforge/trustforge_aqueduct.dart';
import 'package:trustforge/trustforge_shelf.dart';

http.Client mockClient(Future<http.Response> Function(http.Request) handler) {
  return http_testing.MockClient(handler);
}

TrustforgeClient mockTfClient(
  Future<http.Response> Function(http.Request) handler, {
  Mode mode = Mode.enforce,
}) {
  final cfg = TrustforgeConfig(mode: mode, timeout: const Duration(seconds: 1));
  return TrustforgeClient(cfg, httpClient: mockClient(handler));
}

void main() {
  group('Decision', () {
    test('parses known values', () {
      expect(Decision.parse('allow'), Decision.allow);
      expect(Decision.parse('deny'), Decision.deny);
      expect(Decision.parse('approval-required'), Decision.approvalRequired);
      expect(Decision.parse('escalate'), Decision.escalate);
      expect(Decision.parse('log-only'), Decision.logOnly);
      expect(Decision.parse('weird'), Decision.unknown);
    });
    test('round-trips wireValue', () {
      for (final d in [
        Decision.allow,
        Decision.deny,
        Decision.approvalRequired,
        Decision.escalate,
        Decision.logOnly,
      ]) {
        expect(Decision.parse(d.wireValue), d);
      }
    });
  });

  group('encodeRequestBody', () {
    test('omits unset fields', () {
      final body = encodeRequestBody(const DecideRequest(action: 'fs.read'));
      expect(body, contains('fs.read'));
      expect(body, isNot(contains('host_token')));
      expect(body, isNot(contains('target')));
    });
    test('includes provided fields', () {
      final body = encodeRequestBody(const DecideRequest(
        action: 'net.connect',
        hostToken: 'abc',
        hostTokenKind: 'session',
        target: '/x',
        traceId: 'tf-1',
      ));
      expect(body, contains('"host_token":"abc"'));
      expect(body, contains('"host_token_kind":"session"'));
      expect(body, contains('"target":"/x"'));
      expect(body, contains('"trace_id":"tf-1"'));
    });
  });

  group('parseResponseBody', () {
    test('decodes allow', () {
      final r = parseResponseBody(
          '{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":["fs.read"]}');
      expect(r.decision, Decision.allow);
      expect(r.proofId, 'p1');
      expect(r.dangerTags, ['fs.read']);
    });
    test('decodes approval-required', () {
      final r = parseResponseBody(
          '{"decision":"approval-required","reason":"need","proof_id":"p2","approval_id":"a-9","danger_tags":[]}');
      expect(r.decision, Decision.approvalRequired);
      expect(r.approvalId, 'a-9');
    });
    test('throws on invalid JSON', () {
      expect(() => parseResponseBody('not json'),
          throwsA(isA<TrustforgeException>()));
    });
  });

  group('extractBearer', () {
    test('matches case-insensitively', () {
      expect(extractBearer('Bearer abc'), 'abc');
      expect(extractBearer('bearer xyz'), 'xyz');
    });
    test('trims and rejects empty', () {
      expect(extractBearer('Bearer  tok  '), 'tok');
      expect(extractBearer('Bearer '), null);
      expect(extractBearer('Basic abc'), null);
      expect(extractBearer(null), null);
    });
  });

  group('TrustforgeClient.decide', () {
    test('returns parsed allow', () async {
      final client = mockTfClient((req) async {
        expect(req.method, 'POST');
        expect(req.url.path, '/v1/decide');
        return http.Response(
            jsonEncode({
              'decision': 'allow',
              'reason': 'ok',
              'proof_id': 'p1',
              'danger_tags': []
            }),
            200,
            headers: {'content-type': 'application/json'});
      });
      final resp = await client.decide(const DecideRequest(action: 'fs.read'));
      expect(resp.decision, Decision.allow);
    });

    test('throws daemon-unavailable on 503', () async {
      final client = mockTfClient((_) async => http.Response('boom', 503));
      expect(
        () => client.decide(const DecideRequest(action: 'fs.read')),
        throwsA(isA<TrustforgeException>()),
      );
    });
  });

  group('Shelf middleware', () {
    test('lets allow through', () async {
      final tf = mockTfClient((_) async => http.Response(
          '{"decision":"allow","reason":"","proof_id":"p"}', 200));
      final handler = const shelf.Pipeline()
          .addMiddleware(trustforgeMiddleware(tf, 'fs.read'))
          .addHandler((req) => shelf.Response.ok('inner'));
      final resp = await handler(shelf.Request('GET', Uri.parse('http://x/y')));
      expect(resp.statusCode, 200);
      expect(await resp.readAsString(), 'inner');
    });

    test('returns 403 on deny', () async {
      final tf = mockTfClient((_) async => http.Response(
          '{"decision":"deny","reason":"no","proof_id":"p"}', 200));
      final handler = const shelf.Pipeline()
          .addMiddleware(trustforgeMiddleware(tf, 'fs.read'))
          .addHandler((req) => shelf.Response.ok('inner'));
      final resp = await handler(shelf.Request('GET', Uri.parse('http://x/y')));
      expect(resp.statusCode, 403);
    });

    test('returns 202 on approval-required with header', () async {
      final tf = mockTfClient((_) async => http.Response(
          '{"decision":"approval-required","reason":"","proof_id":"p","approval_id":"a-7"}',
          200));
      final handler = const shelf.Pipeline()
          .addMiddleware(trustforgeMiddleware(tf, 'fs.read'))
          .addHandler((req) => shelf.Response.ok('inner'));
      final resp = await handler(shelf.Request('GET', Uri.parse('http://x/y')));
      expect(resp.statusCode, 202);
      expect(resp.headers['x-tf-approval-id'], 'a-7');
    });

    test('observe-only lets through on daemon failure', () async {
      final tf = mockTfClient(
        (_) async => http.Response('boom', 503),
        mode: Mode.observeOnly,
      );
      final handler = const shelf.Pipeline()
          .addMiddleware(trustforgeMiddleware(tf, 'fs.read'))
          .addHandler((req) => shelf.Response.ok('inner'));
      final resp = await handler(shelf.Request('GET', Uri.parse('http://x/y')));
      expect(resp.statusCode, 200);
    });
  });

  group('Aqueduct/Conduit guard', () {
    test('allow', () async {
      final tf = mockTfClient((_) async => http.Response(
          '{"decision":"allow","reason":"","proof_id":"p"}', 200));
      final c = TrustforgeController(client: tf, action: 'fs.read');
      final r = await c.guard('/x', {'authorization': 'Bearer t'});
      expect(r.allow, true);
    });
    test('deny', () async {
      final tf = mockTfClient((_) async => http.Response(
          '{"decision":"deny","reason":"","proof_id":"p"}', 200));
      final c = TrustforgeController(client: tf, action: 'fs.read');
      final r = await c.guard('/x', {});
      expect(r.allow, false);
      expect(r.statusCode, 403);
    });
  });
}
