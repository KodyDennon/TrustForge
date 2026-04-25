<?php
declare(strict_types=1);

namespace TrustForge\Laravel\Tests;

use PHPUnit\Framework\TestCase;
use TrustForge\Laravel\TrustForgeClient;
use TrustForge\Laravel\TrustForgeMiddleware;
use TrustForge\Laravel\JsonResponseStub;

final class FakeRequest
{
    public function __construct(private string $method, private string $path) {}
    public function method(): string { return $this->method; }
    public function path(): string { return $this->path; }
    public function header(string $k): ?string { return null; }
}

final class MiddlewareTest extends TestCase
{
    private function clientReturning(array $resp): TrustForgeClient
    {
        return new TrustForgeClient(
            'http://daemon.invalid',
            null,
            5.0,
            function ($url, $body, $headers) use ($resp) {
                $this->assertStringEndsWith('/v1/decide', $url);
                $this->assertNotEmpty($body);
                return [200, json_encode($resp)];
            }
        );
    }

    public function test_allow_passes_through(): void
    {
        $client = $this->clientReturning(['decision' => 'allow', 'proof_id' => 'p1']);
        $mw = new TrustForgeMiddleware($client);
        $next = fn($req) => 'OK';
        $result = $mw->handle(new FakeRequest('GET', 'widgets'), $next);
        $this->assertSame('OK', $result);
    }

    public function test_deny_blocks_with_403(): void
    {
        $client = $this->clientReturning(['decision' => 'deny', 'reason' => 'policy']);
        $mw = new TrustForgeMiddleware($client);
        $next = fn($req) => 'OK';
        $result = $mw->handle(new FakeRequest('POST', 'admin'), $next);
        $this->assertInstanceOf(JsonResponseStub::class, $result);
        $this->assertSame(403, $result->getStatusCode());
        $this->assertStringContainsString('"decision":"deny"', $result->getContent());
    }

    public function test_observe_only_does_not_block(): void
    {
        $client = $this->clientReturning(['decision' => 'deny']);
        $mw = new TrustForgeMiddleware($client, 'observe-only');
        $next = fn($req) => 'OK';
        $result = $mw->handle(new FakeRequest('GET', '/'), $next);
        $this->assertSame('OK', $result);
    }
}
