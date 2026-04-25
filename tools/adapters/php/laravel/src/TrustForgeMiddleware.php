<?php
declare(strict_types=1);

namespace TrustForge\Laravel;

/**
 * Laravel HTTP middleware. Framework-agnostic in shape — we only require
 * `$request->method()`, `$request->path()`, and an `$next($request)` closure,
 * which matches Laravel's middleware contract.
 */
class TrustForgeMiddleware
{
    private TrustForgeClient $client;
    private string $mode;
    private ?string $actor;

    public function __construct(TrustForgeClient $client, string $mode = 'enforce', ?string $actor = null)
    {
        if (!in_array($mode, ['enforce', 'observe-only'], true)) {
            throw new \InvalidArgumentException('mode must be enforce or observe-only');
        }
        $this->client = $client;
        $this->mode = $mode;
        $this->actor = $actor;
    }

    public function handle($request, \Closure $next)
    {
        $method = strtolower((string)$request->method());
        $path = (string)$request->path();
        $traceId = (string)($request->header('x-trace-id') ?? bin2hex(random_bytes(8)));

        $req = [
            'action' => 'http.' . $method,
            'target' => '/' . ltrim($path, '/'),
            'context' => ['method' => strtoupper($method), 'path' => $path],
            'trace_id' => $traceId,
        ];
        if ($this->actor !== null) {
            $req['actor'] = $this->actor;
        }

        try {
            $resp = $this->client->decide($req);
        } catch (TrustForgeException $e) {
            if ($this->mode === 'enforce') {
                return new JsonResponseStub(503, ['error' => 'trustforge_unavailable']);
            }
            return $next($request);
        }

        $decision = $resp['decision'] ?? 'deny';
        if ($this->mode === 'enforce' && $decision !== 'allow') {
            return new JsonResponseStub(403, [
                'decision' => $decision,
                'reason' => $resp['reason'] ?? '',
                'proof_id' => $resp['proof_id'] ?? '',
            ]);
        }
        return $next($request);
    }
}
