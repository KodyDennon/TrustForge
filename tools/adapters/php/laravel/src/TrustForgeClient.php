<?php
declare(strict_types=1);

namespace TrustForge\Laravel;

/**
 * Minimum-viable HTTP client for tf-daemon's POST /v1/decide.
 *
 * Wire contract: identical to the conformance vectors in
 * conformance/decide-protocol-vectors.yaml and the TS/Python SDKs.
 */
class TrustForgeClient
{
    private string $daemonUrl;
    private ?string $adminToken;
    private float $timeout;
    /** @var callable|null */
    private $transport;

    public function __construct(
        string $daemonUrl,
        ?string $adminToken = null,
        float $timeout = 5.0,
        ?callable $transport = null
    ) {
        if ($daemonUrl === '') {
            throw new \InvalidArgumentException('daemonUrl is required');
        }
        $this->daemonUrl = rtrim($daemonUrl, '/');
        $this->adminToken = $adminToken;
        $this->timeout = $timeout;
        $this->transport = $transport;
    }

    /**
     * @param array<string,mixed> $req DecideRequest fields.
     * @return array<string,mixed> DecideResponse fields.
     * @throws TrustForgeException
     */
    public function decide(array $req): array
    {
        if (empty($req['action'])) {
            throw new \InvalidArgumentException('action is required');
        }
        if (empty($req['trace_id'])) {
            throw new \InvalidArgumentException('trace_id is required');
        }
        $payload = array_filter($req, fn($v) => $v !== null);
        if (!isset($payload['context'])) {
            $payload['context'] = new \stdClass();
        }
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $url = $this->daemonUrl . '/v1/decide';
        $headers = [
            'content-type: application/json',
            'accept: application/json',
        ];
        if ($this->adminToken !== null) {
            $headers[] = 'authorization: Bearer ' . $this->adminToken;
        }

        if ($this->transport !== null) {
            [$status, $raw] = ($this->transport)($url, $body, $headers);
        } else {
            [$status, $raw] = $this->httpPost($url, $body, $headers);
        }

        $parsed = json_decode((string)$raw, true);
        if ($status >= 400) {
            throw new TrustForgeException(
                "tf-daemon /v1/decide returned $status",
                $status,
                is_array($parsed) ? $parsed : null
            );
        }
        if (!is_array($parsed)) {
            throw new TrustForgeException(
                'tf-daemon /v1/decide returned non-object body',
                $status,
                null
            );
        }
        return $parsed;
    }

    /**
     * @return array{0:int,1:string}
     */
    private function httpPost(string $url, string $body, array $headers): array
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, (int)$this->timeout);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($resp === false) {
            throw new TrustForgeException('tf-daemon /v1/decide network error: ' . $err);
        }
        return [$status, (string)$resp];
    }
}
