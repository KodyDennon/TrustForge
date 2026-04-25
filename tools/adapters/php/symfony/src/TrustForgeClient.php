<?php
declare(strict_types=1);

namespace TrustForge\Symfony;

class TrustForgeClient
{
    private string $daemonUrl;
    private ?string $adminToken;
    /** @var callable|null */
    private $transport;

    public function __construct(string $daemonUrl, ?string $adminToken = null, ?callable $transport = null)
    {
        if ($daemonUrl === '') {
            throw new \InvalidArgumentException('daemonUrl is required');
        }
        $this->daemonUrl = rtrim($daemonUrl, '/');
        $this->adminToken = $adminToken;
        $this->transport = $transport;
    }

    /**
     * @param array<string,mixed> $req
     * @return array<string,mixed>
     */
    public function decide(array $req): array
    {
        $payload = array_filter($req, fn($v) => $v !== null);
        if (!isset($payload['context'])) {
            $payload['context'] = new \stdClass();
        }
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $url = $this->daemonUrl . '/v1/decide';
        $headers = ['content-type: application/json', 'accept: application/json'];
        if ($this->adminToken !== null) {
            $headers[] = 'authorization: Bearer ' . $this->adminToken;
        }
        if ($this->transport !== null) {
            [$status, $raw] = ($this->transport)($url, $body, $headers);
        } else {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            $resp = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_error($ch);
            curl_close($ch);
            if ($resp === false) {
                throw new \RuntimeException('tf-daemon /v1/decide network error: ' . $err);
            }
            $raw = $resp;
        }
        $parsed = json_decode((string)$raw, true);
        if ($status >= 400 || !is_array($parsed)) {
            throw new \RuntimeException("tf-daemon /v1/decide returned $status");
        }
        return $parsed;
    }
}
