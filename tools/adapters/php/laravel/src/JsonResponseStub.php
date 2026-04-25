<?php
declare(strict_types=1);

namespace TrustForge\Laravel;

/**
 * Tiny JSON response shim used in tests and as a fallback when
 * Illuminate\Http\JsonResponse isn't available (e.g. unit tests without
 * a full Laravel runtime). When running under Laravel proper, the host
 * application's JsonResponse will be used instead via the service
 * provider; this class exists for adapter-level testability.
 */
class JsonResponseStub
{
    public int $status;
    /** @var array<string,mixed> */
    public array $body;

    /**
     * @param array<string,mixed> $body
     */
    public function __construct(int $status, array $body)
    {
        $this->status = $status;
        $this->body = $body;
    }

    public function getStatusCode(): int
    {
        return $this->status;
    }

    public function getContent(): string
    {
        return (string)json_encode($this->body);
    }
}
