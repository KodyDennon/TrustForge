<?php
declare(strict_types=1);

namespace TrustForge\Laravel;

class TrustForgeException extends \RuntimeException
{
    public int $status;
    /** @var array<string,mixed>|null */
    public ?array $body;

    /**
     * @param array<string,mixed>|null $body
     */
    public function __construct(string $message, int $status = 0, ?array $body = null)
    {
        parent::__construct($message);
        $this->status = $status;
        $this->body = $body;
    }
}
