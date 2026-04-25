<?php
declare(strict_types=1);

namespace TrustForge\Laravel;

/**
 * Laravel Service Provider. Registers a singleton TrustForgeClient and
 * the TrustForgeMiddleware in the container.
 *
 * We extend the framework's ServiceProvider only when it's available; the
 * fallback class lets unit tests load this file outside Laravel.
 */
if (class_exists(\Illuminate\Support\ServiceProvider::class)) {
    abstract class _BaseProvider extends \Illuminate\Support\ServiceProvider {}
} else {
    abstract class _BaseProvider
    {
        protected $app;
        public function __construct($app = null) { $this->app = $app; }
    }
}

class TrustForgeServiceProvider extends _BaseProvider
{
    public function register(): void
    {
        $bind = function ($key, $factory) {
            if ($this->app !== null && method_exists($this->app, 'singleton')) {
                $this->app->singleton($key, $factory);
            }
        };
        $bind(TrustForgeClient::class, function () {
            $url = getenv('TF_DAEMON_URL') ?: 'http://127.0.0.1:8731';
            $tok = getenv('TF_ADMIN_TOKEN') ?: null;
            return new TrustForgeClient($url, $tok);
        });
    }

    public function boot(): void
    {
        // No-op; the consumer wires the middleware into their HTTP kernel.
    }
}
