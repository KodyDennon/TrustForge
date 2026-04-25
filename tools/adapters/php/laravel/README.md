# trustforge/laravel

Laravel Service Provider + Middleware. Calls `tf-daemon`'s `/v1/decide` for
every HTTP request and either passes the request through, blocks it with a
403, or fails open in `observe-only` mode.

## Install

```sh
composer require trustforge/laravel
```

Then add the middleware to `app/Http/Kernel.php`:

```php
protected $middleware = [
  \TrustForge\Laravel\TrustForgeMiddleware::class,
];
```

## Test

```sh
composer install
vendor/bin/phpunit
```

Requires `php >= 8.1` with `ext-curl` and `ext-json`. If `composer` /
`phpunit` are not installed, install via Homebrew (`brew install
composer php`) or your distro's PHP package.
