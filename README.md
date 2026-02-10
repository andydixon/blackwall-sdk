# BlackWall Auth SDK (PHP)

A distributable PHP SDK for integrating applications with BlackWall OAuth 2.1 and OpenID Connect.

This package provides:
- OAuth authorisation URL generation with PKCE (`S256`)
- Code-for-token exchange
- Refresh token exchange
- UserInfo retrieval
- Session helpers for `state` and `code_verifier`
- Typed API (`AuthClient`, `TokenSet`) and specific exception classes

## Requirements

- PHP 8.1+
- cURL extension (`ext-curl`)

## Installation

### 1. Install as a Composer package

If this repository is published and tagged:

```bash
composer require dixon/blackwall-auth-sdk
```

### 2. Install from local path (during development)

In the consuming application's `composer.json`:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../test.dixon.cx"
    }
  ],
  "require": {
    "dixon/blackwall-auth-sdk": "*"
  }
}
```

Then run:

```bash
composer update dixon/blackwall-auth-sdk
```

## Quick start

```php
<?php

declare(strict_types=1);

session_start();

require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$config = Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]);

$client = new AuthClient($config);

// Step 1: redirect user to provider
$auth = $client->buildAuthorisationUrl();
header('Location: ' . $auth['url']);
exit;
```

For callback handling, see `docs/INTEGRATION_GUIDE.md`.

## Backwards compatibility

A wrapper class is retained for older integrations:

```php
use BlackWallSDK\BlackWallAuth;
```

This wrapper now delegates to `BlackWall\Auth\AuthClient`.

## Public API

- `BlackWall\Auth\Config`
- `BlackWall\Auth\AuthClient`
- `BlackWall\Auth\TokenSet`
- `BlackWall\Auth\AuthResult`
- `BlackWall\Auth\Http\HttpClientInterface`
- `BlackWall\Auth\Http\CurlHttpClient`
- `BlackWall\Auth\Exception\*`

## Security notes

- Always validate OAuth `state` in callback handlers.
- Always use HTTPS in production.
- Store refresh tokens securely.
- Keep access tokens out of logs and browser-visible output.
- Use short session lifetimes where possible.

## Repository layout

- `src/Auth/` - main SDK classes
- `src/Auth/Http/` - HTTP transport abstraction
- `src/Auth/Exception/` - typed exceptions
- `src/BlackWallAuth.php` - legacy compatibility wrapper
- `src/legacy_autoload.php` - fallback non-Composer loader
- `public_html/` - demonstration application
- `docs/` - integration documentation

## Licence

Proprietary (internal distribution by default).
