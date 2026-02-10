# Integration Guide (British English)

This guide shows a complete OAuth/OIDC login flow using `BlackWall\Auth\AuthClient`.

## 1. Start login

```php
<?php

declare(strict_types=1);

session_start();
require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$client = new AuthClient(Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]));

if (!isset($_SESSION['user'])) {
    $auth = $client->buildAuthorisationUrl();
    header('Location: ' . $auth['url']);
    exit;
}

echo 'Already signed in.';
```

## 2. Handle callback

```php
<?php

declare(strict_types=1);

session_start();
require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$client = new AuthClient(Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
]));

if (!isset($_GET['code'], $_GET['state'])) {
    http_response_code(400);
    echo 'Missing code/state';
    exit;
}

$client->assertStateMatches((string) $_GET['state']);
$tokens = $client->exchangeCodeForTokens((string) $_GET['code']);
$user = $client->getUserInfo($tokens->accessToken);

$_SESSION['user'] = $user;
$_SESSION['access_token'] = $tokens->accessToken;
$_SESSION['refresh_token'] = $tokens->refreshToken;

$client->clearPkceSessionState();

header('Location: /');
exit;
```

## 3. Refresh token (optional)

```php
<?php

$tokens = $client->refreshAccessToken($_SESSION['refresh_token']);
$_SESSION['access_token'] = $tokens->accessToken;
if ($tokens->refreshToken !== null) {
    $_SESSION['refresh_token'] = $tokens->refreshToken;
}
```

## Exceptions

Catch specific exceptions for clearer handling:

- `BlackWall\Auth\Exception\StateMismatchException`
- `BlackWall\Auth\Exception\TokenExchangeException`
- `BlackWall\Auth\Exception\UserInfoException`
- `BlackWall\Auth\Exception\TransportException`

Example:

```php
try {
    $tokens = $client->exchangeCodeForTokens($code);
} catch (\BlackWall\Auth\Exception\TokenExchangeException $e) {
    error_log('Token exchange failed: ' . $e->getMessage());
    http_response_code(502);
}
```

## Operational guidance

- Keep provider URLs in environment variables, not hard-coded.
- Avoid printing tokens in production pages.
- Rotate client secrets for confidential clients.
- Validate `state` on every callback request.
- Use secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax` or stricter).
