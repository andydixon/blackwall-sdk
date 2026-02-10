# Migration Guide

## Moving from `BlackWallSDK\BlackWallAuth` to `BlackWall\Auth\AuthClient`

### Before

```php
$auth = new BlackWallSDK\BlackWallAuth($config);
$authData = $auth->getAuthorizationUrl();
$tokens = $auth->exchangeCodeForTokens($code);
$user = $auth->getUserInfo($tokens['access_token']);
```

### After

```php
use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$client = new AuthClient(Config::fromArray($config));
$authData = $client->buildAuthorisationUrl();
$tokens = $client->exchangeCodeForTokens($code);
$user = $client->getUserInfo($tokens->accessToken);
```

## Key differences

- Method spelling uses British English in the new API: `buildAuthorisationUrl()`.
- Token responses are strongly typed via `TokenSet`.
- Errors are represented by specific exception classes.
- HTTP transport is swappable via `HttpClientInterface`.

## Compatibility status

`BlackWallSDK\BlackWallAuth` remains available and delegates to the new client. Existing applications can upgrade gradually.
