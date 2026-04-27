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
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]));

if (!isset($_SESSION['user'])) {
    $auth = $client->buildAuthorisationUrl();
    // Prevent stale redirects from being reused from cache.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: ' . $auth['url']);
    exit;
}

echo 'Already signed in.';
```

When the requested scope contains `openid`, the SDK generates a secure nonce, persists it in `$_SESSION['blackwall_oidc_nonce']`, and includes `nonce=...` in the provider authorisation URL together with `state`, `code_challenge`, and the rest of the OAuth/OIDC query parameters.

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
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
]));

if (isset($_GET['error'])) {
    $error = (string) $_GET['error'];
    $description = isset($_GET['error_description']) ? (string) $_GET['error_description'] : 'Unknown provider error';
    // access_denied is a normal authorisation outcome (for example, membership
    // revoked, privilege changed, or user denied consent between request and submit).
    // invalid_scope usually means the app requested scopes not enabled on the provider client.
    http_response_code(in_array($error, ['access_denied', 'invalid_scope'], true) ? 403 : 400);
    exit('Authorisation failed: ' . $description);
}

$result = $client->handleCallback($_GET, true, [
    'expected_nonce' => $_SESSION[\BlackWall\Auth\AuthClient::NONCE_SESSION_KEY] ?? null,
]);

$_SESSION['user'] = [
    'email' => $result->user->email,
    'privilege_level' => $result->user->privilegeLevel,
    'role' => $result->user->role,
];
$_SESSION['access_token'] = $result->tokens->accessToken;
$_SESSION['refresh_token'] = $result->tokens->refreshToken;

header('Location: /');
exit;
```

If the provider returns an `id_token`, `handleCallback()` decodes the payload claims and checks the `nonce` claim against the expected value. If no `id_token` is returned, the callback continues normally. If the `nonce` claim is missing or mismatched, the SDK throws `BlackWall\Auth\Exception\NonceMismatchException`.

## OIDC nonce handling

Use `state` and `nonce` for different jobs:

- `state` protects the front-channel redirect and callback correlation.
- `nonce` protects the OpenID Connect authentication result carried by `id_token`.

The SDK stores the following session keys when persistence is enabled:

- `blackwall_oauth_state`
- `blackwall_oauth_code_verifier`
- `blackwall_oidc_nonce`

If you need to supply your own nonce, pass it directly:

```php
$auth = $client->buildAuthorisationUrl([
    'nonce' => 'your-application-generated-nonce',
]);
```

You can validate an `id_token` nonce directly:

```php
$claims = $client->assertIdTokenNonceMatches(
    $result->tokens->idToken,
    $_SESSION[\BlackWall\Auth\AuthClient::NONCE_SESSION_KEY] ?? null
);
```

You can also inspect JWT payload claims when debugging or doing application-level checks:

```php
$claims = $client->decodeJwtPayloadClaims($result->tokens->idToken);
```

This helper only decodes the JWT payload. It does not verify signature, issuer, audience, expiry, or token use. Full ID token verification may require JWK retrieval and additional OpenID Connect checks outside the current SDK scope.

If a deployment cannot yet enforce nonce validation strictly, a temporary compatibility mode is available:

```php
$result = $client->handleCallback($_GET, true, [
    'validate_nonce' => false,
]);
```

Use this only as a short-term bridge while the application is updated to persist and enforce nonce consistently.

If your provider returns an `id_token` without the `nonce` claim, the SDK will allow missing nonce values by default while still enforcing a match when one is present. You can also set it explicitly:

```php
$result = $client->handleCallback($_GET, true, [
    'allow_missing_nonce' => true,
]);
```

Use this only after confirming the provider cannot include `nonce`, because it weakens replay protection for those tokens.

## 3. Single callback for multiple app roles

Using one OAuth client and one callback URL is recommended.

Map users in your application by:

1. `email` claim to local account record
2. `privilege_level` (or `role`) to application role

Typical mapping example:

- `privilege_level = 1` => admin/superadmin
- `privilege_level = 2` => user/tutor

If `privilege_level` is absent, the SDK also resolves common role strings (`admin`, `superadmin`, `user`, `tutor`).

## 4. Refresh token (optional)

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
- `BlackWall\Auth\Exception\NonceMismatchException`
- `BlackWall\Auth\Exception\TokenExchangeException`
- `BlackWall\Auth\Exception\UserInfoException`
- `BlackWall\Auth\Exception\TransportException`

Example:

```php
try {
    $tokens = $client->exchangeCodeForTokens($code);
} catch (\BlackWall\Auth\Exception\TokenExchangeException $e) {
    error_log('Token exchange failed: ' . $e->getMessage());
    error_log('Auth code: ' . ($e->authCode() ?? 'none'));
    http_response_code(502);
}
```

`UserInfoException` with `invalid_token` can occur when provider-side subject scope is no longer active (for example user/project disabled) between token issuance and userinfo retrieval.
`TokenExchangeException` with `invalid_grant` can also occur when provider-side client/user/project state is inactive at exchange time.
Token introspection can return `active=false` when the token subject (user/project) or client has since been disabled.
Provider JWT access tokens are now revocation-aware at `userinfo`; revoked JWTs can fail before natural expiry.
Refresh-token exchange can return `invalid_grant` when provider client scope policy has been tightened and stored refresh scopes are no longer allowed.
Provider login/authorisation steps can also fail with `access_denied` when account status is disabled before completion.
WebAuthn-based login verification can return credential-style failures for disabled accounts even when authenticator assertions are otherwise valid.
Existing authenticated sessions may also be invalidated when account status changes to disabled.
OAuth authorisation consent submission can return `access_denied` if the account becomes inactive between session establishment and consent completion.
OAuth authorisation can also return `invalid_scope` if requested scopes are not explicitly allowed on the provider client configuration.
Provider user/project assignment views may exclude disabled projects even if historical assignments exist.

## Operational guidance

- Keep provider URLs in environment variables, not hard-coded.
- Avoid printing tokens in production pages.
- Expect `429 Too Many Requests` from provider control endpoints under abuse protection; implement backoff/retry instead of tight loops.
- Apply the same backoff strategy for provider `userinfo` calls that return `429 Too Many Requests`.
- For token exchange and refresh, apply bounded retry/backoff on transient provider failures instead of immediate repeated retries.
- Use exactly one client authentication method per token/control request (do not send both HTTP Basic and `client_secret` form fields together).
- If you call provider WebAuthn login challenge/verify endpoints directly, use `POST` only.
- Treat admin enrolment URL export as a state-changing operation: call it with `POST` and include a valid CSRF token.
- Treat provider CSV exports as untrusted input in spreadsheet tools; prefer importing into systems that neutralise formula cells.
- Treat enrolment URLs as sensitive bearer material: do not place them in redirect query parameters, logs, or analytics tags; keep them in one-time server-side flash/session state.
- If your deployment runs behind reverse proxies, ensure trusted-proxy configuration is strict so spoofed forwarding headers cannot bypass IP-based abuse controls.
- Trusted proxy allowlists may be expressed as explicit IPs or CIDR ranges; avoid broad ranges and keep proxy chains minimal.
- For approval-driven admin mutations, assume provider-side execution is serialised per approval item; client retries should still be idempotent and bounded.
- This serialisation applies across approval actions (approve/reject/cancel), so clients should avoid parallel decision submissions for the same request ID.
- For provider CSV-based user import operations, enforce strict file-size and row-count limits in automation tooling and surface clear operator errors on limit breaches.
- Configure OAuth client redirect URIs as HTTPS in production; reserve HTTP for localhost loopback testing only.
- Assume provider rate limits are enforced per source identity (for example IP) and shared across related auth endpoints.
- Treat report/export-style provider endpoints as high-cost and expect stricter rate limits.
- Rotate client secrets for confidential clients.
- Do not transport secrets or tokens in URL query parameters; keep them in server-side session or secure storage only.
- Add a unique `nonce` to each OIDC authorisation request and validate it against the `id_token` when one is returned.
- Keep `state`, `nonce`, and PKCE values within standard URL-safe formats/lengths; malformed values can be rejected by provider validation.
- Validate `state` on every callback request.
- Use secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax` or stricter).
- HTTPS URLs are enforced by default in `Config::fromArray()`.
- For localhost-only HTTP testing, explicitly set `allowInsecureHttp => true`.
- If you call Cryptbin unwrap APIs directly, include the original share key as `key_b64url`; unwrap now returns `403 Forbidden` when key proof does not match metadata verifier.
- New Cryptbin items may also bind unwrap/update/delete operations to the creating WebAuthn credential; use the same authenticator for follow-up operations.
