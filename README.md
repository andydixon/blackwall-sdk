# BlackWall Auth SDK (PHP)

A distributable PHP SDK for integrating applications with BlackWall OAuth 2.1 and OpenID Connect.

This package provides:
- OAuth authorisation URL generation with PKCE (`S256`)
- Code-for-token exchange
- Refresh token exchange
- UserInfo retrieval
- UserInfo normalisation (`email`, `privilege_level`, `role`)
- Unified callback handling helper (`handleCallback`)
- First-class OIDC nonce generation, session persistence, and validation helpers
- Session helpers for `state`, `code_verifier`, and `nonce`
- Typed API (`AuthClient`, `TokenSet`) and specific exception classes

## Requirements

- PHP 8.1+
- cURL extension (`ext-curl`)

## Installation

### 1. Install as a Composer package

If this repository is published and tagged:

```bash
composer require andydixon/blackwall-auth-sdk
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
    "andydixon/blackwall-auth-sdk": "*"
  }
}
```

Then run:

```bash
composer update andydixon/blackwall-auth-sdk
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
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]);

$client = new AuthClient($config);

// Step 1: redirect user to provider
$auth = $client->buildAuthorisationUrl();
header('Location: ' . $auth['url']);
exit;
```

When the requested scope includes `openid`, `buildAuthorisationUrl()` generates a URL-safe nonce automatically, stores it in `$_SESSION['blackwall_oidc_nonce']` when session persistence is enabled, and includes it in the authorisation request.

For callback handling, see `docs/INTEGRATION_GUIDE.md`.
For provider-side threat/invariant assumptions, see `docs/SECURITY_MODEL.md`.

Minimal callback example:

```php
$result = $client->handleCallback($_GET, true, [
    'expected_nonce' => $_SESSION[\BlackWall\Auth\AuthClient::NONCE_SESSION_KEY] ?? null,
]);

$_SESSION['user'] = [
    'email' => $result->user->email,
    'privilege_level' => $result->user->privilegeLevel,
    'role' => $result->user->role,
];
$_SESSION['access_token'] = $result->tokens->accessToken;
```

## OIDC nonce handling

Use `nonce` for OpenID Connect authorisation requests. `state` protects the browser redirect flow against CSRF and mix-up issues. `nonce` binds the returned `id_token` to the login request that started in the user's session.

The SDK now treats nonce as a first-class value:

- `buildAuthorisationUrl()` generates a secure nonce automatically when the scope contains `openid`.
- Pass `'nonce' => 'your-value'` if you need to supply your own nonce.
- With default persistence enabled, the SDK stores:
  - `$_SESSION['blackwall_oauth_state']`
  - `$_SESSION['blackwall_oauth_code_verifier']`
  - `$_SESSION['blackwall_oidc_nonce']`
- The returned array from `buildAuthorisationUrl()` now includes `'nonce' => ?string`.
- `assertNonceMatches()` checks a nonce against the stored session value.
- `assertIdTokenNonceMatches()` decodes the JWT payload claims and validates the `nonce` claim against an explicit or session-backed expected nonce.
- `handleCallback()` will validate nonce automatically when both of these are true:
  - the token response contains an `id_token`
  - an expected nonce is available explicitly or in session

If the provider does not return an `id_token`, callback handling remains graceful and does not fail purely because a nonce was stored. If an `id_token` is returned but the `nonce` claim is missing or mismatched, the SDK throws `BlackWall\Auth\Exception\NonceMismatchException`.

Compatibility mode: if you have a temporary deployment constraint and cannot enforce nonce immediately, call `handleCallback($_GET, true, ['validate_nonce' => false])`. Treat this as a short-lived compatibility setting only.

If your provider issues an `id_token` but omits the `nonce` claim, the SDK will accept missing nonce values by default while still enforcing a match when one is present. You can also set it explicitly:

```php
$result = $client->handleCallback($_GET, true, [
  'allow_missing_nonce' => true,
]);
```

Use this only when you have verified the provider cannot include `nonce`. It weakens replay protection for those tokens.

### JWT payload decoding helper

Use `decodeJwtPayloadClaims()` when you need to inspect an `id_token` payload:

```php
$claims = $client->decodeJwtPayloadClaims($result->tokens->idToken);
```

This helper only decodes the JWT payload. It does not verify the token signature, issuer, audience, expiry, or authorised token use. Nonce matching is still important, and complete ID token verification may require provider JWK handling and additional OIDC checks outside the current SDK scope.

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
- `BlackWall\Auth\CallbackResult`
- `BlackWall\Auth\UserInfo`
- `BlackWall\Auth\UserInfoNormalizer`
- `BlackWall\Auth\Http\HttpClientInterface`
- `BlackWall\Auth\Http\CurlHttpClient`
- `BlackWall\Auth\Exception\*`

## Security notes

- Always validate OAuth `state` in callback handlers.
- Handle provider callback errors (`error`, `error_description`) explicitly; treat `access_denied` as an expected user/authorisation outcome rather than a transport failure.
- Treat `invalid_scope` as a client-configuration mismatch: requested scopes must be a subset of scopes allowed on the provider client.
- Expect `access_denied` even after the consent page is displayed if provider-side project membership or tenant scope changes before consent submission.
- Expect provider token introspection to return `active=false` when user/project/client state is no longer active.
- Expect revoked JWT access tokens to be rejected by provider `userinfo` even before token expiry.
- Register only HTTPS redirect URIs in provider client settings (HTTP should be used only for localhost loopback during development).
- Use OAuth/portal authentication endpoints for end users; provider admin login endpoints enforce separate admin scope checks.
- For provider admin enrolment URL export operations, use `POST` with CSRF protection; do not automate them via unauthenticated `GET` links.
- Handle provider CSV exports with formula-injection safety in mind if opening them in spreadsheet applications.
- Treat generated enrolment URLs as secrets and keep them out of URL query strings and request logs.
- For reverse-proxy deployments, harden trusted proxy/IP forwarding configuration to prevent spoofed client IP headers.
- Prefer narrowly scoped trusted-proxy entries (explicit IPs/CIDR ranges) instead of broad network trust.
- Keep client-side admin mutation retries idempotent; approval workflows can be lock-serialised and should not be assumed to execute twice.
- Do not submit parallel approve/reject/cancel decisions for the same approval request ID.
- Apply bounded CSV import sizes and row counts for admin bulk-user operations.
- Never place client secrets, refresh tokens, or access tokens in URL query strings.
- For OIDC providers, include a per-request `nonce` in authorisation requests and validate it when an `id_token` is returned.
- Ensure requested `scope` values in SDK config/examples (for example `offline_access`) are enabled on the provider-side client before rollout.
- Expect refresh-token exchange to fail (`invalid_grant`) if provider-side client scopes were tightened and the refresh token now carries disallowed scopes.
- For direct Cryptbin API usage, send `key_b64url` on unwrap calls; provider rejects key-mismatch unwrap attempts with `403 Forbidden`.
- For newly created Cryptbin items, continue using the creating WebAuthn credential for unwrap/update/delete flows.
- Always use HTTPS in production.
- Store refresh tokens securely.
- Keep access tokens out of logs and browser-visible output.
- Use short session lifetimes where possible.
- `Config::fromArray()` enforces HTTPS URLs by default.
- For localhost-only development over HTTP, set `allowInsecureHttp => true`.

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
