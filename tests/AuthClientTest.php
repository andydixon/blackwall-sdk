<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;
use BlackWall\Auth\Exception\NonceMismatchException;
use BlackWall\Auth\Exception\StateMismatchException;
use BlackWall\Auth\Exception\TokenExchangeException;
use BlackWall\Auth\Exception\UserInfoException;
use PHPUnit\Framework\TestCase;

final class AuthClientTest extends TestCase
{
    private Config $config;
    private FakeHttpClient $http;
    private AuthClient $client;

    protected function setUp(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }

        $_SESSION = [];

        $this->config = Config::fromArray([
            'clientId' => 'client-123',
            'authorizeUrl' => 'https://provider.example/oauth/authorize',
            'tokenUrl' => 'https://provider.example/oauth/token',
            'userInfoUrl' => 'https://provider.example/oauth/userinfo',
            'redirectUri' => 'https://app.example/callback.php',
            'scope' => 'openid profile email',
            'clientSecret' => 'secret-abc',
        ]);

        $this->http = new FakeHttpClient();
        $this->client = new AuthClient($this->config, $this->http);
    }

    public function testBuildAuthorisationUrlPersistsStateAndVerifier(): void
    {
        $result = $this->client->buildAuthorisationUrl();

        self::assertArrayHasKey('url', $result);
        self::assertArrayHasKey('state', $result);
        self::assertArrayHasKey('code_verifier', $result);
        self::assertArrayHasKey('code_challenge', $result);
        self::assertArrayHasKey('nonce', $result);
        self::assertIsString($result['nonce']);
        self::assertNotSame('', $result['nonce']);
        self::assertSame($result['state'], $_SESSION[AuthClient::STATE_SESSION_KEY]);
        self::assertSame($result['code_verifier'], $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY]);
        self::assertSame($result['nonce'], $_SESSION[AuthClient::NONCE_SESSION_KEY]);
        self::assertStringContainsString('code_challenge_method=S256', $result['url']);
        self::assertStringContainsString('nonce=', $result['url']);
    }

    public function testBuildAuthorisationUrlDoesNotGenerateNonceWithoutOpenIdScope(): void
    {
        $result = $this->client->buildAuthorisationUrl([
            'scope' => 'profile email',
        ]);

        self::assertNull($result['nonce']);
        self::assertArrayNotHasKey(AuthClient::NONCE_SESSION_KEY, $_SESSION);
        self::assertStringNotContainsString('nonce=', $result['url']);
    }

    public function testBuildAuthorisationUrlPersistsProvidedNonce(): void
    {
        $result = $this->client->buildAuthorisationUrl([
            'nonce' => 'nonce-123',
        ]);

        self::assertSame('nonce-123', $result['nonce']);
        self::assertSame('nonce-123', $_SESSION[AuthClient::NONCE_SESSION_KEY]);
    }

    public function testAssertNonceMatchesThrowsOnMismatch(): void
    {
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->expectException(NonceMismatchException::class);
        $this->client->assertNonceMatches('actual-nonce');
    }

    public function testDecodeJwtPayloadClaimsReturnsClaimsWithoutVerification(): void
    {
        $claims = $this->client->decodeJwtPayloadClaims($this->makeJwt([
            'sub' => 'user-1',
            'nonce' => 'nonce-1',
        ]));

        self::assertSame('user-1', $claims['sub']);
        self::assertSame('nonce-1', $claims['nonce']);
    }

    public function testAssertStateMatchesThrowsOnMismatch(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'expected';

        $this->expectException(StateMismatchException::class);
        $this->client->assertStateMatches('actual');
    }

    public function testExchangeCodeForTokensReturnsTypedTokenSet(): void
    {
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => 'id-1',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'scope' => 'openid profile email',
            ], JSON_THROW_ON_ERROR),
        ]);

        $tokens = $this->client->exchangeCodeForTokens('code-1');

        self::assertSame('access-1', $tokens->accessToken);
        self::assertSame('refresh-1', $tokens->refreshToken);
        self::assertSame('id-1', $tokens->idToken);
        self::assertSame(3600, $tokens->expiresIn);
        self::assertCount(1, $this->http->postCalls);
        self::assertSame('authorization_code', $this->http->postCalls[0]['fields']['grant_type']);
        self::assertSame('verifier-123', $this->http->postCalls[0]['fields']['code_verifier']);
    }

    public function testExchangeCodeForTokensThrowsWhenVerifierMissing(): void
    {
        $this->expectException(TokenExchangeException::class);
        $this->client->exchangeCodeForTokens('code-2');
    }

    public function testExchangeCodeForTokensThrowsOnEndpointError(): void
    {
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';

        $this->http->queuePost([
            'status' => 400,
            'body' => '{"error":"invalid_grant"}',
        ]);

        $this->expectException(TokenExchangeException::class);
        $this->expectExceptionMessage('Token endpoint error (400)');
        $this->client->exchangeCodeForTokens('bad-code');
    }

    public function testRefreshAccessTokenCallsRefreshGrant(): void
    {
        $this->http->queuePost([
            'status' => 200,
            'body' => '{"access_token":"access-2","refresh_token":"refresh-2","token_type":"Bearer"}',
        ]);

        $tokens = $this->client->refreshAccessToken('refresh-1');

        self::assertSame('access-2', $tokens->accessToken);
        self::assertSame('refresh_token', $this->http->postCalls[0]['fields']['grant_type']);
        self::assertSame('refresh-1', $this->http->postCalls[0]['fields']['refresh_token']);
        self::assertSame('client-123', $this->http->postCalls[0]['fields']['client_id']);
    }

    public function testGetUserInfoReturnsPayload(): void
    {
        $this->http->queueGet([
            'status' => 200,
            'body' => '{"sub":"user-1","name":"Example User"}',
        ]);

        $user = $this->client->getUserInfo('access-3');

        self::assertSame('user-1', $user['sub']);
        self::assertCount(1, $this->http->getCalls);
        self::assertSame('Bearer access-3', $this->http->getCalls[0]['headers']['Authorization']);
    }

    public function testGetUserInfoThrowsOnErrorResponse(): void
    {
        $this->http->queueGet([
            'status' => 401,
            'body' => '{"error":"invalid_token"}',
        ]);

        $this->expectException(UserInfoException::class);
        $this->expectExceptionMessage('UserInfo endpoint error (401)');
        $this->client->getUserInfo('expired-token');
    }

    public function testGetNormalizedUserInfoReturnsCanonicalFields(): void
    {
        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"Admin@Example.com","claims":{"role":"admin"}}',
        ]);

        $user = $this->client->getNormalizedUserInfo('access-4');

        self::assertSame('admin@example.com', $user->email);
        self::assertSame(1, $user->privilegeLevel);
        self::assertSame('admin', $user->role);
    }

    public function testResolvePrivilegeLevelSupportsAliases(): void
    {
        self::assertSame(1, AuthClient::resolvePrivilegeLevel(['privilege_level' => 1]));
        self::assertSame(2, AuthClient::resolvePrivilegeLevel(['claims' => ['role_level' => '2']]));
        self::assertSame(1, AuthClient::resolvePrivilegeLevel(['role' => 'superadmin']));
        self::assertSame(2, AuthClient::resolvePrivilegeLevel(['role' => 'tutor']));
        self::assertNull(AuthClient::resolvePrivilegeLevel(['foo' => 'bar']));
    }

    public function testHandleCallbackReturnsCallbackResult(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'nonce-1';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => $this->makeJwt(['nonce' => 'nonce-1', 'sub' => 'user-1']),
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"tutor@example.com","privilege_level":2}',
        ]);

        $result = $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ]);

        self::assertSame('access-1', $result->tokens->accessToken);
        self::assertSame('tutor@example.com', $result->user->email);
        self::assertSame(2, $result->user->privilegeLevel);
        self::assertArrayNotHasKey(AuthClient::STATE_SESSION_KEY, $_SESSION);
        self::assertArrayNotHasKey(AuthClient::CODE_VERIFIER_SESSION_KEY, $_SESSION);
        self::assertArrayNotHasKey(AuthClient::NONCE_SESSION_KEY, $_SESSION);
    }

    public function testHandleCallbackThrowsWhenIdTokenNonceDoesNotMatch(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => $this->makeJwt(['nonce' => 'actual-nonce', 'sub' => 'user-1']),
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->expectException(NonceMismatchException::class);
        $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ]);
    }

    public function testHandleCallbackSucceedsWhenNoIdTokenReturned(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"tutor@example.com","privilege_level":2}',
        ]);

        $result = $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ]);

        self::assertSame('access-1', $result->tokens->accessToken);
        self::assertNull($result->tokens->idToken);
    }

    public function testHandleCallbackAllowsMissingNonceClaimWhenEnabled(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => $this->makeJwt(['sub' => 'user-1']),
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"tutor@example.com","privilege_level":2}',
        ]);

        $result = $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ], true, [
            'allow_missing_nonce' => true,
        ]);

        self::assertSame('access-1', $result->tokens->accessToken);
    }

    public function testHandleCallbackAllowsMissingNonceClaimByDefault(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => $this->makeJwt(['sub' => 'user-1']),
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"tutor@example.com","privilege_level":2}',
        ]);

        $result = $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ]);

        self::assertSame('access-1', $result->tokens->accessToken);
    }

    public function testHandleCallbackCanDisableNonceValidationTemporarily(): void
    {
        $_SESSION[AuthClient::STATE_SESSION_KEY] = 'state-1';
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY] = 'verifier-123';
        $_SESSION[AuthClient::NONCE_SESSION_KEY] = 'expected-nonce';

        $this->http->queuePost([
            'status' => 200,
            'body' => json_encode([
                'access_token' => 'access-1',
                'refresh_token' => 'refresh-1',
                'id_token' => $this->makeJwt(['nonce' => 'different-nonce', 'sub' => 'user-1']),
                'token_type' => 'Bearer',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->http->queueGet([
            'status' => 200,
            'body' => '{"email":"tutor@example.com","privilege_level":2}',
        ]);

        $result = $this->client->handleCallback([
            'code' => 'code-1',
            'state' => 'state-1',
        ], true, [
            'validate_nonce' => false,
        ]);

        self::assertSame('access-1', $result->tokens->accessToken);
    }

    public function testHandleCallbackThrowsOnMissingParams(): void
    {
        $this->expectException(UserInfoException::class);
        $this->client->handleCallback(['state' => 'only-state']);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function makeJwt(array $claims): string
    {
        $header = $this->base64Url(json_encode(['alg' => 'none', 'typ' => 'JWT'], JSON_THROW_ON_ERROR));
        $payload = $this->base64Url(json_encode($claims, JSON_THROW_ON_ERROR));

        return $header . '.' . $payload . '.signature';
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
