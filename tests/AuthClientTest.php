<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;
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
        self::assertSame($result['state'], $_SESSION['blackwall_oauth_state']);
        self::assertSame($result['code_verifier'], $_SESSION['blackwall_oauth_code_verifier']);
        self::assertStringContainsString('code_challenge_method=S256', $result['url']);
    }

    public function testAssertStateMatchesThrowsOnMismatch(): void
    {
        $_SESSION['blackwall_oauth_state'] = 'expected';

        $this->expectException(StateMismatchException::class);
        $this->client->assertStateMatches('actual');
    }

    public function testExchangeCodeForTokensReturnsTypedTokenSet(): void
    {
        $_SESSION['blackwall_oauth_code_verifier'] = 'verifier-123';

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
        $_SESSION['blackwall_oauth_code_verifier'] = 'verifier-123';

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
}
