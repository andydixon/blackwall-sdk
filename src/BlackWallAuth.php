<?php

declare(strict_types=1);

namespace BlackWallSDK;

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

/**
 * Backwards-compatible wrapper for existing integrations.
 *
 * Prefer using BlackWall\Auth\AuthClient directly for new projects.
 */
class BlackWallAuth
{
    private AuthClient $client;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        $this->client = new AuthClient(Config::fromArray($config));
    }

    /**
     * @param array<string, mixed> $opts
     * @return array{url:string,state:string,code_verifier:string,code_challenge:string,nonce:?string}
     */
    public function getAuthorizationUrl(array $opts = []): array
    {
        return $this->client->buildAuthorisationUrl($opts);
    }

    public function assertNonceMatches(string $nonce): void
    {
        $this->client->assertNonceMatches($nonce);
    }

    /**
     * @return array<string, mixed>
     */
    public function assertIdTokenNonceMatches(string $idToken, ?string $expectedNonce = null): array
    {
        return $this->client->assertIdTokenNonceMatches($idToken, $expectedNonce);
    }

    /**
     * Decodes JWT payload claims only. This does not perform cryptographic verification.
     *
     * @return array<string, mixed>
     */
    public function decodeJwtPayloadClaims(string $jwt): array
    {
        return $this->client->decodeJwtPayloadClaims($jwt);
    }

    /**
     * @return array<string, mixed>
     */
    public function exchangeCodeForTokens(string $code, ?string $codeVerifier = null): array
    {
        return $this->client->exchangeCodeForTokens($code, $codeVerifier)->raw;
    }

    /**
     * @return array<string, mixed>
     */
    public function refreshAccessToken(string $refreshToken): array
    {
        return $this->client->refreshAccessToken($refreshToken)->raw;
    }

    /**
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array
    {
        return $this->client->getUserInfo($accessToken);
    }

    /**
     * @return array{email:string,privilege_level:?int,role:?string,raw:array<string,mixed>}
     */
    public function getNormalizedUserInfo(string $accessToken): array
    {
        $normalized = $this->client->getNormalizedUserInfo($accessToken);
        return [
            'email' => $normalized->email,
            'privilege_level' => $normalized->privilegeLevel,
            'role' => $normalized->role,
            'raw' => $normalized->raw,
        ];
    }

    /**
     * @param array<string,mixed> $query
    * @param array{expected_nonce?:?string,validate_nonce?:bool,allow_missing_nonce?:bool} $options
     * @return array{
     *   tokens: array<string,mixed>,
     *   user: array{email:string,privilege_level:?int,role:?string,raw:array<string,mixed>},
     *   raw_user: array<string,mixed>
     * }
     */
    public function handleCallback(array $query, bool $clearPkce = true, array $options = []): array
    {
        $result = $this->client->handleCallback($query, $clearPkce, $options);
        return [
            'tokens' => $result->tokens->raw,
            'user' => [
                'email' => $result->user->email,
                'privilege_level' => $result->user->privilegeLevel,
                'role' => $result->user->role,
                'raw' => $result->user->raw,
            ],
            'raw_user' => $result->rawUser,
        ];
    }
}
