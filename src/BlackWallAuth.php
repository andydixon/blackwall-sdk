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
     * @return array{url:string,state:string,code_verifier:string,code_challenge:string}
     */
    public function getAuthorizationUrl(array $opts = []): array
    {
        return $this->client->buildAuthorisationUrl($opts);
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
}
