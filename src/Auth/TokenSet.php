<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class TokenSet
{
    /**
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly ?string $refreshToken,
        public readonly ?string $idToken,
        public readonly string $tokenType,
        public readonly ?int $expiresIn,
        public readonly ?string $scope,
        public readonly array $raw
    ) {
    }

    /**
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        if (empty($payload['access_token']) || !is_string($payload['access_token'])) {
            throw new \InvalidArgumentException('Token payload does not include access_token');
        }

        return new self(
            accessToken: $payload['access_token'],
            refreshToken: isset($payload['refresh_token']) && is_string($payload['refresh_token']) ? $payload['refresh_token'] : null,
            idToken: isset($payload['id_token']) && is_string($payload['id_token']) ? $payload['id_token'] : null,
            tokenType: isset($payload['token_type']) && is_string($payload['token_type']) ? $payload['token_type'] : 'Bearer',
            expiresIn: isset($payload['expires_in']) ? (int) $payload['expires_in'] : null,
            scope: isset($payload['scope']) && is_string($payload['scope']) ? $payload['scope'] : null,
            raw: $payload
        );
    }
}
