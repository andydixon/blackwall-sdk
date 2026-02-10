<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class Config
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $authorizeUrl,
        public readonly string $tokenUrl,
        public readonly string $redirectUri,
        public readonly ?string $userInfoUrl = null,
        public readonly ?string $clientSecret = null,
        public readonly string $defaultScope = 'openid profile email'
    ) {
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        foreach (['clientId', 'authorizeUrl', 'tokenUrl', 'redirectUri'] as $required) {
            if (empty($config[$required]) || !is_string($config[$required])) {
                throw new \InvalidArgumentException("{$required} is required");
            }
        }

        return new self(
            clientId: $config['clientId'],
            authorizeUrl: rtrim($config['authorizeUrl'], '/'),
            tokenUrl: rtrim($config['tokenUrl'], '/'),
            redirectUri: $config['redirectUri'],
            userInfoUrl: isset($config['userInfoUrl']) ? rtrim((string) $config['userInfoUrl'], '/') : null,
            clientSecret: isset($config['clientSecret']) ? (string) $config['clientSecret'] : null,
            defaultScope: isset($config['scope']) ? (string) $config['scope'] : 'openid profile email'
        );
    }
}
