<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class AuthResult
{
    /**
     * @param array<string, mixed> $user
     */
    public function __construct(
        public readonly TokenSet $tokens,
        public readonly array $user
    ) {
    }
}
