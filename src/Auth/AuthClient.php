<?php

declare(strict_types=1);

namespace BlackWall\Auth;

use BlackWall\Auth\Exception\NonceMismatchException;
use BlackWall\Auth\Exception\AuthException;
use BlackWall\Auth\Exception\StateMismatchException;
use BlackWall\Auth\Exception\TokenExchangeException;
use BlackWall\Auth\Exception\UserInfoException;
use BlackWall\Auth\Http\CurlHttpClient;
use BlackWall\Auth\Http\HttpClientInterface;

final class AuthClient
{
    public const STATE_SESSION_KEY = 'blackwall_oauth_state';
    public const CODE_VERIFIER_SESSION_KEY = 'blackwall_oauth_code_verifier';
    public const NONCE_SESSION_KEY = 'blackwall_oidc_nonce';

    public function __construct(
        private readonly Config $config,
        private readonly HttpClientInterface $httpClient = new CurlHttpClient()
    ) {
    }

    /**
     * @param array<string, mixed> $options
     * @return array{url:string,state:string,code_verifier:string,code_challenge:string,nonce:?string}
     */
    public function buildAuthorisationUrl(array $options = []): array
    {
        $state = isset($options['state']) ? (string) $options['state'] : bin2hex(random_bytes(16));
        $codeVerifier = isset($options['code_verifier']) ? (string) $options['code_verifier'] : $this->randomUrlSafe(43);
        $codeChallenge = $this->base64Url(hash('sha256', $codeVerifier, true));
        $scope = isset($options['scope']) ? (string) $options['scope'] : $this->config->defaultScope;
        $extra = isset($options['extra']) && is_array($options['extra']) ? $options['extra'] : [];
        $persist = !isset($options['persist']) || (bool) $options['persist'];
        $nonce = $this->resolveNonce($scope, $options, $extra);

        if ($persist && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION[self::STATE_SESSION_KEY] = $state;
            $_SESSION[self::CODE_VERIFIER_SESSION_KEY] = $codeVerifier;
            if ($nonce !== null) {
                $_SESSION[self::NONCE_SESSION_KEY] = $nonce;
            } else {
                unset($_SESSION[self::NONCE_SESSION_KEY]);
            }
        }

        $query = array_merge([
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'scope' => $scope,
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], $extra);
        if ($nonce !== null) {
            $query['nonce'] = $nonce;
        }

        $url = $this->config->authorizeUrl . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $url,
            'state' => $state,
            'code_verifier' => $codeVerifier,
            'code_challenge' => $codeChallenge,
            'nonce' => $nonce,
        ];
    }

    public function assertStateMatches(string $state): void
    {
        $sessionState = $_SESSION[self::STATE_SESSION_KEY] ?? null;
        if (!is_string($sessionState) || $state !== $sessionState) {
            throw new StateMismatchException('The OAuth state did not match the session value', 'state_mismatch');
        }
    }

    public function assertNonceMatches(string $nonce): void
    {
        $sessionNonce = $_SESSION[self::NONCE_SESSION_KEY] ?? null;
        if (!is_string($sessionNonce) || $nonce !== $sessionNonce) {
            throw new NonceMismatchException('The OIDC nonce did not match the session value', 'nonce_mismatch');
        }
    }

    public function exchangeCodeForTokens(string $code, ?string $codeVerifier = null): TokenSet
    {
        $verifier = $codeVerifier ?? ($_SESSION[self::CODE_VERIFIER_SESSION_KEY] ?? null);
        if (!is_string($verifier) || $verifier === '') {
            throw new TokenExchangeException('Missing code verifier; pass one explicitly or persist it in session.', 'missing_code_verifier');
        }

        $payload = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id' => $this->config->clientId,
            'code_verifier' => $verifier,
        ];

        if ($this->config->clientSecret !== null && $this->config->clientSecret !== '') {
            $payload['client_secret'] = $this->config->clientSecret;
        }

        $result = $this->httpClient->postForm($this->config->tokenUrl, $payload);
        $data = json_decode($result['body'], true);

        if ($result['status'] >= 400) {
            $message = is_array($data) ? json_encode($data) : $result['body'];
            throw new TokenExchangeException('Token endpoint error (' . $result['status'] . '): ' . $message, 'token_exchange_failed');
        }

        if (!is_array($data)) {
            throw new TokenExchangeException('Token endpoint returned invalid JSON', 'token_response_invalid_json');
        }

        return TokenSet::fromArray($data);
    }

    public function refreshAccessToken(string $refreshToken): TokenSet
    {
        $payload = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->config->clientId,
        ];

        if ($this->config->clientSecret !== null && $this->config->clientSecret !== '') {
            $payload['client_secret'] = $this->config->clientSecret;
        }

        $result = $this->httpClient->postForm($this->config->tokenUrl, $payload);
        $data = json_decode($result['body'], true);

        if ($result['status'] >= 400) {
            $message = is_array($data) ? json_encode($data) : $result['body'];
            throw new TokenExchangeException('Refresh token error (' . $result['status'] . '): ' . $message, 'refresh_exchange_failed');
        }

        if (!is_array($data)) {
            throw new TokenExchangeException('Refresh token response was not valid JSON', 'refresh_response_invalid_json');
        }

        return TokenSet::fromArray($data);
    }

    /**
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array
    {
        if ($this->config->userInfoUrl === null || $this->config->userInfoUrl === '') {
            throw new UserInfoException('UserInfo URL has not been configured', 'userinfo_url_missing');
        }

        $result = $this->httpClient->get($this->config->userInfoUrl, [
            'Authorization' => 'Bearer ' . $accessToken,
        ]);

        $data = json_decode($result['body'], true);
        if ($result['status'] >= 400) {
            $message = is_array($data) ? json_encode($data) : $result['body'];
            throw new UserInfoException('UserInfo endpoint error (' . $result['status'] . '): ' . $message, 'userinfo_request_failed');
        }

        if (!is_array($data)) {
            throw new UserInfoException('UserInfo response was not valid JSON', 'userinfo_invalid_json');
        }

        return $data;
    }

    public function getNormalizedUserInfo(string $accessToken): UserInfo
    {
        return UserInfoNormalizer::normalize($this->getUserInfo($accessToken));
    }

    /**
     * Decodes JWT payload claims only. This does not verify signature, issuer, audience, expiry, or token use.
     *
     * @return array<string, mixed>
     */
    public function decodeJwtPayloadClaims(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new AuthException('JWT must contain exactly three segments', 'invalid_jwt');
        }

        $payload = $this->base64UrlDecode($parts[1]);
        if ($payload === false) {
            throw new AuthException('JWT payload was not valid base64url', 'invalid_jwt');
        }

        $claims = json_decode($payload, true);
        if (!is_array($claims)) {
            throw new AuthException('JWT payload was not valid JSON', 'invalid_jwt');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    public function assertIdTokenNonceMatches(string $idToken, ?string $expectedNonce = null): array
    {
        $claims = $this->decodeJwtPayloadClaims($idToken);
        $nonce = $claims['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '') {
            throw new NonceMismatchException('The ID token did not contain a nonce claim', 'nonce_missing');
        }

        $expected = $expectedNonce ?? ($_SESSION[self::NONCE_SESSION_KEY] ?? null);
        if (!is_string($expected) || $expected === '') {
            throw new NonceMismatchException('Missing expected nonce; pass one explicitly or persist it in session.', 'missing_expected_nonce');
        }

        if (!hash_equals($expected, $nonce)) {
            throw new NonceMismatchException('The ID token nonce did not match the expected value', 'nonce_mismatch');
        }

        return $claims;
    }

    /**
     * @param array<string, mixed> $query
     * @param array{expected_nonce?:?string,validate_nonce?:bool,allow_missing_nonce?:bool} $options
     */
    public function handleCallback(array $query, bool $clearPkce = true, array $options = []): CallbackResult
    {
        if (!isset($query['code'], $query['state'])) {
            throw new UserInfoException('Missing code/state', 'missing_callback_params');
        }

        $this->assertStateMatches((string) $query['state']);
        $tokens = $this->exchangeCodeForTokens((string) $query['code']);
        $this->maybeValidateNonce($tokens, $options);
        $rawUser = $this->getUserInfo($tokens->accessToken);
        $user = UserInfoNormalizer::normalize($rawUser);

        if ($clearPkce) {
            $this->clearPkceSessionState();
        }

        return new CallbackResult($tokens, $user, $rawUser);
    }

    /**
     * @param array<string, mixed> $userInfo
     */
    public static function resolvePrivilegeLevel(array $userInfo): ?int
    {
        return UserInfoNormalizer::resolvePrivilegeLevel($userInfo);
    }

    /**
     * @param array<string, mixed> $userInfo
     */
    public static function resolveRole(array $userInfo): ?string
    {
        return UserInfoNormalizer::resolveRole($userInfo);
    }

    public function exchangeCodeAndFetchUser(string $code, ?string $codeVerifier = null): AuthResult
    {
        $tokens = $this->exchangeCodeForTokens($code, $codeVerifier);
        $user = $this->getUserInfo($tokens->accessToken);

        return new AuthResult($tokens, $user);
    }

    public function clearPkceSessionState(): void
    {
        unset($_SESSION[self::STATE_SESSION_KEY], $_SESSION[self::CODE_VERIFIER_SESSION_KEY], $_SESSION[self::NONCE_SESSION_KEY]);
    }

    private function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $value): string|false
    {
        $padding = strlen($value) % 4;
        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($value, '-_', '+/'), true);
    }

    /**
     * @param array<string, mixed> $options
     * @param array<string, mixed> $extra
     */
    private function resolveNonce(string $scope, array $options, array $extra): ?string
    {
        if (array_key_exists('nonce', $options)) {
            $nonce = $options['nonce'];
            return is_string($nonce) && $nonce !== '' ? $nonce : null;
        }

        if (isset($extra['nonce']) && is_string($extra['nonce']) && $extra['nonce'] !== '') {
            return $extra['nonce'];
        }

        return $this->scopeIncludesOpenId($scope) ? $this->randomUrlSafe(32) : null;
    }

    private function scopeIncludesOpenId(string $scope): bool
    {
        $scopes = preg_split('/\s+/', trim($scope)) ?: [];
        return in_array('openid', $scopes, true);
    }

    /**
     * @param array{expected_nonce?:?string,validate_nonce?:bool,allow_missing_nonce?:bool} $options
     */
    private function maybeValidateNonce(TokenSet $tokens, array $options): void
    {
        $validateNonce = !isset($options['validate_nonce']) || (bool) $options['validate_nonce'];
        if (!$validateNonce || $tokens->idToken === null) {
            return;
        }

        $expectedNonce = $options['expected_nonce'] ?? ($_SESSION[self::NONCE_SESSION_KEY] ?? null);
        if (!is_string($expectedNonce) || $expectedNonce === '') {
            return;
        }

        $allowMissingNonce = !isset($options['allow_missing_nonce']) || (bool) $options['allow_missing_nonce'];
        if ($allowMissingNonce) {
            $claims = $this->decodeJwtPayloadClaims($tokens->idToken);
            $nonce = $claims['nonce'] ?? null;
            if (!is_string($nonce) || $nonce === '') {
                return;
            }

            if (!hash_equals($expectedNonce, $nonce)) {
                throw new NonceMismatchException('The ID token nonce did not match the expected value', 'nonce_mismatch');
            }

            return;
        }

        $this->assertIdTokenNonceMatches($tokens->idToken, $expectedNonce);
    }

    private function randomUrlSafe(int $length): string
    {
        return $this->base64Url(random_bytes($length));
    }
}
