<?php

declare(strict_types=1);

namespace BlackWall\Auth;

use BlackWall\Auth\Exception\StateMismatchException;
use BlackWall\Auth\Exception\TokenExchangeException;
use BlackWall\Auth\Exception\UserInfoException;
use BlackWall\Auth\Http\CurlHttpClient;
use BlackWall\Auth\Http\HttpClientInterface;

final class AuthClient
{
    public function __construct(
        private readonly Config $config,
        private readonly HttpClientInterface $httpClient = new CurlHttpClient()
    ) {
    }

    /**
     * @param array<string, mixed> $options
     * @return array{url:string,state:string,code_verifier:string,code_challenge:string}
     */
    public function buildAuthorisationUrl(array $options = []): array
    {
        $state = isset($options['state']) ? (string) $options['state'] : bin2hex(random_bytes(16));
        $codeVerifier = isset($options['code_verifier']) ? (string) $options['code_verifier'] : $this->randomUrlSafe(43);
        $codeChallenge = $this->base64Url(hash('sha256', $codeVerifier, true));
        $scope = isset($options['scope']) ? (string) $options['scope'] : $this->config->defaultScope;
        $extra = isset($options['extra']) && is_array($options['extra']) ? $options['extra'] : [];
        $persist = !isset($options['persist']) || (bool) $options['persist'];

        if ($persist && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['blackwall_oauth_state'] = $state;
            $_SESSION['blackwall_oauth_code_verifier'] = $codeVerifier;
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

        $url = $this->config->authorizeUrl . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $url,
            'state' => $state,
            'code_verifier' => $codeVerifier,
            'code_challenge' => $codeChallenge,
        ];
    }

    public function assertStateMatches(string $state): void
    {
        $sessionState = $_SESSION['blackwall_oauth_state'] ?? null;
        if (!is_string($sessionState) || $state !== $sessionState) {
            throw new StateMismatchException('The OAuth state did not match the session value');
        }
    }

    public function exchangeCodeForTokens(string $code, ?string $codeVerifier = null): TokenSet
    {
        $verifier = $codeVerifier ?? ($_SESSION['blackwall_oauth_code_verifier'] ?? null);
        if (!is_string($verifier) || $verifier === '') {
            throw new TokenExchangeException('Missing code verifier; pass one explicitly or persist it in session.');
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
            throw new TokenExchangeException('Token endpoint error (' . $result['status'] . '): ' . $message);
        }

        if (!is_array($data)) {
            throw new TokenExchangeException('Token endpoint returned invalid JSON');
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
            throw new TokenExchangeException('Refresh token error (' . $result['status'] . '): ' . $message);
        }

        if (!is_array($data)) {
            throw new TokenExchangeException('Refresh token response was not valid JSON');
        }

        return TokenSet::fromArray($data);
    }

    /**
     * @return array<string, mixed>
     */
    public function getUserInfo(string $accessToken): array
    {
        if ($this->config->userInfoUrl === null || $this->config->userInfoUrl === '') {
            throw new UserInfoException('UserInfo URL has not been configured');
        }

        $result = $this->httpClient->get($this->config->userInfoUrl, [
            'Authorization' => 'Bearer ' . $accessToken,
        ]);

        $data = json_decode($result['body'], true);
        if ($result['status'] >= 400) {
            $message = is_array($data) ? json_encode($data) : $result['body'];
            throw new UserInfoException('UserInfo endpoint error (' . $result['status'] . '): ' . $message);
        }

        if (!is_array($data)) {
            throw new UserInfoException('UserInfo response was not valid JSON');
        }

        return $data;
    }

    public function exchangeCodeAndFetchUser(string $code, ?string $codeVerifier = null): AuthResult
    {
        $tokens = $this->exchangeCodeForTokens($code, $codeVerifier);
        $user = $this->getUserInfo($tokens->accessToken);

        return new AuthResult($tokens, $user);
    }

    public function clearPkceSessionState(): void
    {
        unset($_SESSION['blackwall_oauth_state'], $_SESSION['blackwall_oauth_code_verifier']);
    }

    private function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    private function randomUrlSafe(int $length): string
    {
        return $this->base64Url(random_bytes($length));
    }
}
