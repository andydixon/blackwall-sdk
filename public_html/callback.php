<?php

declare(strict_types=1);

session_start();

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../src/legacy_autoload.php',
];

foreach ($autoloadCandidates as $file) {
    if (is_file($file)) {
        require_once $file;
    }
}

use BlackWallSDK\BlackWallAuth;

$auth = new BlackWallAuth([
    'clientId' => '94d228c4-d4c6-4479-9b02-793e6a73e3f2',
    'authorizeUrl' => 'https://blackwall.dixon.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.dixon.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.dixon.cx/oauth/userinfo',
    'redirectUri' => 'https://test.dixon.cx/callback.php',
]);

if (!isset($_GET['code'], $_GET['state'])) {
    http_response_code(400);
    echo 'Missing code/state';
    exit;
}

if (isset($_SESSION['blackwall_oauth_state']) && $_GET['state'] !== $_SESSION['blackwall_oauth_state']) {
    http_response_code(400);
    echo 'Invalid state';
    exit;
}

try {
    $tokens = $auth->exchangeCodeForTokens($_GET['code']);
    $_SESSION['access_token'] = $tokens['access_token'] ?? null;
    $_SESSION['refresh_token'] = $tokens['refresh_token'] ?? null;

    if (isset($_SESSION['access_token']) && is_string($_SESSION['access_token'])) {
        $_SESSION['user'] = $auth->getUserInfo($_SESSION['access_token']);
    }

    unset($_SESSION['blackwall_oauth_state'], $_SESSION['blackwall_oauth_code_verifier']);

    header('Location: /');
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Auth failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
