<?php

declare(strict_types=1);

namespace BlackWall\Auth\Http;

interface HttpClientInterface
{
    /**
     * @param array<string, string> $headers
     * @return array{status:int, body:string}
     */
    public function postForm(string $url, array $fields, array $headers = []): array;

    /**
     * @param array<string, string> $headers
     * @return array{status:int, body:string}
     */
    public function get(string $url, array $headers = []): array;
}
