<?php

declare(strict_types=1);

namespace BlackWall\Auth\Http;

use BlackWall\Auth\Exception\TransportException;

final class CurlHttpClient implements HttpClientInterface
{
    public function __construct(private readonly int $timeoutSeconds = 20)
    {
    }

    public function postForm(string $url, array $fields, array $headers = []): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('Unable to initialise cURL for POST request');
        }

        $headerLines = $this->normaliseHeaders(array_merge([
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ], $headers));

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
        ]);

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new TransportException($error !== '' ? $error : 'Unknown cURL POST error');
        }

        return ['status' => $status, 'body' => $body];
    }

    public function get(string $url, array $headers = []): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('Unable to initialise cURL for GET request');
        }

        $headerLines = $this->normaliseHeaders(array_merge([
            'Accept' => 'application/json',
        ], $headers));

        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
        ]);

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new TransportException($error !== '' ? $error : 'Unknown cURL GET error');
        }

        return ['status' => $status, 'body' => $body];
    }

    /**
     * @param array<string, string> $headers
     * @return string[]
     */
    private function normaliseHeaders(array $headers): array
    {
        $result = [];
        foreach ($headers as $name => $value) {
            $result[] = sprintf('%s: %s', $name, $value);
        }

        return $result;
    }
}
