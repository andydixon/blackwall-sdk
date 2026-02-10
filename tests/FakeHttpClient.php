<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\Http\HttpClientInterface;

final class FakeHttpClient implements HttpClientInterface
{
    /** @var list<array{status:int,body:string}> */
    private array $postQueue = [];

    /** @var list<array{status:int,body:string}> */
    private array $getQueue = [];

    /** @var list<array{url:string,fields:array<string,string>,headers:array<string,string>}> */
    public array $postCalls = [];

    /** @var list<array{url:string,headers:array<string,string>}> */
    public array $getCalls = [];

    /**
     * @param array{status:int,body:string} $response
     */
    public function queuePost(array $response): void
    {
        $this->postQueue[] = $response;
    }

    /**
     * @param array{status:int,body:string} $response
     */
    public function queueGet(array $response): void
    {
        $this->getQueue[] = $response;
    }

    public function postForm(string $url, array $fields, array $headers = []): array
    {
        /** @var array<string, string> $fields */
        /** @var array<string, string> $headers */
        $this->postCalls[] = ['url' => $url, 'fields' => $fields, 'headers' => $headers];

        if ($this->postQueue === []) {
            throw new \RuntimeException('No fake POST response queued');
        }

        return array_shift($this->postQueue);
    }

    public function get(string $url, array $headers = []): array
    {
        /** @var array<string, string> $headers */
        $this->getCalls[] = ['url' => $url, 'headers' => $headers];

        if ($this->getQueue === []) {
            throw new \RuntimeException('No fake GET response queued');
        }

        return array_shift($this->getQueue);
    }
}
