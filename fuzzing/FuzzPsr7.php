<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use PhpFuzzer\Config;
use RuntimeException;
use function array_key_exists;
use function hash_equals;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function strlen;
use function substr;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    $response = new Response(200, ['Content-Type' => 'application/json'], $input);

    $body = $response->getBody()->getContents();
    if ($body !== $input) {
        throw new RuntimeException('Response body contents mismatch');
    }

    $response->getBody()->rewind();
    $body2 = $response->getBody()->getContents();
    if ($body2 !== $input) {
        throw new RuntimeException('Response body re-read mismatch');
    }

    $decoded = json_decode($input, true, 32);
    if (is_array($decoded)) {
        // Simulate protocol message construction
        $message = [
            '!pkd-context' => 'https://github.com/fedi-e2ee/public-key-directory/v1',
            'action' => 'TestAction',
            'message' => $decoded,
        ];

        $encoded = json_encode($message, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $request = new Request(
            'POST',
            'https://pkd.example.com/inbox',
            ['Content-Type' => 'application/json'],
            $encoded
        );

        if ($request->getMethod() !== 'POST') {
            throw new RuntimeException('Request method mismatch');
        }

        $requestBody = $request->getBody()->getContents();
        if ($requestBody !== $encoded) {
            throw new RuntimeException('Request body mismatch');
        }
        $newBody = Utils::streamFor($input);
        $modifiedRequest = $request->withBody($newBody);
        if ($modifiedRequest->getBody()->getContents() !== $input) {
            throw new RuntimeException('withBody modification failed');
        }
        $withHeader = $request->withHeader('X-Custom', 'value');
        if ($withHeader->getHeaderLine('X-Custom') !== 'value') {
            throw new RuntimeException('Header manipulation failed');
        }
    }

    $statusCodes = [200, 400, 401, 403, 404, 500];
    foreach ($statusCodes as $code) {
        $resp = new Response($code, [], $input);
        if ($resp->getStatusCode() !== $code) {
            throw new RuntimeException('Status code mismatch');
        }
    }
    $signatureValue = 'keyId="ed25519:' . $input . '",algorithm="hs2019",headers="(request-target)"';
    $respWithSig = new Response(200, ['Signature' => $signatureValue], '{}');
    $sigHeader = $respWithSig->getHeaderLine('Signature');
    if (!str_contains($sigHeader, 'keyId=')) {
        throw new RuntimeException('Signature header missing keyId');
    }

    $contentTypes = [
        'application/json',
        'application/json; charset=utf-8',
        'application/activity+json',
        'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
    ];
    foreach ($contentTypes as $ct) {
        $r = new Response(200, ['Content-Type' => $ct], $input);
        $headerLine = $r->getHeaderLine('Content-Type');
        if (strlen($headerLine) === 0) {
            throw new RuntimeException('Content-Type header missing');
        }
    }

    $jsonBody = json_decode($input, true, 32);
    if (is_array($jsonBody)) {
        $contexts = [
            'fedi-e2ee:v1/api/actor/get-keys',
            'fedi-e2ee:v1/api/actor/aux-info',
            'fedi-e2ee:v1/api/actor/get-aux',
            'fedi-e2ee:v1/api/history',
            'fedi-e2ee:v1/api/info',
            'fedi-e2ee:v1/api/server-public-key',
        ];

        $result = true;
        if (array_key_exists('!pkd-context', $jsonBody) && is_string($jsonBody['!pkd-context'])) {
            foreach ($contexts as $expected) {
                // Constant-time comparison as in real code
                $result = $result && hash_equals($expected, $jsonBody['!pkd-context']);
            }
        }
        if (array_key_exists('public-keys', $jsonBody) && is_array($jsonBody['public-keys'])) {
            foreach ($jsonBody['public-keys'] as $row) {
                if (is_array($row) && array_key_exists('public-key', $row)) {
                    $meta = $row;
                    unset($meta['public-key']);
                }
            }
        }
        if (array_key_exists('inclusion-proof', $jsonBody) && is_array($jsonBody['inclusion-proof'])) {
            foreach ($jsonBody['inclusion-proof'] as $proofElement) {
                if (is_string($proofElement)) {
                    $result = $result && strlen($proofElement) > 0;
                }
            }
        }
    }
    assert($result, 'false');
    $safeInput = preg_replace('/[^a-zA-Z0-9._~-]/', '', substr($input, 0, 100)) ?: 'test';
    $request = new Request('GET', 'https://pkd.example.com/api/actor/' . urlencode($safeInput) . '/keys');
    $uri = $request->getUri();
    $path = $uri->getPath();
    if (strlen($path) === 0) {
        throw new RuntimeException('URI path is empty');
    }
    $largeBody = str_repeat($input, 10);
    if (strlen($largeBody) <= 10000) {
        $req = new Request('POST', 'https://pkd.example.com/inbox', [], $largeBody);
        $reqBody = $req->getBody()->getContents();
        if (strlen($reqBody) !== strlen($largeBody)) {
            throw new RuntimeException('Large body size mismatch');
        }
    }
    $emptyResp = new Response(200, [], '');
    $emptyBody = $emptyResp->getBody()->getContents();
    if ($emptyBody !== '') {
        throw new RuntimeException('Empty body should be empty string');
    }
    $binaryData = 'hpke:' . $input;
    $binaryReq = new Request('POST', 'https://pkd.example.com/inbox', [], $binaryData);
    $binaryBody = $binaryReq->getBody()->getContents();
    if ($binaryBody !== $binaryData) {
        throw new RuntimeException('Binary body mismatch');
    }
});
