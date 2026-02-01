<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use PhpFuzzer\Config;
use RuntimeException;
use function parse_url;
use function rawurldecode;
use function rawurlencode;
use function str_contains;
use function urldecode;
use function urlencode;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    $encoded = urlencode($input);
    $decoded = urldecode($encoded);

    if ($decoded !== $input) {
        throw new RuntimeException('urlencode/urldecode round-trip failed');
    }

    $rawEncoded = rawurlencode($input);
    $rawDecoded = rawurldecode($rawEncoded);

    if ($rawDecoded !== $input) {
        throw new RuntimeException('rawurlencode/rawurldecode round-trip failed');
    }

    $baseUrl = 'https://pkd.example.com';
    $paths = [
        '/api/actor/' . urlencode($input) . '/keys',
        '/api/actor/' . urlencode($input) . '/auxiliary',
        '/api/actor/' . urlencode($input) . '/auxiliary/' . urlencode($input),
    ];

    foreach ($paths as $path) {
        $fullUrl = $baseUrl . $path;

        // Verify URL is parseable
        $parsed = parse_url($fullUrl);
        if ($parsed === false) {
            throw new RuntimeException('Failed to parse constructed URL');
        }

        // URL should not contain unencoded special characters in the path
        if (isset($parsed['path'])) {
            // Path should be decodable
            urldecode($parsed['path']);
        }
    }

    if (str_contains($input, '@')) {
        $parts = explode('@', $input);
        foreach ($parts as $part) {
            if ($part !== '') {
                urlencode($part);
            }
        }
    }

    $inputParsed = parse_url($input);
    if ($inputParsed !== false && isset($inputParsed['host'])) {
        $encodedUrl = urlencode($input);
        $decodedUrl = urldecode($encodedUrl);
        if ($decodedUrl !== $input) {
            throw new RuntimeException('URL encoding round-trip failed');
        }
    }
});
