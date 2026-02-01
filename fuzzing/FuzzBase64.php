<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PhpFuzzer\Config;
use RangeException;
use RuntimeException;
use SodiumException;
use TypeError;
use function bin2hex;
use function sodium_hex2bin;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$config->setTarget(function (string $input): void {
    // Test Base64UrlSafe::decodeNoPadding
    try {
        $decoded = Base64UrlSafe::decodeNoPadding($input);

        // Verify round-trip
        $reencoded = Base64UrlSafe::encodeUnpadded($decoded);
        $redecoded = Base64UrlSafe::decodeNoPadding($reencoded);

        if ($decoded !== $redecoded) {
            throw new RuntimeException('Round-trip mismatch');
        }
    } catch (RangeException|TypeError) {
        // Expected for invalid base64
    }

    // Test Base64UrlSafe::decode (with padding)
    try {
        $decoded = Base64UrlSafe::decode($input);
        $reencoded = Base64UrlSafe::encode($decoded);
        Base64UrlSafe::decode($reencoded);
    } catch (RangeException|TypeError) {
        // Expected for invalid base64
    }

    // Test standard Base64 operations
    try {
        $decoded = Base64::decode($input);
        Base64::encode($decoded);
    } catch (RangeException|TypeError) {
        // Expected for invalid base64
    }

    // Test encoding arbitrary binary data (should never fail)
    $encoded = Base64UrlSafe::encodeUnpadded($input);
    $decoded = Base64UrlSafe::decodeNoPadding($encoded);

    if ($input !== $decoded) {
        throw new RuntimeException('Encode/decode round-trip failed');
    }

    // Test with hex conversion (common pattern in codebase)
    try {
        $hex = bin2hex($input);
        $binary = sodium_hex2bin($hex);
        $base64 = Base64UrlSafe::encodeUnpadded($binary);
        Base64UrlSafe::decodeNoPadding($base64);
    } catch (SodiumException|RangeException|TypeError) {
        // Expected for edge cases
    }
});
