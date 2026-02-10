<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\ReadOnlyClient;
use PhpFuzzer\Config;
use ReflectionMethod;
use RuntimeException;
use function is_array, is_bool, is_int, json_decode;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$serverKey = SecretKey::generate();
$serverPk = $serverKey->getPublicKey();
$client = new ReadOnlyClient('http://pkd.test', $serverPk);

// Access protected methods via reflection
$hasRequiredProofFields = new ReflectionMethod($client, 'hasRequiredProofFields');
$hasRequiredAuxDataProofFields = new ReflectionMethod(
    $client,
    'hasRequiredAuxDataProofFields'
);
$parseInclusionProof = new ReflectionMethod($client, 'parseInclusionProof');

$config->setTarget(
    function (string $input) use (
        $client,
        $hasRequiredProofFields,
        $hasRequiredAuxDataProofFields,
        $parseInclusionProof
    ): void {
        $decoded = json_decode($input, true, 16);
        if (!is_array($decoded)) {
            return;
        }

        // Test hasRequiredProofFields — must never throw
        try {
            $result = $hasRequiredProofFields->invoke($client, $decoded);
            if (!is_bool($result)) {
                throw new RuntimeException(
                    'hasRequiredProofFields returned non-bool'
                );
            }
        } catch (\TypeError) {
            // Acceptable for extreme input
        }

        // Test hasRequiredAuxDataProofFields — must never throw
        try {
            $result = $hasRequiredAuxDataProofFields->invoke(
                $client,
                $decoded
            );
            if (!is_bool($result)) {
                throw new RuntimeException(
                    'hasRequiredAuxDataProofFields returned non-bool'
                );
            }
        } catch (\TypeError) {
            // Acceptable for extreme input
        }

        // If hasRequiredProofFields passes, parseInclusionProof must work
        try {
            $valid = $hasRequiredProofFields->invoke($client, $decoded);
            if ($valid) {
                $proof = $parseInclusionProof->invoke($client, $decoded);
                if (!is_int($proof->index)) {
                    throw new RuntimeException(
                        'parseInclusionProof returned non-int index'
                    );
                }
                if (!is_array($proof->proof)) {
                    throw new RuntimeException(
                        'parseInclusionProof returned non-array proof'
                    );
                }
            }
        } catch (\TypeError | \RangeException) {
            // Base64 decoding can throw on malformed strings
        }
    }
);
