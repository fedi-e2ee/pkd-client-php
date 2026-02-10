<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Features\APTrait;
use GuzzleHttp\Psr7\Response;
use PhpFuzzer\Config;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

/**
 * Minimal harness that exposes the real APTrait parsing methods.
 *
 * @internal
 */
$harness = new class {
    use APTrait;

    public PublicKey $pk;

    public function __construct()
    {
        // Dummy key; never used for signing verification in this target.
        $this->pk = PublicKey::fromString(
            'ed25519:' . str_repeat('A', 43)
        );
    }
};

$contexts = [
    'fedi-e2ee:v1/api/actor/get-keys',
    'fedi-e2ee:v1/api/actor/aux-info',
    'fedi-e2ee:v1/api/actor/get-aux',
    'fedi-e2ee:v1/api/history',
    'fedi-e2ee:v1/api/info',
    'fedi-e2ee:v1/api/server-public-key',
];

$config->setTarget(function (string $input) use ($harness, $contexts): void {
    $response = new Response(200, ['Content-Type' => 'application/json'], $input);

    // Exercise parseJsonResponse without context check
    try {
        $parsed = $harness->parseJsonResponse($response);
        // Exercise assertKeysExist on the parsed body
        $harness->assertKeysExist($parsed, ['actor-id', 'public-keys']);
    } catch (ClientException) {
        // Expected for invalid JSON
    }

    // Exercise parseJsonResponse with each known context
    foreach ($contexts as $context) {
        $response = new Response(
            200,
            ['Content-Type' => 'application/json'],
            $input
        );
        try {
            $harness->parseJsonResponse($response, $context);
        } catch (ClientException) {
            // Expected for invalid JSON or wrong context
        }
    }
});
