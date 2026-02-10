<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use PhpFuzzer\Config;
use RuntimeException;
use Throwable;
use function get_class, str_contains, str_starts_with;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$serverKey = SecretKey::generate();
$serverPk = $serverKey->getPublicKey();
$client = new ReadOnlyClient('http://pkd.test', $serverPk);

$config->setTarget(function (string $input) use ($client): void {
    $dummyProof = new InclusionProof(0, []);

    try {
        $client->verifyInclusionProof('sha256', $input, 'leaf', $dummyProof, 1);
    } catch (ClientException $e) {
        $msg = $e->getMessage();
        if (
            str_contains($msg, 'missing prefix')
            || str_contains($msg, 'expected 32+ bytes')
        ) {
            return;
        }
        return;
    } catch (Throwable $e) {
        // Unexpected exceptions are bugs
        throw new RuntimeException(
            'Unexpected exception in decodeMerkleRoot: '
            . get_class($e) . ': ' . $e->getMessage()
        );
    }

    // If we got here, decoding succeeded — verify invariants
    $prefix = 'pkd-mr-v1:';
    if (!str_starts_with($input, $prefix)) {
        throw new RuntimeException(
            'decodeMerkleRoot accepted input without prefix'
        );
    }
});
