<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Fuzzing;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Features\PublishTrait;
use PhpFuzzer\Config;
use Throwable;
use function explode, strlen;

/** @var Config $config */

require_once dirname(__DIR__) . '/vendor/autoload.php';

/**
 * Minimal harness that exposes the real PublishTrait HPKE parsing.
 *
 * @internal
 */
$harness = new class {
    use PublishTrait;

    public PublicKey $pk;

    public function __construct()
    {
        $this->pk = PublicKey::fromString(
            'ed25519:' . str_repeat('A', 43)
        );
    }

    /**
     * Expose the protected method for fuzzing.
     */
    public function fuzzGetInternalHpke(string $ciphersuite, string $pk): void
    {
        $this->getInternalHpke($ciphersuite, $pk);
    }
};

$config->setTarget(function (string $input) use ($harness): void {
    $parts = explode('|', $input, 2);
    $ciphersuite = $parts[0];
    $pk = $parts[1] ?? '';

    // Only exercise inputs that look like valid ciphersuite format
    $cipherParts = explode('_', $ciphersuite);
    if (count($cipherParts) !== 3) {
        return;
    }
    if (strlen($pk) === 0) {
        return;
    }

    try {
        $harness->fuzzGetInternalHpke($ciphersuite, $pk);
    } catch (Throwable) {
        // Expected for invalid ciphersuites, curves, keys, etc.
    }
});
