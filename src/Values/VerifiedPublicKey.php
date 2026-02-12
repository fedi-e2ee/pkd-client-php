<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Values;

use FediE2EE\PKD\Crypto\PublicKey;

/**
 * A public key with its Merkle inclusion proof verification status.
 */
final readonly class VerifiedPublicKey
{
    public function __construct(
        public PublicKey $publicKey,
        public string $merkleRoot,
        public int $leafIndex,
    ) {}
}
