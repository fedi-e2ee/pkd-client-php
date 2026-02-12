<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Values;

/**
 * Auxiliary data with its Merkle inclusion proof verification status.
 */
final readonly class VerifiedAuxData
{
    public function __construct(
        public AuxData $auxData,
        public string $merkleRoot,
        public int $leafIndex,
    ) {}
}
