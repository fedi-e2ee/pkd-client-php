<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Values;

use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\Interfaces\EncapsKeyInterface;

readonly class ServerHPKE
{
    public function __construct(
        public HPKE $ciphersuite,
        public EncapsKeyInterface $encapsKey,
    ) {}
}
