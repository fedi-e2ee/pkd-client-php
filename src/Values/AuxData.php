<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Values;

final readonly class AuxData
{
    public function __construct(
        public string $type,
        public string $data,
        public string $id,
        public string $actor,
    ) {}
}
