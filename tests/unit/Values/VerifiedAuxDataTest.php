<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Values;

use FediE2EE\PKD\Values\AuxData;
use FediE2EE\PKD\Values\VerifiedAuxData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(VerifiedAuxData::class)]
#[CoversClass(AuxData::class)]
#[Group('unit')]
class VerifiedAuxDataTest extends TestCase
{
    public function testConstructorAndReadonlyProperties(): void
    {
        $auxData = new AuxData(
            type: 'test-type',
            data: 'test-data',
            id: 'aux-001',
            actor: 'https://example.com/users/alice'
        );
        $merkleRoot = 'pkd-mr-v1:test-root';
        $leafIndex = 7;

        $verified = new VerifiedAuxData(
            auxData: $auxData,
            merkleRoot: $merkleRoot,
            leafIndex: $leafIndex,
            verified: true
        );

        $this->assertSame($auxData, $verified->auxData);
        $this->assertSame($merkleRoot, $verified->merkleRoot);
        $this->assertSame($leafIndex, $verified->leafIndex);
        $this->assertTrue($verified->verified);
    }

    public function testUnverifiedState(): void
    {
        $auxData = new AuxData(
            type: 'test-type',
            data: 'test-data',
            id: 'aux-002',
            actor: 'https://example.com/users/bob'
        );

        $unverified = new VerifiedAuxData(
            auxData: $auxData,
            merkleRoot: 'pkd-mr-v1:test-root',
            leafIndex: 0,
            verified: false
        );

        $this->assertFalse($unverified->verified);
    }

    public function testAuxDataFieldsAccessible(): void
    {
        $auxData = new AuxData(
            type: 'my-type',
            data: 'my-data',
            id: 'aux-003',
            actor: 'https://example.com/users/charlie'
        );

        $verified = new VerifiedAuxData(
            auxData: $auxData,
            merkleRoot: 'pkd-mr-v1:root',
            leafIndex: 3,
            verified: true
        );

        $this->assertSame('my-type', $verified->auxData->type);
        $this->assertSame('my-data', $verified->auxData->data);
        $this->assertSame('aux-003', $verified->auxData->id);
        $this->assertSame(
            'https://example.com/users/charlie',
            $verified->auxData->actor
        );
    }
}
