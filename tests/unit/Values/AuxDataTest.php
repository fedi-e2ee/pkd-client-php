<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Values;

use FediE2EE\PKD\Values\AuxData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(AuxData::class)]
#[Group('unit')]
class AuxDataTest extends TestCase
{
    public function testConstructorSetsAllProperties(): void
    {
        $auxData = new AuxData(
            type: 'test-type',
            data: 'test-data',
            id: 'aux-123',
            actor: 'https://example.com/users/alice'
        );

        $this->assertSame('test-type', $auxData->type);
        $this->assertSame('test-data', $auxData->data);
        $this->assertSame('aux-123', $auxData->id);
        $this->assertSame('https://example.com/users/alice', $auxData->actor);
    }

    public function testReadonlyProperties(): void
    {
        $auxData = new AuxData(
            type: 'age-verification',
            data: '21+',
            id: 'aux-456',
            actor: 'https://mastodon.social/users/bob'
        );

        // Verify all properties are accessible
        $this->assertIsString($auxData->type);
        $this->assertIsString($auxData->data);
        $this->assertIsString($auxData->id);
        $this->assertIsString($auxData->actor);
    }

    public function testWithEmptyStrings(): void
    {
        $auxData = new AuxData(
            type: '',
            data: '',
            id: '',
            actor: ''
        );

        $this->assertSame('', $auxData->type);
        $this->assertSame('', $auxData->data);
        $this->assertSame('', $auxData->id);
        $this->assertSame('', $auxData->actor);
    }

    public function testWithSpecialCharacters(): void
    {
        $auxData = new AuxData(
            type: 'type-with-special-chars!@#$%',
            data: "data\nwith\nnewlines",
            id: 'id/with/slashes',
            actor: 'https://example.com/users/user%20name'
        );

        $this->assertSame('type-with-special-chars!@#$%', $auxData->type);
        $this->assertSame("data\nwith\nnewlines", $auxData->data);
        $this->assertSame('id/with/slashes', $auxData->id);
        $this->assertSame('https://example.com/users/user%20name', $auxData->actor);
    }
}
