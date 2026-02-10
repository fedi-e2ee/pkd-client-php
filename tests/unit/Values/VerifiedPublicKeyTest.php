<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Values;

use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Values\VerifiedPublicKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(VerifiedPublicKey::class)]
#[Group('unit')]
class VerifiedPublicKeyTest extends TestCase
{
    /**
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testConstructorAndReadonlyProperties(): void
    {
        $pk = SecretKey::generate()->getPublicKey();
        $merkleRoot = 'pkd-mr-v1:test-root';
        $leafIndex = 42;

        $verified = new VerifiedPublicKey(
            publicKey: $pk,
            merkleRoot: $merkleRoot,
            leafIndex: $leafIndex,
            verified: true
        );

        $this->assertSame($pk, $verified->publicKey);
        $this->assertSame($merkleRoot, $verified->merkleRoot);
        $this->assertSame($leafIndex, $verified->leafIndex);
        $this->assertTrue($verified->verified);
    }

    /**
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testUnverifiedState(): void
    {
        $pk = SecretKey::generate()->getPublicKey();

        $unverified = new VerifiedPublicKey(
            publicKey: $pk,
            merkleRoot: 'pkd-mr-v1:test-root',
            leafIndex: 0,
            verified: false
        );

        $this->assertFalse($unverified->verified);
    }
}
