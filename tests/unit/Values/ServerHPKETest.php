<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Values;

use FediE2EE\PKD\Values\ServerHPKE;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use function random_bytes;

#[CoversClass(ServerHPKE::class)]
#[Group('unit')]
class ServerHPKETest extends TestCase
{
    private function createHpke(): HPKE
    {
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        return new HPKE($kem, $kdf, new ChaCha20Poly1305());
    }

    private function createEncapsKey(): EncapsKey
    {
        // Generate a valid X25519 public key (32 bytes)
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        return new EncapsKey(Curve::X25519, $publicKey);
    }

    public function testConstructorSetsProperties(): void
    {
        $hpke = $this->createHpke();
        $encapsKey = $this->createEncapsKey();

        $serverHpke = new ServerHPKE($hpke, $encapsKey);

        $this->assertSame($hpke, $serverHpke->ciphersuite);
        $this->assertSame($encapsKey, $serverHpke->encapsKey);
    }

    public function testReadonlyProperties(): void
    {
        $hpke = $this->createHpke();
        $encapsKey = $this->createEncapsKey();

        $serverHpke = new ServerHPKE($hpke, $encapsKey);

        $this->assertInstanceOf(HPKE::class, $serverHpke->ciphersuite);
        $this->assertInstanceOf(EncapsKey::class, $serverHpke->encapsKey);
    }
}
