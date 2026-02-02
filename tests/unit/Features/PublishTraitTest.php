<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Features\PublishTrait;
use FediE2EE\PKD\Values\ServerHPKE;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use ParagonIE\HPKE\AEAD\ChaCha20Poly1305;
use ParagonIE\HPKE\Hash;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KDF\HKDF;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use ParagonIE\HPKE\KEM\DiffieHellmanKEM;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\TestCase;
use ReflectionException;
use ReflectionMethod;
use SodiumException;

#[CoversNothing]
#[Group('unit')]
class PublishTraitTest extends TestCase
{
    use PublishTrait;

    private PublicKey $pk;
    private SecretKey $sk;

    /**
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function setUp(): void
    {
        $this->sk = SecretKey::generate();
        $this->pk = $this->sk->getPublicKey();
        $this->httpClient = null;
        $this->serverHPKE = null;
        $this->serverActorInbox = null;
        $this->recentMerkleRoot = null;
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeWithX25519Sha256ChachaPoly(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($publicKey);

        $result = $this->getInternalHpke('X25519_sha256_ChaChaPoly', $pk);

        $this->assertInstanceOf(ServerHPKE::class, $result);
        $this->assertInstanceOf(HPKE::class, $result->ciphersuite);
        $this->assertInstanceOf(EncapsKey::class, $result->encapsKey);
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeWithX25519Sha256Aes128GCM(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($publicKey);

        $result = $this->getInternalHpke('X25519_sha256_Aes128GCM', $pk);

        $this->assertInstanceOf(ServerHPKE::class, $result);
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeWithX25519Sha256Aes256GCM(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($publicKey);

        $result = $this->getInternalHpke('X25519_sha256_Aes256GCM', $pk);

        $this->assertInstanceOf(ServerHPKE::class, $result);
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeThrowsOnInvalidCurve(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($publicKey);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid curve: ed25519');
        $this->getInternalHpke('Ed25519_SHA256_ChaChaPoly', $pk);
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeThrowsOnInvalidAEAD(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded($publicKey);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid AEAD: InvalidAEAD');
        $this->getInternalHpke('X25519_SHA256_InvalidAEAD', $pk);
    }

    public function testWithRecentMerkleRoot(): void
    {
        $validRoot = 'pkd-mr-v1:abc123';
        $result = $this->withRecentMerkleRoot($validRoot);

        $this->assertSame($this, $result);
        $this->assertSame($validRoot, $this->recentMerkleRoot);
    }

    public function testWithRecentMerkleRootNull(): void
    {
        $this->recentMerkleRoot = 'pkd-mr-v1:existing';
        $result = $this->withRecentMerkleRoot(null);

        $this->assertSame($this, $result);
        $this->assertNull($this->recentMerkleRoot);
    }

    public function testWithRecentMerkleRootRejectsInvalidFormat(): void
    {
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage("Invalid Merkle root format: must start with 'pkd-mr-v1:'");

        $this->withRecentMerkleRoot('invalid-format');
    }

    public function testWithServerActorInbox(): void
    {
        $result = $this->withServerActorInbox('https://example.com/inbox');

        $this->assertSame($this, $result);
        $this->assertSame('https://example.com/inbox', $this->serverActorInbox);
    }

    /**
     * @throws HPKEException
     * @throws SodiumException
     */
    public function testWithServerHPKE(): void
    {
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $serverHpke = new ServerHPKE($hpke, $encapsKey);

        $result = $this->withServerHPKE($serverHpke);

        $this->assertSame($this, $result);
        $this->assertSame($serverHpke, $this->serverHPKE);
    }

    /**
     * @throws ClientException
     * @throws Exception
     * @throws JsonException
     */
    #[AllowMockObjectsWithoutExpectations]
    public function testEncryptBundleThrowsWhenHpkeNotSet(): void
    {
        $this->serverHPKE = null;

        // Create a mock bundle
        $bundle = $this->createMock(Bundle::class);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('HPKE config is not defined');
        $this->encryptBundle($bundle);
    }

    /**
     * @throws ReflectionException
     */
    public function testAssertSecretKeySetThrowsWhenNotSet(): void
    {
        // Create a test object with sk set to a non-SecretKey value
        $testObj = new class {
            use PublishTrait;
            public ?PublicKey $pk = null;
            /** @var mixed Intentionally not a SecretKey to test the validation */
            protected mixed $sk = null;
        };

        $method = new ReflectionMethod($testObj, 'assertSecretKeySet');

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The secret key must be set');
        $method->invoke($testObj);
    }

    public function testGetHandlerReturnsSameInstance(): void
    {
        $handler1 = $this->getHandler();
        $handler2 = $this->getHandler();

        $this->assertSame($handler1, $handler2);
    }
}
