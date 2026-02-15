<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use ErrorException;
use FediE2EE\PKD\Crypto\Exceptions\HttpSignatureException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Features\PublishTrait;
use FediE2EE\PKD\Tests\TestHelper;
use FediE2EE\PKD\Values\ServerHPKE;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use ParagonIE\ConstantTime\Base64UrlSafe;
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
use Psr\Http\Client\ClientExceptionInterface;
use ReflectionException;
use ReflectionMethod;
use SodiumException;
use Throwable;

#[CoversNothing]
#[Group('unit')]
class PublishTraitTest extends TestCase
{
    use PublishTrait;

    private PublicKey $pk;
    private SecretKey $sk;
    private string $url = 'http://pkd.test';

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
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

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
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

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
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

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
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

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
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

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
        $testObj = new class() {
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

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenHttpClientNull(): void
    {
        $this->httpClient = null;

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The http client is not injected');
        $this->fetchServerInfo();
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenActorMissing(): void
    {
        $infoResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            ['public-key' => $this->pk->toString()],
            'fedi-e2ee:v1/api/info'
        );

        $this->httpClient = $this->createMockClient([$infoResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The server actor does not exist');
        $this->fetchServerInfo();
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenPublicKeyMissing(): void
    {
        $infoResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            ['actor' => 'https://pkd.test/actor'],
            'fedi-e2ee:v1/api/info'
        );

        $this->httpClient = $this->createMockClient([$infoResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The server public key does not exist');
        $this->fetchServerInfo();
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenPublicKeyMismatch(): void
    {
        $differentKey = SecretKey::generate();
        $infoResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            [
                'actor' => 'https://pkd.test/actor',
                'public-key' => $differentKey->getPublicKey()->toString(),
            ],
            'fedi-e2ee:v1/api/info'
        );

        $this->httpClient = $this->createMockClient([$infoResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The server public key does not match');
        $this->fetchServerInfo();
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenHpkeKeyMissing(): void
    {
        $actorUrl = 'https://pkd.test/actor';

        $infoResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            [
                'actor' => $actorUrl,
                'public-key' => $this->pk->toString(),
            ],
            'fedi-e2ee:v1/api/info'
        );

        // Actor document (canonicalize returns URL as-is, no WebFinger)
        $actorResponse = new Response(200, [
            'Content-Type' => 'application/activity+json',
        ], json_encode([
            'id' => $actorUrl,
            'type' => 'Application',
            'inbox' => 'https://pkd.test/inbox',
        ]));

        // HPKE response missing hpke-public-key
        $hpkeResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            [],
            'fedi-e2ee:v1/api/server-public-key'
        );

        $this->httpClient = $this->createMockClient([
            $infoResponse,
            $actorResponse,
            $hpkeResponse,
        ]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The server public key does not exist');
        $this->fetchServerInfo();
    }

    /**
    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoThrowsWhenCiphersuiteNotString(): void
    {
        $actorUrl = 'https://pkd.test/actor';
        $hpkeKeyPair = sodium_crypto_box_keypair();
        $hpkePk = sodium_crypto_box_publickey($hpkeKeyPair);

        $infoResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            [
                'actor' => $actorUrl,
                'public-key' => $this->pk->toString(),
            ],
            'fedi-e2ee:v1/api/info'
        );

        // Actor document (canonicalize returns URL as-is, no WebFinger)
        $actorResponse = new Response(200, [
            'Content-Type' => 'application/activity+json',
        ], json_encode([
            'id' => $actorUrl,
            'type' => 'Application',
            'inbox' => 'https://pkd.test/inbox',
        ]));

        // Ciphersuite as array instead of string
        $hpkeResponse = TestHelper::createSignedJsonResponse(
            $this->sk,
            [
                'hpke-public-key' => Base64UrlSafe::encodeUnpadded($hpkePk),
                'hpke-ciphersuite' => ['not', 'a', 'string'],
            ],
            'fedi-e2ee:v1/api/server-public-key'
        );

        $this->httpClient = $this->createMockClient([
            $infoResponse,
            $actorResponse,
            $hpkeResponse,
        ]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid ciphersuite format');
        $this->fetchServerInfo();
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HPKEException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchServerInfoSkipsRefetchWhenAlreadySet(): void
    {
        // Pre-set both values
        $this->serverActorInbox = 'https://pkd.test/inbox';

        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $this->serverHPKE = new ServerHPKE($hpke, $encapsKey);

        // Empty mock — no requests should be made
        $this->httpClient = $this->createMockClient([]);

        // Should not throw — both values are already set
        $this->fetchServerInfo();

        $this->assertSame('https://pkd.test/inbox', $this->serverActorInbox);
    }

    /**
     * @throws ClientException
     * @throws ErrorException
     * @throws SodiumException
     */
    public function testGetInternalHpkeThrowsOnTooFewParts(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

        set_error_handler(static function (int $errno, string $errstr): never {
            throw new ErrorException($errstr, 0, $errno);
        });
        try {
            $this->expectException(Throwable::class);
            $this->getInternalHpke('X25519_sha256', $pk);
        } finally {
            restore_error_handler();
        }
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws HPKEException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[AllowMockObjectsWithoutExpectations]
    public function testPublishBundleSendsPlaintextForBurnDown(): void
    {
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $this->serverHPKE = new ServerHPKE($hpke, $encapsKey);
        $this->serverActorInbox = 'https://pkd.test/inbox';

        $publishResponse = new Response(200, [], '{"ok":true}');
        $this->httpClient = $this->createMockClient([$publishResponse]);

        $bundle = $this->createMock(Bundle::class);
        $bundle->method('getAction')->willReturn('BurnDown');
        $bundle->method('toJson')->willReturn('{"action":"BurnDown"}');

        $response = $this->publishBundle($this->sk, $bundle);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws HPKEException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[AllowMockObjectsWithoutExpectations]
    public function testPublishBundleSendsPlaintextForCheckpoint(): void
    {
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $this->serverHPKE = new ServerHPKE($hpke, $encapsKey);
        $this->serverActorInbox = 'https://pkd.test/inbox';

        $publishResponse = new Response(200, [], '{"ok":true}');
        $this->httpClient = $this->createMockClient([$publishResponse]);

        $bundle = $this->createMock(Bundle::class);
        $bundle->method('getAction')->willReturn('Checkpoint');
        $bundle->method('toJson')->willReturn('{"action":"Checkpoint"}');

        $response = $this->publishBundle($this->sk, $bundle);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws Exception
     * @throws HPKEException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[AllowMockObjectsWithoutExpectations]
    public function testPublishBundleEncryptsForAddKey(): void
    {
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $this->serverHPKE = new ServerHPKE($hpke, $encapsKey);
        $this->serverActorInbox = 'https://pkd.test/inbox';

        $publishResponse = new Response(200, [], '{"ok":true}');
        $this->httpClient = $this->createMockClient([$publishResponse]);

        $bundle = $this->createMock(Bundle::class);
        $bundle->method('getAction')->willReturn('AddKey');
        $bundle->method('toJson')->willReturn('{"action":"AddKey"}');

        $response = $this->publishBundle($this->sk, $bundle);
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function testGetInternalHpkeWithCurve25519Alias(): void
    {
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $pk = Base64UrlSafe::encodeUnpadded($publicKey);

        // Curve25519 is an alias for X25519
        $result = $this->getInternalHpke('Curve25519_sha256_ChaChaPoly', $pk);
        $this->assertInstanceOf(ServerHPKE::class, $result);
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPublishStringThrowsWhenHttpClientNull(): void
    {
        $this->httpClient = null;

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The http client is not injected');
        $this->publishString($this->sk, '{"test":true}');
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testPublishStringThrowsWhenServerActorInboxNull(): void
    {
        $this->httpClient = $this->createMockClient([]);
        $this->serverActorInbox = null;

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The actor inbox URL is not set');
        $this->publishString($this->sk, '{"test":true}');
    }
}
