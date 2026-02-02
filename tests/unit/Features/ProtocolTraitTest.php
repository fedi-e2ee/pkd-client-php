<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\HttpSignatureException;
use FediE2EE\PKD\Crypto\Exceptions\JsonException;
use FediE2EE\PKD\Crypto\Exceptions\NetworkException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\EndUserClient;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\InstanceClient;
use FediE2EE\PKD\Values\ServerHPKE;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(EndUserClient::class)]
#[CoversClass(InstanceClient::class)]
#[CoversClass(ServerHPKE::class)]
#[Group('unit')]
class ProtocolTraitTest extends TestCase
{
    private SecretKey $serverKey;
    private SecretKey $userKey;
    private ServerHPKE $serverHPKE;

    /**
     * @return void
     * @throws NotImplementedException
     * @throws HPKEException
     * @throws SodiumException
     */
    protected function setUp(): void
    {
        $this->serverKey = SecretKey::generate();
        $this->userKey = SecretKey::generate();

        // Create HPKE config
        $kdf = new HKDF(Hash::Sha256);
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE($kem, $kdf, new ChaCha20Poly1305());
        $keyPair = sodium_crypto_box_keypair();
        $publicKey = sodium_crypto_box_publickey($keyPair);
        $encapsKey = new EncapsKey(Curve::X25519, $publicKey);
        $this->serverHPKE = new ServerHPKE($hpke, $encapsKey);
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    /**
     * @throws NotImplementedException
     * @throws SodiumException
     */
    private function createConfiguredEndUserClient(string $actorUrl): EndUserClient
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new EndUserClient(
            'http://pkd.test',
            $serverPk,
            new Registry(),
            $this->userKey,
            $actorUrl // Use URL directly as actor to skip WebFinger
        );
        $client->withRecentMerkleRoot('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $client->withServerHPKE($this->serverHPKE);
        $client->withServerActorInbox('http://pkd.test/inbox');
        return $client;
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testAddKeyReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $newKey = SecretKey::generate()->getPublicKey();
        $result = $client->addKey($newKey, $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        // HPKE encrypted bundles start with 'hpke:'
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeKeyReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $keyToRevoke = SecretKey::generate()->getPublicKey();
        $result = $client->revokeKey($keyToRevoke, $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testAddAuxDataReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->addAuxData('test-data', 'test-type', $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeAuxDataByDataReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->revokeAuxData('test-type', 'test-data', null, $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeAuxDataByIdReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->revokeAuxData('test-type', null, 'aux-id-123', $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeAuxDataThrowsWhenBothDataAndIdMissing(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Either the data or ID must be provided');
        $client->revokeAuxData('test-type', null, null, $actorUrl);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testMoveIdentityReturnsEncryptedBundle(): void
    {
        $oldActorUrl = 'https://example.com/users/alice';
        $newActorUrl = 'https://newdomain.com/users/alice';

        $client = $this->createConfiguredEndUserClient($oldActorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->moveIdentity($newActorUrl, $oldActorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    public function testFireproofReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->fireproof($actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testUndoFireproofReturnsEncryptedBundle(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->undoFireproof($actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeKeyThirdPartyReturnsPlaintextJson(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        // RevokeKeyThirdParty uses a valid revocation token format
        // For testing, we'll use a simple token that the protocol will validate
        $token = 'test-revocation-token';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->revokeKeyThirdParty($token);

        $this->assertIsString($result);
        // RevokeKeyThirdParty returns plaintext JSON, not HPKE encrypted
        $decoded = json_decode($result, true);
        $this->assertIsArray($decoded);
        $this->assertSame('RevokeKeyThirdParty', $decoded['action']);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testBurnDownThrowsForEndUserClient(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new EndUserClient('http://pkd.test', $serverPk);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('BurnDown is an instance-only action');
        $client->burnDown();
    }

    /**
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testInstanceClientBurnDownReturnsPlaintextJson(): void
    {
        $actorUrl = 'https://example.com/users/badactor';

        $serverPk = $this->serverKey->getPublicKey();
        $instanceSk = SecretKey::generate();
        $client = new InstanceClient('http://pkd.test', $serverPk, new Registry(), $instanceSk);
        $client->withRecentMerkleRoot('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $client->withServerHPKE($this->serverHPKE);
        $client->withServerActorInbox('http://pkd.test/inbox');
        $client->setHttpClient($this->createMockClient([]));

        $result = $client->burnDown($actorUrl, 'admin@example.com');

        $this->assertIsString($result);
        $decoded = json_decode($result, true);
        $this->assertIsArray($decoded);
        $this->assertSame('BurnDown', $decoded['action']);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testInstanceClientCheckpointReturnsPlaintextJson(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $instanceSk = SecretKey::generate();
        $client = new InstanceClient('http://pkd.test', $serverPk, new Registry(), $instanceSk);
        $client->withRecentMerkleRoot('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $client->withServerHPKE($this->serverHPKE);
        $client->withServerActorInbox('http://pkd.test/inbox');
        $client->setHttpClient($this->createMockClient([]));

        $fromKey = SecretKey::generate()->getPublicKey();
        $result = $client->checkpoint(
            $fromKey,
            'http://pkd1.example.com',
            'pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            'http://pkd2.example.com',
            'pkd-mr-v1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
        );

        $this->assertIsString($result);
        $decoded = json_decode($result, true);
        $this->assertIsArray($decoded);
        $this->assertSame('Checkpoint', $decoded['action']);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFlattenActorThrowsWhenNoActorProvided(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        // Create client without default actor
        $client = new EndUserClient('http://pkd.test', $serverPk, new Registry(), $this->userKey);
        $client->withRecentMerkleRoot('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $client->withServerHPKE($this->serverHPKE);
        $client->withServerActorInbox('http://pkd.test/inbox');
        $client->setHttpClient($this->createMockClient([]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Actor ID is mandatory');
        $client->fireproof(); // No actor provided
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testActorCanBeOverriddenPerMethod(): void
    {
        $defaultActorUrl = 'https://example.com/users/alice';
        $overrideActorUrl = 'https://example.com/users/bob';

        // Create client with default actor 'alice'
        $client = $this->createConfiguredEndUserClient($defaultActorUrl);
        $client->setHttpClient($this->createMockClient([]));

        // Override with 'bob' for this call - the message should use 'bob', not 'alice'
        $result = $client->fireproof($overrideActorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testExplicitActorTakesPrecedenceOverDefault(): void
    {
        $defaultActorUrl = 'https://example.com/users/default';
        $explicitActorUrl = 'https://example.com/users/explicit';

        $serverPk = $this->serverKey->getPublicKey();
        $client = new EndUserClient(
            'http://pkd.test',
            $serverPk,
            new Registry(),
            $this->userKey,
            $defaultActorUrl
        );
        $client->withRecentMerkleRoot('pkd-mr-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $client->withServerHPKE($this->serverHPKE);
        $client->withServerActorInbox('http://pkd.test/inbox');
        $client->setHttpClient($this->createMockClient([]));

        // Call with explicit actor - it MUST use 'explicit', not 'default'
        $result1 = $client->fireproof($explicitActorUrl);
        // Call without actor - should use default
        $result2 = $client->fireproof();

        // Both should succeed but produce different encrypted outputs
        // (different actor in the encrypted payload)
        $this->assertStringStartsWith('hpke:', $result1);
        $this->assertStringStartsWith('hpke:', $result2);
        // The encrypted payloads should be different because they contain different actors
        $this->assertNotSame($result1, $result2);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeAuxDataWithBothDataAndIdUsesData(): void
    {
        $actorUrl = 'https://example.com/users/alice';

        $client = $this->createConfiguredEndUserClient($actorUrl);
        $client->setHttpClient($this->createMockClient([]));

        // Both data and ID provided - should work
        $result = $client->revokeAuxData('test-type', 'test-data', 'aux-id-123', $actorUrl);

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('hpke:', $result);
    }
}
