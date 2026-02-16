<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\ReadOnlyClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(ReadOnlyClient::class)]
#[Group('unit')]
class ReadOnlyClientTest extends TestCase
{
    private function createMockClient(array $responses = []): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testConstructorWithMinimalArguments(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testConstructorWithRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $registry = new Registry();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk, $registry);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testConstructorWithNullRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk, null);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testMethodsExist(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        // Verified fetch methods (from VerifyTrait) - default/recommended
        $this->assertTrue(method_exists($client, 'fetchPublicKeys'));
        $this->assertTrue(method_exists($client, 'fetchAuxData'));
        // Unverified fetch methods (from FetchTrait) - use with caution
        $this->assertTrue(method_exists($client, 'fetchUnverifiedPublicKeys'));
        $this->assertTrue(method_exists($client, 'fetchUnverifiedAuxData'));
        $this->assertTrue(method_exists($client, 'fetchAuxDataByID'));
        $this->assertTrue(method_exists($client, 'setHttpClient'));
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testSetHttpClient(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        $mockClient = $this->createMockClient();
        $result = $client->setHttpClient($mockClient);

        $this->assertSame($client, $result);
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    public function testDoesNotHaveWriteMethods(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        // ReadOnlyClient should NOT have write methods
        $this->assertFalse(method_exists($client, 'addKey'));
        $this->assertFalse(method_exists($client, 'revokeKey'));
        $this->assertFalse(method_exists($client, 'burnDown'));
        $this->assertFalse(method_exists($client, 'fireproof'));
    }

    public static function merkleRootProvider(): array
    {
        return [
            ['blake2b', 32],
            ['sha256', 32],
            ['sha384', 48],
            ['sha512', 64],
        ];
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider("merkleRootProvider")]
    public function testDecodeMerkleRoot(string $hashFunc, int $zeroes): void
    {
        $sk = SecretKey::generate();
        $serverPk = $sk->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);
        $encoded = (new Tree([], $hashFunc))->getEncodedRoot();
        $out = $client->decodeMerkleRoot($encoded, $hashFunc);
        $this->assertSame($zeroes, strlen($out));
    }
}
