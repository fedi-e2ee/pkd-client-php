<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\ReadOnlyClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(ReadOnlyClient::class)]
#[Group('unit')]
class ReadOnlyClientTest extends TestCase
{
    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    public function testConstructorWithMinimalArguments(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

    public function testConstructorWithRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $registry = new Registry();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk, $registry);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

    public function testConstructorWithNullRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new ReadOnlyClient('https://pkd.example.com', $pk, null);

        $this->assertInstanceOf(ReadOnlyClient::class, $client);
    }

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

    public function testSetHttpClient(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new ReadOnlyClient('https://pkd.example.com', $pk);

        $mockClient = $this->createMockClient([]);
        $result = $client->setHttpClient($mockClient);

        $this->assertSame($client, $result);
    }

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
}
