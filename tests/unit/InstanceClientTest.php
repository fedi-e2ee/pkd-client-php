<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\InstanceClient;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(InstanceClient::class)]
#[Group('unit')]
class InstanceClientTest extends TestCase
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

        $client = new InstanceClient('https://pkd.example.com', $pk);

        $this->assertInstanceOf(InstanceClient::class, $client);
    }

    public function testConstructorWithAllArguments(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $registry = new Registry();

        $client = new InstanceClient(
            'https://pkd.example.com',
            $pk,
            $registry,
            $sk
        );

        $this->assertInstanceOf(InstanceClient::class, $client);
    }

    public function testConstructorWithNullRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new InstanceClient('https://pkd.example.com', $pk, null, $sk);

        $this->assertInstanceOf(InstanceClient::class, $client);
    }

    public function testMethodsExist(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new InstanceClient('https://pkd.example.com', $pk);

        $this->assertTrue(method_exists($client, 'publish'));
        $this->assertTrue(method_exists($client, 'burnDown'));
        $this->assertTrue(method_exists($client, 'checkpoint'));
        $this->assertTrue(method_exists($client, 'fetchPublicKeys'));
        $this->assertTrue(method_exists($client, 'fetchAuxData'));
    }

    public function testSetHttpClient(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new InstanceClient('https://pkd.example.com', $pk);

        $mockClient = $this->createMockClient([]);
        $result = $client->setHttpClient($mockClient);

        $this->assertSame($client, $result);
    }

    public function testSecretKeyIsStoredWhenProvided(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new InstanceClient('https://pkd.example.com', $pk, null, $sk);

        // Use reflection to verify the secret key was stored
        $reflection = new \ReflectionClass($client);
        $skProperty = $reflection->getProperty('sk');

        $this->assertSame($sk, $skProperty->getValue($client));
    }

    public function testSecretKeyIsNullWhenNotProvided(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new InstanceClient('https://pkd.example.com', $pk);

        // Use reflection to verify the secret key is null
        $reflection = new \ReflectionClass($client);
        $skProperty = $reflection->getProperty('sk');

        $this->assertNull($skProperty->getValue($client));
    }
}
