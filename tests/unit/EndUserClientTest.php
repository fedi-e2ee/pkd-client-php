<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\EndUserClient;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\Registry;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(EndUserClient::class)]
#[Group('unit')]
class EndUserClientTest extends TestCase
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

        $client = new EndUserClient('https://pkd.example.com', $pk);

        $this->assertInstanceOf(EndUserClient::class, $client);
    }

    public function testConstructorWithAllArguments(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $registry = new Registry();

        $client = new EndUserClient(
            'https://pkd.example.com',
            $pk,
            $registry,
            $sk,
            'alice@example.com'
        );

        $this->assertInstanceOf(EndUserClient::class, $client);
    }

    public function testConstructorWithNullRegistry(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        // Pass null explicitly for registry
        $client = new EndUserClient('https://pkd.example.com', $pk, null, $sk);

        $this->assertInstanceOf(EndUserClient::class, $client);
    }

    public function testBurnDownAlwaysThrows(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new EndUserClient('https://pkd.example.com', $pk);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('BurnDown is an instance-only action, and must not be generated client-side!');
        $client->burnDown();
    }

    public function testMethodsExist(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new EndUserClient('https://pkd.example.com', $pk);

        $this->assertTrue(method_exists($client, 'addKey'));
        $this->assertTrue(method_exists($client, 'addAuxData'));
        $this->assertTrue(method_exists($client, 'revokeKey'));
        $this->assertTrue(method_exists($client, 'revokeKeyThirdParty'));
        $this->assertTrue(method_exists($client, 'revokeAuxData'));
        $this->assertTrue(method_exists($client, 'moveIdentity'));
        $this->assertTrue(method_exists($client, 'burnDown'));
        $this->assertTrue(method_exists($client, 'fireproof'));
        $this->assertTrue(method_exists($client, 'undoFireproof'));
        $this->assertTrue(method_exists($client, 'fetchPublicKeys'));
        $this->assertTrue(method_exists($client, 'fetchAuxData'));
    }

    public function testSetHttpClient(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new EndUserClient('https://pkd.example.com', $pk);

        $mockClient = $this->createMockClient([]);
        $result = $client->setHttpClient($mockClient);

        $this->assertSame($client, $result);
    }

    public function testSecretKeyIsStoredWhenProvided(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new EndUserClient('https://pkd.example.com', $pk, null, $sk);

        // Use reflection to verify the secret key was stored
        $reflection = new \ReflectionClass($client);
        $skProperty = $reflection->getProperty('sk');

        $this->assertSame($sk, $skProperty->getValue($client));
    }

    public function testSecretKeyIsNullWhenNotProvided(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $client = new EndUserClient('https://pkd.example.com', $pk);

        // Use reflection to verify the secret key is null
        $reflection = new \ReflectionClass($client);
        $skProperty = $reflection->getProperty('sk');

        $this->assertNull($skProperty->getValue($client));
    }

    public function testActorIsStoredWhenProvided(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $actor = 'alice@example.com';

        $client = new EndUserClient('https://pkd.example.com', $pk, null, $sk, $actor);

        // Use reflection to verify the actor was stored
        $reflection = new \ReflectionClass($client);
        $actorProperty = $reflection->getProperty('actor');

        $this->assertSame($actor, $actorProperty->getValue($client));
    }
}
