<?php
declare(strict_types=1);
namespace FediE2EE\PKD\IntegrationTests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\EndUserClient;
use FediE2EE\PKD\Extensions\ExtensionInterface;
use FediE2EE\PKD\Extensions\Registry;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Throwable;

#[CoversClass(EndUserClient::class)]
#[Group('integration')]
class EndUserClientTest extends TestCase
{
    private const MINI_FEDI_PORT = 65233;
    private const PKD_SERVER_PORT = 65234;

    private function isServerRunning(int $port): bool
    {
        $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 1);
        if ($fp) {
            fclose($fp);
            return true;
        }
        return false;
    }

    private function getMiniFediUrl(): string
    {
        return 'http://127.0.0.1:' . self::MINI_FEDI_PORT;
    }

    private function getPkdServerUrl(): string
    {
        return 'http://127.0.0.1:' . self::PKD_SERVER_PORT;
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    public function testClientCanBeConstructed(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();
        $client = new EndUserClient('https://pkd.example.com', $pk);

        $this->assertInstanceOf(EndUserClient::class, $client);
    }

    public function testFetchPublicKeysWithMockedResponses(): void
    {
        $serverKey = SecretKey::generate();
        $serverPk = $serverKey->getPublicKey();
        $actorKey = SecretKey::generate();
        $actorPk = $actorKey->getPublicKey();

        $hostname = '127.0.0.1:' . self::MINI_FEDI_PORT;
        $actor = 'testuser';
        $canonical = 'http://' . $hostname . '/users/' . $actor;

        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:' . $actor . '@' . $hostname,
            'links' => [['rel' => 'self', 'type' => 'application/activity+json', 'href' => $canonical]]
        ]));

        $keysResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/get-keys',
            'actor-id' => $canonical,
            'public-keys' => [['public-key' => $actorPk->toString(), 'key-id' => 'key-001', 'trusted' => true]]
        ]));

        $client = new EndUserClient('http://pkd.test', $serverPk);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $keys = $client->fetchPublicKeys($actor . '@' . $hostname);

        $this->assertCount(1, $keys);
        $this->assertSame($actorPk->toString(), $keys[0]->toString());
    }

    public function testFetchPublicKeysThrowsOnActorNotFound(): void
    {
        $serverKey = SecretKey::generate();
        $serverPk = $serverKey->getPublicKey();

        $hostname = '127.0.0.1:' . self::MINI_FEDI_PORT;
        $actor = 'nonexistent';
        $canonical = 'http://' . $hostname . '/users/' . $actor;

        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:' . $actor . '@' . $hostname,
            'links' => [['rel' => 'self', 'type' => 'application/activity+json', 'href' => $canonical]]
        ]));

        $notFoundResponse = new Response(404, [
            'Content-Type' => 'application/json'
        ], json_encode(['error' => 'Actor not found']));

        $client = new EndUserClient('http://pkd.test', $serverPk);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $notFoundResponse]));

        $this->expectException(Throwable::class);
        $client->fetchPublicKeys($actor . '@' . $hostname);
    }

    public function testFetchAuxDataWithMockedResponses(): void
    {
        $serverKey = SecretKey::generate();
        $serverPk = $serverKey->getPublicKey();

        $hostname = '127.0.0.1:' . self::MINI_FEDI_PORT;
        $actor = 'testuser';
        $canonical = 'http://' . $hostname . '/users/' . $actor;

        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:' . $actor . '@' . $hostname,
            'links' => [['rel' => 'self', 'type' => 'application/activity+json', 'href' => $canonical]]
        ]));

        $auxListResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/aux-info',
            'actor-id' => $canonical,
            'auxiliary' => [['aux-id' => 'aux-001', 'aux-type' => 'test-type']]
        ]));

        $auxDataResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/get-aux',
            'actor-id' => $canonical,
            'aux-id' => 'aux-001',
            'aux-type' => 'test-type',
            'aux-data' => 'test-data-value'
        ]));

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid test data'; }
            public function isValid(string $auxData): bool { return true; }
        };

        $registry = new Registry();
        $registry->addAuxDataType($testExtension);

        $client = new EndUserClient('http://pkd.test', $serverPk, $registry);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxListResponse, $auxDataResponse]));

        $auxData = $client->fetchAuxData($actor . '@' . $hostname, 'test-type');

        $this->assertCount(1, $auxData);
        $this->assertSame('test-data-value', $auxData[0]->data);
    }

    public function testFetchAuxDataReturnsEmptyForNoMatches(): void
    {
        $serverKey = SecretKey::generate();
        $serverPk = $serverKey->getPublicKey();

        $hostname = '127.0.0.1:' . self::MINI_FEDI_PORT;
        $actor = 'testuser';
        $canonical = 'http://' . $hostname . '/users/' . $actor;

        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:' . $actor . '@' . $hostname,
            'links' => [['rel' => 'self', 'type' => 'application/activity+json', 'href' => $canonical]]
        ]));

        $auxListResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/aux-info',
            'actor-id' => $canonical,
            'auxiliary' => [['aux-id' => 'aux-001', 'aux-type' => 'other-type']]
        ]));

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid test data'; }
            public function isValid(string $auxData): bool { return true; }
        };

        $registry = new Registry();
        $registry->addAuxDataType($testExtension);

        $client = new EndUserClient('http://pkd.test', $serverPk, $registry);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxListResponse]));

        $auxData = $client->fetchAuxData($actor . '@' . $hostname, 'test-type');

        $this->assertCount(0, $auxData);
    }

    public function testLiveMiniFediServerWebFinger(): void
    {
        if (!$this->isServerRunning(self::MINI_FEDI_PORT)) {
            $this->markTestSkipped('mini-fedi-server is not running');
        }

        $httpClient = new HttpClient();
        $response = $httpClient->get(
            $this->getMiniFediUrl() . '/.well-known/webfinger',
            ['query' => ['resource' => 'acct:test@127.0.0.1:' . self::MINI_FEDI_PORT], 'http_errors' => false]
        );

        $this->assertContains($response->getStatusCode(), [200, 404]);
    }

    public function testLivePkdServerPublicKey(): void
    {
        if (!$this->isServerRunning(self::PKD_SERVER_PORT)) {
            $this->markTestSkipped('pkd-server-php is not running');
        }

        $httpClient = new HttpClient();
        $response = $httpClient->get($this->getPkdServerUrl() . '/api/server-public-key');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode($response->getBody()->getContents(), true);
        $this->assertSame('fedi-e2ee:v1/api/server-public-key', $body['!pkd-context']);
    }

    public function testLivePkdServerHistory(): void
    {
        if (!$this->isServerRunning(self::PKD_SERVER_PORT)) {
            $this->markTestSkipped('pkd-server-php is not running');
        }

        $httpClient = new HttpClient();
        $response = $httpClient->get($this->getPkdServerUrl() . '/api/history');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode($response->getBody()->getContents(), true);
        $this->assertSame('fedi-e2ee:v1/api/history', $body['!pkd-context']);
    }

    public function testLivePkdServerExtensions(): void
    {
        if (!$this->isServerRunning(self::PKD_SERVER_PORT)) {
            $this->markTestSkipped('pkd-server-php is not running');
        }

        $httpClient = new HttpClient();
        $response = $httpClient->get($this->getPkdServerUrl() . '/api/extensions');

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode($response->getBody()->getContents(), true);
        $this->assertSame('fedi-e2ee:v1/api/extensions', $body['!pkd-context']);
    }
}
