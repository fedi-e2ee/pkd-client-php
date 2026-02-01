<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Features\APTrait;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
#[Group('unit')]
class APTraitTest extends TestCase
{
    use APTrait;

    private PublicKey $pk;

    protected function setUp(): void
    {
        $this->pk = SecretKey::generate()->getPublicKey();
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    public function testParseJsonResponseWithValidJson(): void
    {
        $body = json_encode(['key' => 'value', 'number' => 42]);
        $response = new Response(200, ['Content-Type' => 'application/json'], $body);

        $result = $this->parseJsonResponse($response);

        $this->assertSame(['key' => 'value', 'number' => 42], $result);
    }

    public function testParseJsonResponseWithPkdContext(): void
    {
        $body = json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/test',
            'data' => 'test'
        ]);
        $response = new Response(200, ['Content-Type' => 'application/json'], $body);

        $result = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/test');

        $this->assertSame('test', $result['data']);
    }

    public function testParseJsonResponseThrowsOnEmptyBody(): void
    {
        $response = new Response(200, ['Content-Type' => 'application/json'], '');

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Empty JSON response.');
        $this->parseJsonResponse($response);
    }

    public function testParseJsonResponseThrowsOnInvalidJson(): void
    {
        $response = new Response(200, ['Content-Type' => 'application/json'], 'not valid json');

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid JSON response');
        $this->parseJsonResponse($response);
    }

    public function testParseJsonResponseThrowsOnWrongContext(): void
    {
        $body = json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/wrong',
            'data' => 'test'
        ]);
        $response = new Response(200, ['Content-Type' => 'application/json'], $body);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid PKD context for response.');
        $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/expected');
    }

    public function testAssertKeysExistWithAllKeysPresent(): void
    {
        $body = ['key1' => 'value1', 'key2' => 'value2', 'key3' => 'value3'];

        // Should not throw
        $this->assertKeysExist($body, ['key1', 'key2']);
        $this->assertTrue(true);
    }

    public function testAssertKeysExistThrowsOnMissingKey(): void
    {
        $body = ['key1' => 'value1'];

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Key is not set in body: missing-key');
        $this->assertKeysExist($body, ['key1', 'missing-key']);
    }

    public function testAssertKeysExistWithEmptyKeys(): void
    {
        $body = ['key1' => 'value1'];

        // Should not throw with empty required keys
        $this->assertKeysExist($body, []);
        $this->assertTrue(true);
    }

    public function testSetHttpClient(): void
    {
        $mockClient = $this->createMockClient([]);

        $result = $this->setHttpClient($mockClient);

        $this->assertSame($mockClient, $this->httpClient);
        $this->assertSame($this, $result);
    }

    public function testEnsureHttpClientConfigured(): void
    {
        $this->httpClient = null;
        $this->ensureHttpClientConfigured();

        $this->assertInstanceOf(HttpClient::class, $this->httpClient);
    }

    public function testEnsureHttpClientConfiguredDoesNotOverwrite(): void
    {
        $mockClient = $this->createMockClient([]);
        $this->httpClient = $mockClient;

        $this->ensureHttpClientConfigured();

        $this->assertSame($mockClient, $this->httpClient);
    }

    public function testGetInboxUrlThrowsWhenHttpClientNotSet(): void
    {
        $this->httpClient = null;

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('The http client is not injected');
        $this->getInboxUrl('test@example.com');
    }

    public function testGetInboxUrlThrowsWhenInboxMissing(): void
    {
        // WebFinger response
        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:test@example.com',
            'links' => [[
                'rel' => 'self',
                'type' => 'application/activity+json',
                'href' => 'https://example.com/users/test'
            ]]
        ]));

        // Actor response without inbox
        $actorResponse = new Response(200, [
            'Content-Type' => 'application/activity+json'
        ], json_encode([
            'id' => 'https://example.com/users/test',
            'type' => 'Person'
            // Missing 'inbox' field
        ]));

        $this->httpClient = $this->createMockClient([$webFingerResponse, $actorResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('JSON response did not contain inbox field');
        $this->getInboxUrl('test@example.com');
    }

    public function testGetInboxUrlSuccess(): void
    {
        // WebFinger response
        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:test@example.com',
            'links' => [[
                'rel' => 'self',
                'type' => 'application/activity+json',
                'href' => 'https://example.com/users/test'
            ]]
        ]));

        // Actor response with inbox
        $actorResponse = new Response(200, [
            'Content-Type' => 'application/activity+json'
        ], json_encode([
            'id' => 'https://example.com/users/test',
            'type' => 'Person',
            'inbox' => 'https://example.com/users/test/inbox'
        ]));

        $this->httpClient = $this->createMockClient([$webFingerResponse, $actorResponse]);

        $inbox = $this->getInboxUrl('test@example.com');

        $this->assertSame('https://example.com/users/test/inbox', $inbox);
    }

    public function testCanonicalizeWithMockedWebFinger(): void
    {
        $webFingerResponse = new Response(200, [
            'Content-Type' => 'application/jrd+json'
        ], json_encode([
            'subject' => 'acct:alice@example.com',
            'links' => [[
                'rel' => 'self',
                'type' => 'application/activity+json',
                'href' => 'https://example.com/users/alice'
            ]]
        ]));

        $this->httpClient = $this->createMockClient([$webFingerResponse]);

        $canonical = $this->canonicalize('alice@example.com');

        $this->assertSame('https://example.com/users/alice', $canonical);
    }
}
