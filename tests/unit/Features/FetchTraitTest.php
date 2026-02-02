<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\EndUserClient;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\ExtensionInterface;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\Features\FetchTrait;
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Tests\TestHelper;
use FediE2EE\PKD\Values\AuxData;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

#[CoversClass(ReadOnlyClient::class)]
#[CoversClass(EndUserClient::class)]
#[CoversClass(AuxData::class)]
#[Group('unit')]
class FetchTraitTest extends TestCase
{
    use FetchTrait;

    private SecretKey $serverKey;
    private PublicKey $pk;
    private string $url = 'http://pkd.test';
    private Registry $registry;

    protected function setUp(): void
    {
        $this->serverKey = SecretKey::generate();
        $this->pk = $this->serverKey->getPublicKey();
        $this->httpClient = null;
        $this->registry = new Registry();
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    /**
     * @param array<int, Response> $responses
     * @param array<array-key, mixed> $history
     */
    private function createMockClientWithHistory(array $responses, array &$history): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        // @phpstan-ignore-next-line parameterByRef.type
        $handlerStack->push(Middleware::history($history));
        return new HttpClient(['handler' => $handlerStack]);
    }

    public function testFetchPublicKeysBuildsCorrectUrl(): void
    {
        $history = [];
        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse('alice', 'example.com', $actorUrl);
        $keysResponse = TestHelper::createPublicKeysResponse(
            $this->serverKey,
            $actorUrl,
            [['public-key' => SecretKey::generate()->getPublicKey()->toString()]]
        );

        $this->httpClient = $this->createMockClientWithHistory(
            [$webFingerResponse, $keysResponse],
            $history
        );

        $this->fetchUnverifiedPublicKeys('alice@example.com');

        // Second request should be to the keys endpoint
        $this->assertCount(2, $history);
        /** @var RequestInterface $keysRequest */
        $keysRequest = $history[1]['request'];
        $expectedUrl = $this->url . '/api/actor/' . urlencode($actorUrl) . '/keys';
        $this->assertSame($expectedUrl, (string) $keysRequest->getUri());
    }

    public function testFetchPublicKeysVerifiesHttpSignature(): void
    {
        $actorUrl = 'https://example.com/users/alice';
        $webFingerResponse = TestHelper::createWebFingerResponse('alice', 'example.com', $actorUrl);

        // Create unsigned response - should fail signature verification
        $keysResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/get-keys',
            'actor-id' => $actorUrl,
            'public-keys' => []
        ]));

        $this->httpClient = $this->createMockClient([$webFingerResponse, $keysResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid HTTP Signature');
        $this->fetchUnverifiedPublicKeys('alice@example.com');
    }

    public function testFetchPublicKeysAssertRequiredKeys(): void
    {
        $actorUrl = 'https://example.com/users/alice';
        $webFingerResponse = TestHelper::createWebFingerResponse('alice', 'example.com', $actorUrl);

        // Create response missing required keys
        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            ['!pkd-context' => 'fedi-e2ee:v1/api/actor/get-keys'],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $keysResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Key is not set in body: actor-id');
        $this->fetchUnverifiedPublicKeys('alice@example.com');
    }

    public function testFetchPublicKeysSetsMetadata(): void
    {
        $actorUrl = 'https://example.com/users/alice';
        $actorPk = SecretKey::generate()->getPublicKey();

        $webFingerResponse = TestHelper::createWebFingerResponse('alice', 'example.com', $actorUrl);
        $keysResponse = TestHelper::createPublicKeysResponse(
            $this->serverKey,
            $actorUrl,
            [[
                'public-key' => $actorPk->toString(),
                'key-id' => 'key-001',
                'trusted' => true,
                'created' => '2025-01-01T00:00:00Z'
            ]]
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $keysResponse]);

        $keys = $this->fetchUnverifiedPublicKeys('alice@example.com');

        $this->assertCount(1, $keys);
        $metadata = $keys[0]->getMetadata();
        $this->assertSame('key-001', $metadata['key-id']);
        $this->assertTrue($metadata['trusted']);
        $this->assertSame('2025-01-01T00:00:00Z', $metadata['created']);
        // public-key should be removed from metadata
        $this->assertArrayNotHasKey('public-key', $metadata);
    }

    public function testFetchPublicKeysThrowsOnNon200(): void
    {
        $actorUrl = 'https://example.com/users/alice';
        $webFingerResponse = TestHelper::createWebFingerResponse('alice', 'example.com', $actorUrl);
        $errorResponse = new Response(404, [], '');

        // Configure mock client to not throw on HTTP errors so we can test our status check
        $mock = new MockHandler([$webFingerResponse, $errorResponse]);
        $handlerStack = HandlerStack::create($mock);
        $this->httpClient = new HttpClient(['handler' => $handlerStack, 'http_errors' => false]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Could not retrieve public keys');
        $this->fetchUnverifiedPublicKeys('alice@example.com');
    }

    public function testFetchAuxDataBuildsCorrectUrl(): void
    {
        $history = [];
        $actorUrl = 'https://example.com/users/bob';

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);
        $auxInfoResponse = TestHelper::createAuxInfoResponse(
            $this->serverKey,
            $actorUrl,
            [['aux-id' => 'aux-001', 'aux-type' => 'test-type']]
        );
        $auxDataResponse = TestHelper::createAuxDataResponse(
            $this->serverKey,
            $actorUrl,
            'aux-001',
            'test-type',
            'test-data'
        );

        $this->httpClient = $this->createMockClientWithHistory(
            [$webFingerResponse, $auxInfoResponse, $auxDataResponse],
            $history
        );

        $this->fetchUnverifiedAuxData('bob@example.com', 'test-type');

        // Check the aux-info URL
        $this->assertCount(3, $history);
        /** @var RequestInterface $auxInfoRequest */
        $auxInfoRequest = $history[1]['request'];
        $expectedAuxInfoUrl = $this->url . '/api/actor/' . urlencode($actorUrl) . '/auxiliary';
        $this->assertSame($expectedAuxInfoUrl, (string) $auxInfoRequest->getUri());

        // Check the aux-data URL
        /** @var RequestInterface $auxDataRequest */
        $auxDataRequest = $history[2]['request'];
        $expectedAuxDataUrl = $this->url . '/api/actor/' . urlencode($actorUrl) . '/auxiliary/' . urlencode('aux-001');
        $this->assertSame($expectedAuxDataUrl, (string) $auxDataRequest->getUri());
    }

    public function testFetchAuxDataSkipsMalformedEntries(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Response with malformed entries (missing aux-id or aux-type)
        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => [
                    ['aux-type' => 'test-type'],  // Missing aux-id
                    ['aux-id' => 'aux-002'],      // Missing aux-type
                    ['aux-id' => 'aux-003', 'aux-type' => 'test-type']  // Valid
                ]
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $auxDataResponse = TestHelper::createAuxDataResponse(
            $this->serverKey,
            $actorUrl,
            'aux-003',
            'test-type',
            'valid-data'
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $auxInfoResponse, $auxDataResponse]);

        $result = $this->fetchUnverifiedAuxData('bob@example.com', 'test-type');

        // Only the valid entry should be fetched
        $this->assertCount(1, $result);
        $this->assertSame('valid-data', $result[0]->data);
    }

    public function testFetchRecentMerkleRootBuildsCorrectUrl(): void
    {
        $history = [];

        $merkleResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            ['merkle-root' => 'pkd-mr-v1:ABC123'],
            'fedi-e2ee:v1/api/history'
        );

        $this->httpClient = $this->createMockClientWithHistory([$merkleResponse], $history);

        $root = $this->fetchRecentMerkleRoot();

        $this->assertSame('pkd-mr-v1:ABC123', $root);
        $this->assertCount(1, $history);
        /** @var RequestInterface $request */
        $request = $history[0]['request'];
        $this->assertSame($this->url . '/api/history', (string) $request->getUri());
    }

    public function testFetchRecentMerkleRootVerifiesSignature(): void
    {
        // Unsigned response
        $merkleResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/history',
            'merkle-root' => 'pkd-mr-v1:ABC123'
        ]));

        $this->httpClient = $this->createMockClient([$merkleResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid HTTP Signature');
        $this->fetchRecentMerkleRoot();
    }

    public function testFetchAuxDataThrowsWhenAuxiliaryKeyMissing(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Response missing 'auxiliary' key
        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            ['actor-id' => $actorUrl],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $auxInfoResponse]);

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Key is not set in body: auxiliary');
        $this->fetchUnverifiedAuxData('bob@example.com', 'test-type');
    }

    public function testFetchAuxDataReturnsMultipleItems(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Response with multiple aux entries
        $auxInfoResponse = TestHelper::createAuxInfoResponse(
            $this->serverKey,
            $actorUrl,
            [
                ['aux-id' => 'aux-001', 'aux-type' => 'test-type'],
                ['aux-id' => 'aux-002', 'aux-type' => 'test-type'],
                ['aux-id' => 'aux-003', 'aux-type' => 'test-type']
            ]
        );

        $auxDataResponse1 = TestHelper::createAuxDataResponse(
            $this->serverKey,
            $actorUrl,
            'aux-001',
            'test-type',
            'data-one'
        );

        $auxDataResponse2 = TestHelper::createAuxDataResponse(
            $this->serverKey,
            $actorUrl,
            'aux-002',
            'test-type',
            'data-two'
        );

        $auxDataResponse3 = TestHelper::createAuxDataResponse(
            $this->serverKey,
            $actorUrl,
            'aux-003',
            'test-type',
            'data-three'
        );

        $this->httpClient = $this->createMockClient([
            $webFingerResponse,
            $auxInfoResponse,
            $auxDataResponse1,
            $auxDataResponse2,
            $auxDataResponse3
        ]);

        $result = $this->fetchUnverifiedAuxData('bob@example.com', 'test-type');

        // All three items should be returned
        $this->assertCount(3, $result);
        $this->assertSame('data-one', $result[0]->data);
        $this->assertSame('data-two', $result[1]->data);
        $this->assertSame('data-three', $result[2]->data);
    }

    public function testFetchAuxDataByIdVerifiesSignature(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Unsigned aux data response
        $auxDataResponse = new Response(200, [
            'Content-Type' => 'application/json'
        ], json_encode([
            '!pkd-context' => 'fedi-e2ee:v1/api/actor/get-aux',
            'actor-id' => $actorUrl,
            'aux-id' => 'aux-001',
            'aux-type' => 'test-type',
            'aux-data' => 'test-data'
        ]));

        $this->httpClient = $this->createMockClient([$webFingerResponse, $auxDataResponse]);

        // Signature verification throws before the try-catch block
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid HTTP Signature');
        $this->fetchAuxDataByID('bob@example.com', 'aux-001');
    }

    public function testFetchAuxDataByIdSkipsResponseMissingRequiredKeys(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Signed response but missing 'aux-id' key
        $auxDataResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'aux-type' => 'test-type',
                'aux-data' => 'test-data'
                // Missing 'aux-id'
            ],
            'fedi-e2ee:v1/api/actor/get-aux'
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $auxDataResponse]);

        // Should return null because of missing key
        $result = $this->fetchAuxDataByID('bob@example.com', 'aux-001');
        $this->assertNull($result);
    }

    public function testFetchAuxDataReturnsEmptyArrayWhenNoMatchingTypes(): void
    {
        $actorUrl = 'https://example.com/users/bob';

        // Register an extension for 'wanted-type'
        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'wanted-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $this->registry->addAuxDataType($testExtension);

        $webFingerResponse = TestHelper::createWebFingerResponse('bob', 'example.com', $actorUrl);

        // Response has aux data, but of a DIFFERENT type than we're looking for
        $auxInfoResponse = TestHelper::createAuxInfoResponse(
            $this->serverKey,
            $actorUrl,
            [
                ['aux-id' => 'aux-001', 'aux-type' => 'other-type'],
                ['aux-id' => 'aux-002', 'aux-type' => 'another-type']
            ]
        );

        $this->httpClient = $this->createMockClient([$webFingerResponse, $auxInfoResponse]);

        // Should return empty array because no aux entries match 'wanted-type'
        $result = $this->fetchUnverifiedAuxData('bob@example.com', 'wanted-type');

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

}
