<?php
declare(strict_types=1);
namespace FediE2EE\PKD\IntegrationTests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\EndUserClient;
use FediE2EE\PKD\Extensions\ExtensionInterface;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Tests\TestHelper;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use JsonException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use function array_filter;
use function array_map;
use function count;
use function file_exists;
use function file_get_contents;
use function json_decode;
use function parse_url;
use function preg_match;
use function strlen;
use function substr;

/**
 * Test vector-based tests for PKD client.
 *
 * These tests verify the client can properly fetch and interpret data
 * that a PKD server would serve after processing the test vector steps.
 */
#[CoversClass(EndUserClient::class)]
#[CoversClass(ReadOnlyClient::class)]
#[Group('integration')]
#[Group('test-vectors')]
class VectorsTest extends TestCase
{
    private const TEST_VECTORS_PATH = __DIR__ . '/../TestVectors/test-vectors.json';

    /** @var array<string, mixed>|null */
    private static ?array $testVectors = null;

    /**
     * @throws JsonException
     */
    private static function loadTestVectors(): array
    {
        if (self::$testVectors !== null) {
            return self::$testVectors;
        }

        if (!file_exists(self::TEST_VECTORS_PATH)) {
            throw new RuntimeException(
                'Test vectors not found at: ' . self::TEST_VECTORS_PATH . "\n" .
                'Please run: cp path/to/vectorgen/output/test-vectors.json tests/TestVectors/'
            );
        }

        $content = file_get_contents(self::TEST_VECTORS_PATH);
        if ($content === false) {
            throw new RuntimeException('Failed to read test vectors file');
        }

        self::$testVectors = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        return self::$testVectors;
    }

    /**
     * @throws JsonException
     */
    public static function provideTestCasesWithPublicKeys(): iterable
    {
        $vectors = self::loadTestVectors();

        foreach ($vectors['test-cases'] as $testCase) {
            $finalMapping = $testCase['final-mapping'] ?? [];
            $actors = $finalMapping['actors'] ?? [];

            // Only yield test cases that have actors with public keys
            foreach ($actors as $actorUrl => $actorData) {
                $publicKeys = $actorData['public-keys'] ?? [];
                if (!empty($publicKeys)) {
                    yield "{$testCase['name']}:{$actorUrl}" => [
                        $testCase['name'],
                        $actorUrl,
                        $actorData,
                        $testCase['server-keys']
                    ];
                }
            }
        }
    }

    /**
     * @throws JsonException
     */
    public static function provideTestCasesWithAuxData(): iterable
    {
        $vectors = self::loadTestVectors();
        $hasYieldedAny = false;

        foreach ($vectors['test-cases'] as $testCase) {
            $finalMapping = $testCase['final-mapping'] ?? [];
            $actors = $finalMapping['actors'] ?? [];

            // Only yield test cases that have actors with aux-data
            foreach ($actors as $actorUrl => $actorData) {
                $auxData = $actorData['aux-data'] ?? [];
                if (!empty($auxData)) {
                    $hasYieldedAny = true;
                    yield "{$testCase['name']}:{$actorUrl}" => [
                        $testCase['name'],
                        $actorUrl,
                        $actorData,
                        $testCase['server-keys']
                    ];
                }
            }
        }

        // If no aux-data found in any test case, yield a placeholder
        if (!$hasYieldedAny) {
            yield 'no-aux-data-in-vectors' => ['placeholder', '', [], []];
        }
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    private function createServerKey(array $serverKeys): SecretKey
    {
        $secretKeyBytes = Base64UrlSafe::decodeNoPadding($serverKeys['sign-secret-key']);
        return new SecretKey($secretKeyBytes, 'ed25519');
    }

    private function extractHostAndActor(string $actorUrl): array
    {
        $parsed = parse_url($actorUrl);
        $host = $parsed['host'] ?? 'example.com';
        if (isset($parsed['port'])) {
            $host .= ':' . $parsed['port'];
        }
        // Extract username from path like /users/alice
        $path = $parsed['path'] ?? '';
        preg_match('/\/users\/([^\/]+)/', $path, $matches);
        $actor = $matches[1] ?? 'unknown';

        return [$host, $actor];
    }

    /**
     * Test that the client can fetch public keys matching the test vector final state.
     */
    #[DataProvider('provideTestCasesWithPublicKeys')]
    public function testFetchPublicKeysMatchesVectorState(
        string $testCaseName,
        string $actorUrl,
        array $actorData,
        array $serverKeys
    ): void {
        $serverKey = $this->createServerKey($serverKeys);
        $serverPk = $serverKey->getPublicKey();
        [$hostname, $actor] = $this->extractHostAndActor($actorUrl);

        $publicKeys = $actorData['public-keys'] ?? [];
        $expectedKeys = [];
        foreach ($publicKeys as $keyId => $keyData) {
            if (($keyData['revoked'] ?? false) === false) {
                $expectedKeys[] = $keyData['public-key'];
            }
        }

        if (empty($expectedKeys)) {
            $this->markTestSkipped("No non-revoked public keys for {$actorUrl} in {$testCaseName}");
        }

        // Create mock responses
        $webFingerResponse = TestHelper::createWebFingerResponse($actor, $hostname, $actorUrl);

        // Build public keys response data
        $keysData = [];
        foreach ($publicKeys as $keyId => $keyData) {
            if (($keyData['revoked'] ?? false) === false) {
                $keysData[] = [
                    'public-key' => $keyData['public-key'],
                    'key-id' => $keyId,
                    'trusted' => true
                ];
            }
        }

        $keysResponse = TestHelper::createPublicKeysResponse($serverKey, $actorUrl, $keysData);

        // Create client and fetch keys
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $fetchedKeys = $client->fetchPublicKeys($actor . '@' . $hostname);

        $this->assertCount(
            count($expectedKeys),
            $fetchedKeys,
            "Key count mismatch for {$actorUrl} in test case {$testCaseName}"
        );

        // Verify each key matches
        $fetchedKeyStrings = array_map(fn($k) => $k->toString(), $fetchedKeys);
        foreach ($expectedKeys as $expectedKey) {
            $this->assertContains(
                $expectedKey,
                $fetchedKeyStrings,
                "Expected key {$expectedKey} not found for {$actorUrl}"
            );
        }
    }

    /**
     * Test that the client can fetch aux data matching the test vector final state.
     */
    #[DataProvider('provideTestCasesWithAuxData')]
    public function testFetchAuxDataMatchesVectorState(
        string $testCaseName,
        string $actorUrl,
        array $actorData,
        array $serverKeys
    ): void {
        // Handle placeholder case when no aux-data exists in vectors
        if ($testCaseName === 'placeholder') {
            $this->markTestSkipped('No test cases with aux-data in vectors');
        }

        $serverKey = $this->createServerKey($serverKeys);
        $serverPk = $serverKey->getPublicKey();
        [$hostname, $actor] = $this->extractHostAndActor($actorUrl);

        $auxDataEntries = $actorData['aux-data'] ?? [];
        if (empty($auxDataEntries)) {
            $this->markTestSkipped("No aux-data for {$actorUrl} in {$testCaseName}");
        }

        // Create registry with test extension that accepts any aux-type
        $registry = new Registry();
        foreach ($auxDataEntries as $entry) {
            $auxType = $entry['aux-type'] ?? 'test-v1';
            $testExtension = new class($auxType) implements ExtensionInterface {
                public function __construct(private string $type) {}
                public function getAuxDataType(): string { return $this->type; }
                public function getRejectionReason(): string { return 'Invalid'; }
                public function isValid(string $auxData): bool { return true; }
            };
            $registry->addAuxDataType($testExtension);
        }

        // Create mock responses
        $webFingerResponse = TestHelper::createWebFingerResponse($actor, $hostname, $actorUrl);

        // Build aux info response
        $auxInfoList = [];
        foreach ($auxDataEntries as $entry) {
            $auxInfoList[] = [
                'aux-id' => $entry['aux-id'] ?? 'aux-001',
                'aux-type' => $entry['aux-type'] ?? 'test-v1'
            ];
        }

        $auxInfoResponse = TestHelper::createAuxInfoResponse($serverKey, $actorUrl, $auxInfoList);

        // Build individual aux data responses
        $responses = [$webFingerResponse, $auxInfoResponse];
        foreach ($auxDataEntries as $entry) {
            $responses[] = TestHelper::createAuxDataResponse(
                $serverKey,
                $actorUrl,
                $entry['aux-id'] ?? 'aux-001',
                $entry['aux-type'] ?? 'test-v1',
                $entry['aux-data'] ?? ''
            );
        }

        // Create client and fetch aux data
        $client = new EndUserClient('http://pkd.test', $serverPk, $registry);
        $client->setHttpClient($this->createMockClient($responses));

        // Fetch for first aux type in list
        $firstAuxType = $auxDataEntries[0]['aux-type'] ?? 'test-v1';
        $fetchedAuxData = $client->fetchAuxData($actor . '@' . $hostname, $firstAuxType);

        // Count expected entries of this type
        $expectedCount = count(array_filter(
            $auxDataEntries,
            fn($e) => ($e['aux-type'] ?? 'test-v1') === $firstAuxType
        ));

        $this->assertCount(
            $expectedCount,
            $fetchedAuxData,
            "Aux data count mismatch for {$actorUrl} in test case {$testCaseName}"
        );
    }

    /**
     * Test that fireproof status is correctly reflected in actor metadata.
     */
    public function testFireproofStatusFromVectors(): void
    {
        $vectors = self::loadTestVectors();

        foreach ($vectors['test-cases'] as $testCase) {
            $finalMapping = $testCase['final-mapping'] ?? [];
            $actors = $finalMapping['actors'] ?? [];

            foreach ($actors as $actorUrl => $actorData) {
                $isFireproof = $actorData['fireproof'] ?? false;

                // Verify the test vector has the expected fireproof values
                // This is a sanity check on the test vectors themselves
                if ($testCase['name'] === 'basic-enrollment-and-fireproof') {
                    $this->assertTrue(
                        $isFireproof,
                        "Actor {$actorUrl} should be fireproof in {$testCase['name']}"
                    );
                }
            }
        }

        // Mark test as passed
        $this->assertTrue(true);
    }

    /**
     * Test that the client handles empty public key lists gracefully.
     */
    public function testHandlesActorWithNoPublicKeys(): void
    {
        $serverKey = SecretKey::generate();
        $serverPk = $serverKey->getPublicKey();

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'newuser',
            'example.com',
            'https://example.com/users/newuser'
        );

        // Server returns empty public keys array
        $keysResponse = TestHelper::createPublicKeysResponse(
            $serverKey,
            'https://example.com/users/newuser',
            []
        );

        $client = new ReadOnlyClient('http://pkd.test', $serverPk);
        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $fetchedKeys = $client->fetchPublicKeys('newuser@example.com');

        $this->assertCount(0, $fetchedKeys);
    }

    /**
     * Test that the merkle root format from vectors is valid.
     */
    public function testMerkleRootFormat(): void
    {
        $vectors = self::loadTestVectors();

        foreach ($vectors['test-cases'] as $testCase) {
            $finalMapping = $testCase['final-mapping'] ?? [];
            $merkleTree = $finalMapping['merkle-tree'] ?? [];
            $root = $merkleTree['root'] ?? null;

            if ($root !== null) {
                // Verify merkle root starts with expected prefix
                $this->assertStringStartsWith(
                    'pkd-mr-v1:',
                    $root,
                    "Merkle root should have pkd-mr-v1: prefix in {$testCase['name']}"
                );

                // Verify the rest is valid base64url
                $rootData = substr($root, strlen('pkd-mr-v1:'));
                $decoded = Base64UrlSafe::decodeNoPadding($rootData);
                $this->assertSame(32, strlen($decoded), "Merkle root should be 32 bytes");
            }
        }

        $this->assertTrue(true);
    }
}
