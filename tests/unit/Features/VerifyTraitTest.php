<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\ExtensionException;
use FediE2EE\PKD\Extensions\ExtensionInterface;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Tests\TestHelper;
use FediE2EE\PKD\Values\AuxData;
use FediE2EE\PKD\Values\VerifiedAuxData;
use FediE2EE\PKD\Values\VerifiedPublicKey;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use SodiumException;

#[CoversClass(ReadOnlyClient::class)]
#[CoversClass(VerifiedAuxData::class)]
#[CoversClass(VerifiedPublicKey::class)]
#[CoversClass(AuxData::class)]
#[Group('unit')]
class VerifyTraitTest extends TestCase
{
    private SecretKey $serverKey;

    protected function setUp(): void
    {
        $this->serverKey = SecretKey::generate();
    }

    private function createMockClient(array $responses): HttpClient
    {
        $mock = new MockHandler($responses);
        $handlerStack = HandlerStack::create($mock);
        return new HttpClient(['handler' => $handlerStack]);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithValidProof(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Build a simple tree with known leaves
        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Generate proof for first leaf
        $proof = $tree->getInclusionProof('leaf1');

        // Verify the proof
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $proof,
            $tree->getSize()
        );

        $this->assertTrue($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithInvalidLeaf(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Build a tree
        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Generate proof for first leaf but try to verify with wrong leaf
        $proof = $tree->getInclusionProof('leaf1');

        // Verify with wrong leaf data - should fail
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'wrong-leaf',
            $proof,
            $tree->getSize()
        );

        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithInvalidRoot(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Build a tree
        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha256');

        // Use a different (wrong) root
        $wrongRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $proof = $tree->getInclusionProof('leaf1');

        $result = $client->verifyInclusionProof(
            'sha256',
            $wrongRoot,
            'leaf1',
            $proof,
            $tree->getSize()
        );

        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithIndexOutOfBounds(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Create a proof with an invalid index
        $proof = new InclusionProof(10, []); // Index 10 is out of bounds for 2 leaves

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $proof,
            $tree->getSize()
        );

        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithIndexAtBoundary(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Index == treeSize should fail (>= check)
        $proof = new InclusionProof($tree->getSize(), []);
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $proof,
            $tree->getSize()
        );
        $this->assertFalse($result);

        // Index == treeSize - 1 with a real proof should succeed
        $proof = $tree->getInclusionProof('leaf3');
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf3',
            $proof,
            $tree->getSize()
        );
        $this->assertTrue($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofNonPowerOfTwoSizes(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        foreach ([3, 5, 7, 9] as $size) {
            $leaves = [];
            for ($i = 0; $i < $size; $i++) {
                $leaves[] = "leaf-{$i}";
            }
            $tree = new Tree($leaves, 'sha256');
            $merkleRoot = $tree->getEncodedRoot();

            // Verify first, middle, and last leaf
            $positions = [0, intdiv($size, 2), $size - 1];
            foreach ($positions as $pos) {
                $leaf = "leaf-{$pos}";
                $proof = $tree->getInclusionProof($leaf);
                $result = $client->verifyInclusionProof(
                    'sha256',
                    $merkleRoot,
                    $leaf,
                    $proof,
                    $tree->getSize()
                );
                $this->assertTrue(
                    $result,
                    "Failed for leaf-{$pos} in {$size}-leaf tree"
                );
            }
        }
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithExtraSiblings(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof('leaf1');

        // Add an extra bogus sibling to the proof
        $tampered = new InclusionProof(
            $proof->index,
            array_merge($proof->proof, [str_repeat("\x00", 32)])
        );

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $tampered,
            $tree->getSize()
        );
        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithTruncatedProof(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof('leaf1');

        // Remove the last sibling from the proof
        $truncatedNodes = array_slice($proof->proof, 0, -1);
        $truncated = new InclusionProof($proof->index, $truncatedNodes);

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $truncated,
            $tree->getSize()
        );
        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithEmptyProofNodes(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Empty proof for a 2-leaf tree should fail
        $emptyProof = new InclusionProof(0, []);
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $emptyProof,
            $tree->getSize()
        );
        $this->assertFalse($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testDecodeMerkleRootThrowsOnMissingPrefix(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2'];
        $tree = new Tree($leaves, 'sha256');
        $proof = $tree->getInclusionProof('leaf1');

        // Root without proper prefix
        $invalidRoot = Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid Merkle root format: missing prefix');

        $client->verifyInclusionProof('sha256', $invalidRoot, 'leaf1', $proof, $tree->getSize());
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testDecodeMerkleRootThrowsOnInvalidLength(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2'];
        $tree = new Tree($leaves, 'sha256');
        $proof = $tree->getInclusionProof('leaf1');

        // Root with wrong length (16 bytes instead of 32)
        $invalidRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 16));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid Merkle root format: expected 32+ bytes');

        $client->verifyInclusionProof('sha256', $invalidRoot, 'leaf1', $proof, $tree->getSize());
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysRejectsInvalidHashFunction(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            'https://example.com/users/alice'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Unsupported hash function: md5');

        $client->fetchPublicKeys('alice@example.com', 'md5');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithSingleLeaf(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Single leaf tree
        $leaves = ['only-leaf'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof('only-leaf');

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'only-leaf',
            $proof,
            $tree->getSize()
        );

        $this->assertTrue($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithLargeTree(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Build a larger tree
        $leaves = [];
        for ($i = 0; $i < 100; $i++) {
            $leaves[] = "leaf-{$i}";
        }
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        // Verify proof for leaf in the middle
        $proof = $tree->getInclusionProof('leaf-50');

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf-50',
            $proof,
            $tree->getSize()
        );

        $this->assertTrue($result);

        // Verify proof for last leaf
        $proof = $tree->getInclusionProof('leaf-99');

        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf-99',
            $proof,
            $tree->getSize()
        );

        $this->assertTrue($result);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithSha384(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha384');
        $merkleRoot = $tree->getEncodedRoot();

        foreach ($leaves as $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $result = $client->verifyInclusionProof(
                'sha384',
                $merkleRoot,
                $leaf,
                $proof,
                $tree->getSize()
            );
            $this->assertTrue($result, "Proof failed for {$leaf} with sha384");
        }
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithSha512(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha512');
        $merkleRoot = $tree->getEncodedRoot();

        foreach ($leaves as $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $result = $client->verifyInclusionProof(
                'sha512',
                $merkleRoot,
                $leaf,
                $proof,
                $tree->getSize()
            );
            $this->assertTrue($result, "Proof failed for {$leaf} with sha512");
        }
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofWithBlake2b(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'blake2b');
        $merkleRoot = $tree->getEncodedRoot();

        foreach ($leaves as $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $result = $client->verifyInclusionProof(
                'blake2b',
                $merkleRoot,
                $leaf,
                $proof,
                $tree->getSize()
            );
            $this->assertTrue($result, "Proof failed for {$leaf} with blake2b");
        }
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofRejectsWrongHashFunction(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // Build tree with sha512
        $leaves = ['leaf1', 'leaf2', 'leaf3', 'leaf4'];
        $tree = new Tree($leaves, 'sha512');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof('leaf1');

        // Verify with sha256 - should fail because hashes won't match
        $result = $client->verifyInclusionProof(
            'sha256',
            $merkleRoot,
            'leaf1',
            $proof,
            $tree->getSize()
        );
        $this->assertFalse($result, 'Incorrect hash function yet the result was accepted!');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testVerifyInclusionProofSha384NonPowerOfTwo(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        // 5 leaves = non-power-of-2, exercises edge cases
        $leaves = ['a', 'b', 'c', 'd', 'e'];
        $tree = new Tree($leaves, 'sha384');
        $merkleRoot = $tree->getEncodedRoot();

        foreach ($leaves as $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $result = $client->verifyInclusionProof(
                'sha384',
                $merkleRoot,
                $leaf,
                $proof,
                $tree->getSize()
            );
            $this->assertTrue($result, "Proof failed for '{$leaf}' with sha384, 5-leaf tree");
        }
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAndVerifyPublicKeysThrowsOnMissingProofFields(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            'https://example.com/users/alice'
        );

        // Response missing required proof fields
        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => 'https://example.com/users/alice',
                'public-keys' => [
                    ['public-key' => 'ed25519:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32))]
                    // Missing: inclusion-proof, merkle-leaf, leaf-index
                ],
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Missing inclusion proof fields');

        $client->fetchPublicKeys('alice@example.com');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAndVerifyAuxDataWithValidProof(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        // Register test extension
        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        // Build a tree with aux-data leaves
        $auxLeaf = 'aux-data-leaf-content';
        $leaves = [$auxLeaf, 'other-leaf'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof($auxLeaf);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createAuxInfoWithProofsResponse(
            $this->serverKey,
            $actorUrl,
            [[
                'aux-id' => 'aux-001',
                'aux-type' => 'test-type',
                'aux-data' => 'test-payload',
                'actor-id' => $actorUrl,
                'inclusion-proof' => array_map(
                    fn($node) => Base64UrlSafe::encodeUnpadded($node),
                    $proof->proof
                ),
                'merkle-leaf' => Base64UrlSafe::encodeUnpadded($auxLeaf),
                'leaf-index' => $proof->index
            ]],
            $merkleRoot,
            $tree->getSize()
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $result = $client->fetchAuxData('alice@example.com', 'test-type');

        $this->assertCount(1, $result);
        $this->assertInstanceOf(VerifiedAuxData::class, $result[0]);
        $this->assertTrue($result[0]->verified);
        $this->assertSame('test-payload', $result[0]->auxData->data);
        $this->assertSame('test-type', $result[0]->auxData->type);
        $this->assertSame($merkleRoot, $result[0]->merkleRoot);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAndVerifyAuxDataThrowsOnMissingProofFields(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        // Response missing required proof fields
        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => [[
                    'aux-id' => 'aux-001',
                    'aux-type' => 'test-type',
                    'aux-data' => 'test-payload',
                    'actor-id' => $actorUrl
                    // Missing: inclusion-proof, merkle-leaf, leaf-index
                ]],
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Missing inclusion proof fields for auxiliary data');

        $client->fetchAuxData('alice@example.com', 'test-type');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testFetchAndVerifyAuxDataThrowsOnInvalidProof(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        // Build a tree
        $auxLeaf = 'aux-data-leaf-content';
        $leaves = [$auxLeaf, 'other-leaf'];
        $tree = new Tree($leaves, 'sha256');
        $proof = $tree->getInclusionProof($auxLeaf);

        // Use wrong merkle root
        $wrongRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(random_bytes(32));

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createAuxInfoWithProofsResponse(
            $this->serverKey,
            $actorUrl,
            [[
                'aux-id' => 'aux-001',
                'aux-type' => 'test-type',
                'aux-data' => 'test-payload',
                'actor-id' => $actorUrl,
                'inclusion-proof' => array_map(
                    fn($node) => Base64UrlSafe::encodeUnpadded($node),
                    $proof->proof
                ),
                'merkle-leaf' => Base64UrlSafe::encodeUnpadded($auxLeaf),
                'leaf-index' => $proof->index
            ]],
            $wrongRoot,
            $tree->getSize()
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Inclusion proof verification failed for auxiliary data');

        $client->fetchAuxData('alice@example.com', 'test-type');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAndVerifyAuxDataFiltersOnType(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'wanted-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        // Build tree with multiple leaves
        $wantedLeaf = 'wanted-leaf-content';
        $otherLeaf = 'other-leaf-content';
        $leaves = [$wantedLeaf, $otherLeaf];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $wantedProof = $tree->getInclusionProof($wantedLeaf);
        $otherProof = $tree->getInclusionProof($otherLeaf);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createAuxInfoWithProofsResponse(
            $this->serverKey,
            $actorUrl,
            [
                [
                    'aux-id' => 'aux-001',
                    'aux-type' => 'wanted-type',
                    'aux-data' => 'wanted-payload',
                    'actor-id' => $actorUrl,
                    'inclusion-proof' => array_map(
                        fn($node) => Base64UrlSafe::encodeUnpadded($node),
                        $wantedProof->proof
                    ),
                    'merkle-leaf' => Base64UrlSafe::encodeUnpadded($wantedLeaf),
                    'leaf-index' => $wantedProof->index
                ],
                [
                    'aux-id' => 'aux-002',
                    'aux-type' => 'other-type',
                    'aux-data' => 'other-payload',
                    'actor-id' => $actorUrl,
                    'inclusion-proof' => array_map(
                        fn($node) => Base64UrlSafe::encodeUnpadded($node),
                        $otherProof->proof
                    ),
                    'merkle-leaf' => Base64UrlSafe::encodeUnpadded($otherLeaf),
                    'leaf-index' => $otherProof->index
                ]
            ],
            $merkleRoot,
            $tree->getSize()
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $result = $client->fetchAuxData('alice@example.com', 'wanted-type');

        // Only the wanted-type entry should be returned
        $this->assertCount(1, $result);
        $this->assertSame('wanted-payload', $result[0]->auxData->data);
        $this->assertSame('wanted-type', $result[0]->auxData->type);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAndVerifyAuxDataWithMultipleValidEntries(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        // Build tree with multiple leaves
        $leaf1 = 'leaf-content-1';
        $leaf2 = 'leaf-content-2';
        $leaf3 = 'leaf-content-3';
        $leaves = [$leaf1, $leaf2, $leaf3];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxiliary = [];
        foreach ($leaves as $i => $leaf) {
            $proof = $tree->getInclusionProof($leaf);
            $auxiliary[] = [
                'aux-id' => 'aux-00' . ($i + 1),
                'aux-type' => 'test-type',
                'aux-data' => 'payload-' . ($i + 1),
                'actor-id' => $actorUrl,
                'inclusion-proof' => array_map(
                    fn($node) => Base64UrlSafe::encodeUnpadded($node),
                    $proof->proof
                ),
                'merkle-leaf' => Base64UrlSafe::encodeUnpadded($leaf),
                'leaf-index' => $proof->index
            ];
        }

        $auxInfoResponse = TestHelper::createAuxInfoWithProofsResponse(
            $this->serverKey,
            $actorUrl,
            $auxiliary,
            $merkleRoot,
            $tree->getSize()
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $result = $client->fetchAuxData('alice@example.com', 'test-type');

        $this->assertCount(3, $result);
        $this->assertSame('payload-1', $result[0]->auxData->data);
        $this->assertSame('payload-2', $result[1]->auxData->data);
        $this->assertSame('payload-3', $result[2]->auxData->data);
        $this->assertTrue($result[0]->verified);
        $this->assertTrue($result[1]->verified);
        $this->assertTrue($result[2]->verified);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysHappyPath(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/alice';

        // Generate two real Ed25519 keys
        $key1 = SecretKey::generate()->getPublicKey();
        $key2 = SecretKey::generate()->getPublicKey();

        // Build a Merkle tree with leaf data for each key
        $leaf1 = 'key-leaf-1';
        $leaf2 = 'key-leaf-2';
        $tree = new Tree([$leaf1, $leaf2], 'sha256');
        $merkleRoot = $tree->getEncodedRoot();

        $proof1 = $tree->getInclusionProof($leaf1);
        $proof2 = $tree->getInclusionProof($leaf2);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => [
                    [
                        'public-key' => $key1->toString(),
                        'key-id' => 'key-001',
                        'trusted' => true,
                        'inclusion-proof' => array_map(
                            fn($n) => Base64UrlSafe::encodeUnpadded($n),
                            $proof1->proof
                        ),
                        'merkle-leaf' => Base64UrlSafe::encodeUnpadded($leaf1),
                        'leaf-index' => $proof1->index,
                    ],
                    [
                        'public-key' => $key2->toString(),
                        'key-id' => 'key-002',
                        'trusted' => false,
                        'inclusion-proof' => array_map(
                            fn($n) => Base64UrlSafe::encodeUnpadded($n),
                            $proof2->proof
                        ),
                        'merkle-leaf' => Base64UrlSafe::encodeUnpadded($leaf2),
                        'leaf-index' => $proof2->index,
                    ],
                ],
                'merkle-root' => $merkleRoot,
                'tree-size' => $tree->getSize(),
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient(
            $this->createMockClient([$webFingerResponse, $keysResponse])
        );

        $result = $client->fetchPublicKeys('alice@example.com');

        // Verify returned array
        $this->assertCount(2, $result);

        // First key
        $this->assertInstanceOf(VerifiedPublicKey::class, $result[0]);
        $this->assertTrue($result[0]->verified);
        $this->assertSame($merkleRoot, $result[0]->merkleRoot);
        $this->assertSame($proof1->index, $result[0]->leafIndex);
        $this->assertSame(
            $key1->toString(),
            $result[0]->publicKey->toString()
        );

        // Metadata preserved (minus proof fields and public-key)
        $meta1 = $result[0]->publicKey->getMetadata();
        $this->assertSame('key-001', $meta1['key-id']);
        $this->assertTrue($meta1['trusted']);
        $this->assertArrayNotHasKey('public-key', $meta1);
        $this->assertArrayNotHasKey('inclusion-proof', $meta1);
        $this->assertArrayNotHasKey('merkle-leaf', $meta1);
        $this->assertArrayNotHasKey('leaf-index', $meta1);

        // Second key
        $this->assertInstanceOf(VerifiedPublicKey::class, $result[1]);
        $this->assertTrue($result[1]->verified);
        $this->assertSame($merkleRoot, $result[1]->merkleRoot);
        $this->assertSame($proof2->index, $result[1]->leafIndex);
        $this->assertSame(
            $key2->toString(),
            $result[1]->publicKey->toString()
        );
        $meta2 = $result[1]->publicKey->getMetadata();
        $this->assertSame('key-002', $meta2['key-id']);
        $this->assertFalse($meta2['trusted']);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysTreeSizeCoercion(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/bob';

        $key = SecretKey::generate()->getPublicKey();
        $leaf = 'coercion-leaf';
        $tree = new Tree([$leaf, 'pad'], 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof($leaf);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'bob',
            'example.com',
            $actorUrl
        );

        // tree-size as string "2" instead of int 2
        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => [[
                    'public-key' => $key->toString(),
                    'inclusion-proof' => array_map(
                        fn($n) => Base64UrlSafe::encodeUnpadded($n),
                        $proof->proof
                    ),
                    'merkle-leaf' => Base64UrlSafe::encodeUnpadded($leaf),
                    'leaf-index' => $proof->index,
                ]],
                'merkle-root' => $merkleRoot,
                'tree-size' => (string) $tree->getSize(),
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient(
            $this->createMockClient([$webFingerResponse, $keysResponse])
        );

        $result = $client->fetchPublicKeys('bob@example.com');

        $this->assertCount(1, $result);
        $this->assertTrue($result[0]->verified);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysThrowsOnNonStringMerkleRoot(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => [],
                'merkle-root' => 12345,
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid merkle-root format');

        $client->fetchPublicKeys('alice@example.com');
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysThrowsOnNonArrayPublicKeys(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => 'not-an-array',
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid public-keys format');

        $client->fetchPublicKeys('alice@example.com');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws RandomException
     * @throws SodiumException
     */
    public function testFetchPublicKeysThrowsOnFailedInclusionProof(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/alice';
        $key = SecretKey::generate()->getPublicKey();

        // Build a tree and get a valid proof
        $leaf = 'test-leaf';
        $tree = new Tree([$leaf, 'pad'], 'sha256');
        $proof = $tree->getInclusionProof($leaf);

        // Use a wrong Merkle root so proof verification fails
        $wrongRoot = 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(
            random_bytes(32)
        );

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => [[
                    'public-key' => $key->toString(),
                    'inclusion-proof' => array_map(
                        fn($n) => Base64UrlSafe::encodeUnpadded($n),
                        $proof->proof
                    ),
                    'merkle-leaf' => Base64UrlSafe::encodeUnpadded($leaf),
                    'leaf-index' => $proof->index,
                ]],
                'merkle-root' => $wrongRoot,
                'tree-size' => $tree->getSize(),
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Inclusion proof verification failed for public key');

        $client->fetchPublicKeys('alice@example.com');
    }

    /**
     * @throws ClientException
     * @throws ExtensionException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAuxDataThrowsOnNonStringMerkleRoot(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => [],
                'merkle-root' => 12345,
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid merkle-root format');

        $client->fetchAuxData('alice@example.com', 'test-type');
    }

    /**
     * @throws ClientException
     * @throws ExtensionException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAuxDataThrowsOnNonArrayAuxiliary(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => 'not-an-array',
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 1
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid auxiliary format');

        $client->fetchAuxData('alice@example.com', 'test-type');
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws ExtensionException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAuxDataTreeSizeCoercion(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        $auxLeaf = 'coercion-aux-leaf';
        $leaves = [$auxLeaf, 'pad'];
        $tree = new Tree($leaves, 'sha256');
        $merkleRoot = $tree->getEncodedRoot();
        $proof = $tree->getInclusionProof($auxLeaf);

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        // tree-size as string instead of int
        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => [[
                    'aux-id' => 'aux-001',
                    'aux-type' => 'test-type',
                    'aux-data' => 'test-payload',
                    'actor-id' => $actorUrl,
                    'inclusion-proof' => array_map(
                        fn($node) => Base64UrlSafe::encodeUnpadded($node),
                        $proof->proof
                    ),
                    'merkle-leaf' => Base64UrlSafe::encodeUnpadded($auxLeaf),
                    'leaf-index' => $proof->index
                ]],
                'merkle-root' => $merkleRoot,
                'tree-size' => (string) $tree->getSize()
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $result = $client->fetchAuxData('alice@example.com', 'test-type');

        $this->assertCount(1, $result);
        $this->assertTrue($result[0]->verified);
    }

    /**
     * @throws ClientException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchPublicKeysThrowsOnNonNumericTreeSize(): void
    {
        $serverPk = $this->serverKey->getPublicKey();
        $client = new ReadOnlyClient('http://pkd.test', $serverPk);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $keysResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'public-keys' => [],
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 'not-a-number'
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $keysResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid tree-size: must be positive');

        $client->fetchPublicKeys('alice@example.com');
    }

    /**
     * @throws ClientException
     * @throws ExtensionException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testFetchAuxDataThrowsOnNonNumericTreeSize(): void
    {
        $serverPk = $this->serverKey->getPublicKey();

        $testExtension = new class implements ExtensionInterface {
            public function getAuxDataType(): string { return 'test-type'; }
            public function getRejectionReason(): string { return 'Invalid'; }
            public function isValid(string $auxData): bool { return true; }
        };
        $registry = new Registry();
        $registry->addAuxDataType($testExtension);
        $client = new ReadOnlyClient('http://pkd.test', $serverPk, $registry);

        $actorUrl = 'https://example.com/users/alice';

        $webFingerResponse = TestHelper::createWebFingerResponse(
            'alice',
            'example.com',
            $actorUrl
        );

        $auxInfoResponse = TestHelper::createSignedJsonResponse(
            $this->serverKey,
            [
                'actor-id' => $actorUrl,
                'auxiliary' => [],
                'merkle-root' => 'pkd-mr-v1:' . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                'tree-size' => 'not-a-number'
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );

        $client->setHttpClient($this->createMockClient([$webFingerResponse, $auxInfoResponse]));

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Invalid tree-size: must be positive');

        $client->fetchAuxData('alice@example.com', 'test-type');
    }
}
