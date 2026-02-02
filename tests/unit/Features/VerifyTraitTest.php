<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\ReadOnlyClient;
use FediE2EE\PKD\Tests\TestHelper;
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

        $client->fetchAndVerifyPublicKeys('alice@example.com');
    }
}
