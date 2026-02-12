<?php
declare(strict_types=1);
namespace FediE2EE\PKD\IntegrationTests;

use FediE2EE\PKD\Crypto\Exceptions\BundleException;
use FediE2EE\PKD\Crypto\Exceptions\CryptoException;
use FediE2EE\PKD\Crypto\Exceptions\InputException;
use FediE2EE\PKD\Crypto\Exceptions\NotImplementedException;
use FediE2EE\PKD\Crypto\Merkle\Tree;
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\Protocol\Parser;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\ReadOnlyClient;
use JsonException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\HPKE;
use ParagonIE\HPKE\HPKEException;
use ParagonIE\HPKE\KEM\DHKEM\Curve;
use ParagonIE\HPKE\KEM\DHKEM\DecapsKey;
use ParagonIE\HPKE\KEM\DHKEM\EncapsKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SodiumException;
use function array_map,
    count,
    file_exists,
    file_get_contents,
    json_decode,
    strlen,
    substr;

/**
 * Test vector-based tests for PKD client.
 *
 * These tests verify the client can properly fetch and interpret data
 * that a PKD server would serve after processing the test vector steps.
 */
#[CoversClass(ReadOnlyClient::class)]
#[Group('integration')]
#[Group('test-vectors')]
class VectorsTest extends TestCase
{
    private const TEST_VECTORS_PATH = __DIR__ . '/../TestVectors/test-vectors.json';

    /** @var array<string, mixed>|null */
    private static ?array $vectors = null;

    /**
     * @throws JsonException
     */
    private static function loadVectors(): array
    {
        if (self::$vectors !== null) {
            return self::$vectors;
        }

        if (!file_exists(self::TEST_VECTORS_PATH)) {
            throw new RuntimeException(
                'Test vectors not found at: ' . self::TEST_VECTORS_PATH . "\n" .
                'Please run: cp path/to/vectorgen/output/test-vectors.json tests/TestVectors/'
            );
        }
        $raw = file_get_contents(self::TEST_VECTORS_PATH);
        if ($raw === false) {
            throw new RuntimeException('Failed to read test vectors');
        }
        self::$vectors = json_decode(
            $raw, true, 512, JSON_THROW_ON_ERROR
        );
        return self::$vectors;
    }

    private static function decodeLeaves(array $encoded): array
    {
        return array_map(
            fn(string $l) => Base64UrlSafe::decodeNoPadding($l),
            $encoded
        );
    }

    /**
     * @return PublicKey[]
     * @throws CryptoException
     */
    private static function identityPublicKeys(array $tc): array
    {
        $keys = [];
        foreach ($tc['identities'] as $actorUrl => $material) {
            $pkBytes = Base64UrlSafe::decodeNoPadding(
                $material['ed25519']['public-key']
            );
            $keys[$actorUrl] = new PublicKey($pkBytes, 'ed25519');
        }
        return $keys;
    }

    /**
     * @throws JsonException
     */
    public static function provideTestCases(): iterable
    {
        $vecs = self::loadVectors();
        foreach ($vecs['test-cases'] as $tc) {
            yield $tc['name'] => [$tc];
        }
    }

    /**
     * @throws JsonException
     */
    public static function provideNonEmptyTreeCases(): iterable
    {
        $vecs = self::loadVectors();
        foreach ($vecs['test-cases'] as $tc) {
            $leafCount = $tc['final-mapping']['merkle-tree']['leaf-count'];
            if ($leafCount > 0) {
                yield $tc['name'] => [$tc];
            }
        }
    }

    /**
     * @throws JsonException
     */
    public static function provideStepsForSignature(): iterable
    {
        $vecs = self::loadVectors();
        foreach ($vecs['test-cases'] as $tc) {
            foreach ($tc['steps'] as $i => $step) {
                yield "{$tc['name']}:step-{$i}" => [
                    $tc, $i, $step,
                ];
            }
        }
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider('provideTestCases')]
    public function testMerkleTreeRootFromLeaves(array $tc): void
    {
        $mt = $tc['final-mapping']['merkle-tree'];
        $leaves = self::decodeLeaves($mt['leaves']);

        $this->assertCount(
            $mt['leaf-count'],
            $leaves,
            "Leaf count mismatch in {$tc['name']}"
        );

        if ($mt['leaf-count'] === 0) {
            $this->assertSame(
                'pkd-mr-v1:'
                . Base64UrlSafe::encodeUnpadded(str_repeat("\x00", 32)),
                $mt['root'],
                "Empty tree root mismatch in {$tc['name']}"
            );
            return;
        }

        $tree = new Tree($leaves, 'sha256');
        $this->assertSame(
            $mt['root'],
            $tree->getEncodedRoot(),
            "Merkle root mismatch in {$tc['name']}"
        );
    }

    /**
     * @throws CryptoException
     * @throws SodiumException
     */
    #[DataProvider('provideTestCases')]
    public function testIncrementalMerkleRootChain(array $tc): void
    {
        $tree = new Tree([], 'sha256');

        foreach ($tc['steps'] as $i => $step) {
            $this->assertSame(
                $step['merkle-root-before'],
                $tree->getEncodedRoot(),
                "Root-before mismatch at step {$i} in {$tc['name']}"
            );

            if ($step['expect-fail'] ?? false) {
                // Rejected step: root must not change
                $this->assertSame(
                    $step['merkle-root-before'],
                    $step['merkle-root-after'],
                    "Failed step {$i} changed root in {$tc['name']}"
                );
            } else {
                // Accepted step: add leaf and verify root.
                // The tree stores the base64url string as the
                // leaf value (not the decoded bytes).
                $tree->addLeaf($step['merkle-leaf']);
                $this->assertSame(
                    $step['merkle-root-after'],
                    $tree->getEncodedRoot(),
                    "Root-after mismatch at step {$i}"
                    . " in {$tc['name']}"
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
    #[DataProvider('provideNonEmptyTreeCases')]
    public function testInclusionProofVerification(array $tc): void
    {
        $mt = $tc['final-mapping']['merkle-tree'];
        $leaves = self::decodeLeaves($mt['leaves']);
        $tree = new Tree($leaves, 'sha256');
        $root = $tree->getEncodedRoot();
        $treeSize = $tree->getSize();

        $serverKey = SecretKey::generate();
        $client = new ReadOnlyClient(
            'http://pkd.test',
            $serverKey->getPublicKey()
        );

        foreach ($leaves as $idx => $leaf) {
            $proof = $tree->getInclusionProof($leaf);

            $this->assertTrue(
                $client->verifyInclusionProof(
                    'sha256', $root, $leaf, $proof, $treeSize
                ),
                "Inclusion proof failed for leaf {$idx}"
                . " in {$tc['name']}"
            );

            // Verify wrong leaf fails
            $this->assertFalse(
                $client->verifyInclusionProof(
                    'sha256',
                    $root,
                    'wrong-leaf-' . $idx,
                    $proof,
                    $treeSize
                ),
                "Wrong leaf should fail for leaf {$idx}"
                . " in {$tc['name']}"
            );
        }
    }

    /**
     * Every step's signed-message must parse as a valid Bundle.
     */
    #[DataProvider('provideStepsForSignature')]
    public function testSignedMessageParsesAsBundle(
        array $tc,
        int $stepIdx,
        array $step,
    ): void {
        $bundle = Bundle::fromJson($step['signed-message']);
        $this->assertNotEmpty(
            $bundle->getAction(),
            "Empty action at step {$stepIdx} in {$tc['name']}"
        );
        $this->assertNotEmpty(
            $bundle->getSignature(),
            "Empty signature at step {$stepIdx} in {$tc['name']}"
        );
    }

    /**
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    #[DataProvider('provideStepsForSignature')]
    public function testSignedMessageSignatureVerification(
        array $tc,
        int $stepIdx,
        array $step,
    ): void {
        $bundle = Bundle::fromJson($step['signed-message']);
        $signedMsg = $bundle->toSignedMessage();
        $identityKeys = self::identityPublicKeys($tc);

        $serverPkBytes = Base64UrlSafe::decodeNoPadding(
            $tc['server-keys']['sign-public-key']
        );
        $allKeys = $identityKeys;
        $allKeys['__server__'] = new PublicKey(
            $serverPkBytes, 'ed25519'
        );

        $verified = false;
        foreach ($allKeys as $key) {
            if ($signedMsg->verify($key)) {
                $verified = true;
                break;
            }
        }

        $this->assertTrue(
            $verified,
            "Signature verification failed for step {$stepIdx}"
            . " ({$step['description']}) in {$tc['name']}"
        );
    }

    /**
     * Verify that the step merkle-leaves (for accepted steps) match
     * the final-mapping tree leaves in order.
     */
    #[DataProvider('provideTestCases')]
    public function testStepLeavesMatchFinalTree(array $tc): void
    {
        $mt = $tc['final-mapping']['merkle-tree'];
        $finalLeaves = self::decodeLeaves($mt['leaves']);
        $leafIdx = 0;

        foreach ($tc['steps'] as $i => $step) {
            if ($step['expect-fail'] ?? false) {
                continue;
            }
            $stepLeaf = $step['merkle-leaf'];
            $this->assertArrayHasKey(
                $leafIdx,
                $finalLeaves,
                "More accepted steps than final leaves at"
                . " step {$i} in {$tc['name']}"
            );
            $this->assertSame(
                $finalLeaves[$leafIdx],
                $stepLeaf,
                "Leaf mismatch: step {$i} != final leaf"
                . " {$leafIdx} in {$tc['name']}"
            );
            $leafIdx++;
        }

        $this->assertSame(
            count($finalLeaves),
            $leafIdx,
            "Accepted step count != final leaf count"
            . " in {$tc['name']}"
        );
    }

    #[DataProvider('provideTestCases')]
    public function testMerkleRootFormat(array $tc): void
    {
        $roots = [$tc['final-mapping']['merkle-tree']['root']];
        foreach ($tc['steps'] as $step) {
            $roots[] = $step['merkle-root-before'];
            $roots[] = $step['merkle-root-after'];
        }

        foreach ($roots as $root) {
            $this->assertStringStartsWith(
                'pkd-mr-v1:',
                $root,
                "Missing prefix in {$tc['name']}"
            );
            $encoded = substr($root, strlen('pkd-mr-v1:'));
            $decoded = Base64UrlSafe::decodeNoPadding($encoded);
            $this->assertSame(
                32,
                strlen($decoded),
                "Root not 32 bytes in {$tc['name']}: "
                . "{$root}"
            );
        }
    }

    /**
     * @throws BundleException
     * @throws HPKEException
     * @throws InputException
     */
    #[DataProvider('provideStepsForSignature')]
    public function testHpkeWrappedMessageDecryption(
        array $tc,
        int $stepIdx,
        array $step,
    ): void {
        $hpkeWrapped = $step['hpke-wrapped-message'] ?? '';
        if ($hpkeWrapped === '') {
            $this->markTestSkipped(
                "No HPKE-wrapped message at step {$stepIdx}"
            );
        }

        // BurnDown is sent unencrypted
        $action = json_decode(
            $step['signed-message'], true
        )['action'];
        if ($action === 'BurnDown') {
            $this->markTestSkipped(
                "BurnDown is not HPKE-encrypted"
            );
        }

        $parser = new Parser();
        $hpkeDecapsKeyBytes = Base64UrlSafe::decodeNoPadding(
            $tc['server-keys']['hpke-decaps-key']
        );
        $hpkeEncapsKeyBytes = Base64UrlSafe::decodeNoPadding(
            $tc['server-keys']['hpke-encaps-key']
        );

        $factory = \ParagonIE\HPKE\Factory::init(
            'DHKEM(X25519, HKDF-SHA256),'
            . ' HKDF-SHA256, ChaCha20Poly1305'
        );
        $hpke = new HPKE(
            $factory->kem, $factory->kdf, $factory->aead
        );

        $curve = Curve::X25519;
        $decapsKey = new DecapsKey(
            $curve, $hpkeDecapsKeyBytes
        );
        $encapsKey = new EncapsKey(
            $curve, $hpkeEncapsKeyBytes
        );

        $decryptedBundle = $parser->hpkeDecrypt(
            $hpkeWrapped, $decapsKey, $encapsKey, $hpke
        );

        $signedBundle = Bundle::fromJson($step['signed-message']);

        $this->assertSame(
            $signedBundle->getAction(),
            $decryptedBundle->getAction(),
            "Action mismatch after HPKE decrypt at"
            . " step {$stepIdx} in {$tc['name']}"
        );
        $this->assertSame(
            $signedBundle->getSignature(),
            $decryptedBundle->getSignature(),
            "Signature mismatch after HPKE decrypt at"
            . " step {$stepIdx} in {$tc['name']}"
        );
        $this->assertSame(
            $signedBundle->getRecentMerkleRoot(),
            $decryptedBundle->getRecentMerkleRoot(),
            "Merkle root mismatch after HPKE decrypt at"
            . " step {$stepIdx} in {$tc['name']}"
        );
    }

    /**
     * @throws JsonException
     */
    public function testVectorVersion(): void
    {
        $vecs = self::loadVectors();
        $this->assertArrayHasKey('version', $vecs);
        $this->assertIsString($vecs['version']);
        $this->assertNotEmpty($vecs['version']);
    }

    /**
     * @throws JsonException
     */
    public function testVectorHasTestCases(): void
    {
        $vecs = self::loadVectors();
        $this->assertArrayHasKey('test-cases', $vecs);
        $this->assertNotEmpty($vecs['test-cases']);
    }
}
