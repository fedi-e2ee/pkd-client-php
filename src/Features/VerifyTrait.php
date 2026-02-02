<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Values\VerifiedPublicKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;
use function array_key_exists, is_array, is_int, is_null, is_string, strlen, urlencode;

trait VerifyTrait
{
    use APTrait;

    /**
     * @throws ClientException
     * @throws SodiumException
     */
    public function verifyInclusionProof(
        string $hashFunction,
        string $merkleRoot,
        string $merkleLeaf,
        InclusionProof $proof,
        int $treeSize
    ): bool {
        $rootBytes = $this->decodeMerkleRoot($merkleRoot);

        // Verify manually following RFC 9162 §2.1.3 since Tree::verifyInclusionProof
        // requires the full tree which we don't have on the client side.
        return $this->verifyInclusionProofInternal(
            $hashFunction,
            $rootBytes,
            $merkleLeaf,
            $proof,
            $treeSize
        );
    }

    /**
     * @throws SodiumException
     */
    protected function verifyInclusionProofInternal(
        string $hashFunction,
        string $expectedRoot,
        string $leaf,
        InclusionProof $proof,
        int $treeSize
    ): bool {
        if ($proof->index >= $treeSize) {
            return false;
        }

        // Hash the leaf with domain separator
        if ($hashFunction === 'blake2b') {
            $node = sodium_crypto_generichash("\x00" . $leaf);
        } else {
            $node = hash($hashFunction, "\x00" . $leaf, true);
        }

        $fn = $proof->index;
        $sn = $treeSize - 1;

        foreach ($proof->proof as $sibling) {
            if ($sn === 0) {
                return false;
            }

            if (($fn & 1) === 1 || $fn === $sn) {
                // Node is right child or only child at this level
                $node = hash('sha256', "\x01" . $sibling . $node, true);
                while ((($fn & 1) === 0) && $fn !== 0) {
                    $fn >>= 1;
                    $sn >>= 1;
                }
            } else {
                // Node is left child
                $node = hash('sha256', "\x01" . $node . $sibling, true);
            }

            $fn >>= 1;
            $sn >>= 1;
        }

        return $sn === 0 && hash_equals($expectedRoot, $node);
    }

    /**
     * Fetch public keys with their inclusion proofs and verify them.
     *
     * @return VerifiedPublicKey[]
     *
     * @throws ClientException
     * @throws SodiumException
     */
    public function fetchAndVerifyPublicKeys(string $actor, string $hashFunc = 'sha256'): array
    {
        $this->ensureHttpClientConfigured();
        $canonical = $this->canonicalize($actor);

        if (is_null($this->httpClient)) {
            throw new ClientException('HTTP client not set.');
        }

        $response = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/keys?include-proofs=true'
        );

        if ($response->getStatusCode() !== 200) {
            throw new ClientException('Could not retrieve public keys.');
        }

        $this->verifyHttpSignature($response);
        $body = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/actor/get-keys');
        $this->assertKeysExist($body, ['actor-id', 'public-keys', 'merkle-root', 'tree-size']);

        if (!is_string($body['merkle-root'])) {
            throw new ClientException('Invalid merkle-root format');
        }
        if (!is_array($body['public-keys'])) {
            throw new ClientException('Invalid public-keys format');
        }

        $merkleRoot = $body['merkle-root'];
        $treeSize = (int) $body['tree-size'];
        $verifiedKeys = [];

        foreach ($body['public-keys'] as $row) {
            if (!$this->hasRequiredProofFields($row)) {
                throw new ClientException('Missing inclusion proof fields for public key');
            }
            /** @var array{inclusion-proof: array<string>, leaf-index: int, public-key: string, merkle-leaf: string} $row */

            $proof = $this->parseInclusionProof($row);
            $merkleLeaf = Base64UrlSafe::decodeNoPadding($row['merkle-leaf']);

            if (!$this->verifyInclusionProof($hashFunc, $merkleRoot, $merkleLeaf, $proof, $treeSize)) {
                throw new ClientException('Inclusion proof verification failed for public key');
            }

            $pk = PublicKey::fromString($row['public-key']);
            $meta = $row;
            unset($meta['public-key'], $meta['inclusion-proof'], $meta['merkle-leaf'], $meta['leaf-index']);
            $pk->setMetadata($meta);

            $verifiedKeys[] = new VerifiedPublicKey(
                publicKey: $pk,
                merkleRoot: $merkleRoot,
                leafIndex: $row['leaf-index'],
                verified: true
            );
        }

        return $verifiedKeys;
    }

    /**
     * Check if a row has all required fields for proof verification.
     *
     * @param mixed $row
     */
    protected function hasRequiredProofFields(mixed $row): bool
    {
        if (!is_array($row)) {
            return false;
        }

        return array_key_exists('public-key', $row)
            && array_key_exists('inclusion-proof', $row)
            && array_key_exists('merkle-leaf', $row)
            && array_key_exists('leaf-index', $row)
            && is_array($row['inclusion-proof'])
            && is_int($row['leaf-index']);
    }

    /**
     * Parse an inclusion proof from a response row.
     *
     * @param array{inclusion-proof: array<string>, leaf-index: int, ...} $row
     */
    protected function parseInclusionProof(array $row): InclusionProof
    {
        $proofNodes = [];
        foreach ($row['inclusion-proof'] as $node) {
            $proofNodes[] = Base64UrlSafe::decodeNoPadding($node);
        }

        return new InclusionProof(
            index: $row['leaf-index'],
            proof: $proofNodes
        );
    }

    /**
     * Decode a Merkle root from its prefixed format.
     *
     * @throws ClientException If the format is invalid
     */
    protected function decodeMerkleRoot(string $merkleRoot): string
    {
        $prefix = 'pkd-mr-v1:';
        if (!str_starts_with($merkleRoot, $prefix)) {
            throw new ClientException('Invalid Merkle root format: missing prefix');
        }

        $encoded = substr($merkleRoot, strlen($prefix));
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        if (strlen($decoded) < 32) {
            throw new ClientException('Invalid Merkle root format: expected 32+ bytes');
        }

        return $decoded;
    }
}
