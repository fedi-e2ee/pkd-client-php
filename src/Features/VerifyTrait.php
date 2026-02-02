<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\Merkle\InclusionProof;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\ExtensionException;
use FediE2EE\PKD\Values\AuxData;
use FediE2EE\PKD\Values\VerifiedAuxData;
use FediE2EE\PKD\Values\VerifiedPublicKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use SodiumException;
use function array_key_exists, is_array, is_int, is_null, is_string, strlen, urlencode;

trait VerifyTrait
{
    use APTrait;

    /**
     * Supported hash functions for Merkle proof verification.
     * Only cryptographically secure hash functions are allowed.
     */
    private const SUPPORTED_HASH_FUNCTIONS = ['sha256', 'sha384', 'sha512', 'blake2b'];

    /**
     * Override me to change the list of supported hash functions.
     * 
     * @return string[]
     */
    public function getSupportedHashFunctions(): array
    {
        return self::SUPPORTED_HASH_FUNCTIONS;
    }

    /**
     * Validate that the hash function is supported and cryptographically secure.
     *
     * @throws ClientException If the hash function is not supported
     */
    protected function assertValidHashFunction(string $hashFunc): void
    {
        if (!in_array($hashFunc, $this->getSupportedHashFunctions(), true)) {
            throw new ClientException(
                "Unsupported hash function: {$hashFunc}. " .
                "Supported: " . implode(', ', $this->getSupportedHashFunctions())
            );
        }
    }

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
     * Fetch public keys with Merkle inclusion proof verification.
     *
     * This is the recommended method for fetching public keys as it verifies
     * that each key is properly included in the PKD's Merkle tree.
     *
     * @return VerifiedPublicKey[]
     *
     * @throws ClientException
     * @throws SodiumException
     */
    public function fetchPublicKeys(string $actor, string $hashFunc = 'sha256'): array
    {
        $this->assertValidHashFunction($hashFunc);
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
     * Fetch auxiliary data with Merkle inclusion proof verification.
     *
     * This is the recommended method for fetching auxiliary data as it verifies
     * that each item is properly included in the PKD's Merkle tree.
     *
     * @return VerifiedAuxData[]
     *
     * @throws ClientException
     * @throws ExtensionException
     * @throws SodiumException
     */
    public function fetchAuxData(
        string $actor,
        string $auxDataType,
        string $hashFunc = 'sha256'
    ): array {
        $this->assertValidHashFunction($hashFunc);
        $typeValidator = $this->registry->lookup($auxDataType);
        $this->ensureHttpClientConfigured();
        $canonical = $this->canonicalize($actor);

        if (is_null($this->httpClient)) {
            throw new ClientException('HTTP client not set.');
        }

        // Get the list of aux-data registered for this actor
        $auxDataListResponse = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/auxiliary?include-proofs=true'
        );
        if ($auxDataListResponse->getStatusCode() !== 200) {
            throw new ClientException('Could not retrieve auxiliary data list.');
        }

        $this->verifyHttpSignature($auxDataListResponse);
        $body = $this->parseJsonResponse(
            $auxDataListResponse,
            'fedi-e2ee:v1/api/actor/aux-info'
        );
        $this->assertKeysExist($body, ['auxiliary', 'merkle-root', 'tree-size']);

        if (!is_string($body['merkle-root'])) {
            throw new ClientException('Invalid merkle-root format');
        }
        if (!is_array($body['auxiliary'])) {
            throw new ClientException('Invalid auxiliary format');
        }

        $merkleRoot = $body['merkle-root'];
        $treeSize = (int) $body['tree-size'];
        $filter = $typeValidator->getAuxDataType();
        $verifiedAuxData = [];

        foreach ($body['auxiliary'] as $row) {
            // Skip entries that don't match the requested type
            if (!is_array($row) || !isset($row['aux-type']) || !is_string($row['aux-type'])) {
                continue;
            }
            if ($row['aux-type'] !== $filter) {
                continue;
            }

            if (!$this->hasRequiredAuxDataProofFields($row)) {
                throw new ClientException('Missing inclusion proof fields for auxiliary data');
            }
            /**
             * @var array{
             *     inclusion-proof: array<string>,
             *     leaf-index: int,
             *     aux-id: string,
             *     aux-type: string,
             *     aux-data: string,
             *     actor-id: string,
             *     merkle-leaf: string
             * } $row
             */

            $proof = $this->parseInclusionProof($row);
            $merkleLeaf = Base64UrlSafe::decodeNoPadding($row['merkle-leaf']);

            if (!$this->verifyInclusionProof($hashFunc, $merkleRoot, $merkleLeaf, $proof, $treeSize)) {
                throw new ClientException('Inclusion proof verification failed for auxiliary data');
            }

            if (!$typeValidator->isValid($row['aux-data'])) {
                continue;
            }

            $auxData = new AuxData(
                type: $row['aux-type'],
                data: $row['aux-data'],
                id: $row['aux-id'],
                actor: $row['actor-id'],
            );

            $verifiedAuxData[] = new VerifiedAuxData(
                auxData: $auxData,
                merkleRoot: $merkleRoot,
                leafIndex: $row['leaf-index'],
                verified: true
            );
        }

        return $verifiedAuxData;
    }

    /**
     * Check if a row has all required fields for public key proof verification.
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
     * Check if a row has all required fields for aux-data proof verification.
     *
     * @param mixed $row
     */
    protected function hasRequiredAuxDataProofFields(mixed $row): bool
    {
        if (!is_array($row)) {
            return false;
        }

        return array_key_exists('aux-id', $row)
            && array_key_exists('aux-type', $row)
            && array_key_exists('aux-data', $row)
            && array_key_exists('actor-id', $row)
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
