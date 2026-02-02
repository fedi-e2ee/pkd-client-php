<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\HttpSignature;
use FediE2EE\PKD\Crypto\SecretKey;
use GuzzleHttp\Psr7\Response;
use ParagonIE\ConstantTime\Base64;

/**
 * Test helper for creating properly signed HTTP responses for unit tests.
 *
 * This allows tests to create mock responses that pass HTTP Signature
 * verification without needing a real PKD server.
 */
final class TestHelper
{
    /**
     * Create a signed HTTP response for testing.
     *
     * @param SecretKey $serverKey The server's secret key for signing
     * @param int $statusCode HTTP status code
     * @param array<string, string|string[]> $headers Response headers
     * @param string $body Response body (typically JSON)
     * @param array<int, string> $headersToSign Headers to include in signature
     */
    public static function createSignedResponse(
        SecretKey $serverKey,
        int $statusCode,
        array $headers,
        string $body,
        array $headersToSign = ['content-type']
    ): Response {
        $response = new Response($statusCode, $headers, $body);

        $httpSig = new HttpSignature('sig1', 300);
        /** @var Response */
        return $httpSig->sign(
            $serverKey,
            $response,
            $headersToSign,
            'test-server-key',
            time()
        );
    }

    /**
     * Create a signed JSON response for PKD API endpoints.
     *
     * @param SecretKey $serverKey The server's secret key for signing
     * @param array<string, mixed> $jsonData The JSON payload
     * @param string $pkdContext The !pkd-context value
     */
    public static function createSignedJsonResponse(
        SecretKey $serverKey,
        array $jsonData,
        string $pkdContext
    ): Response {
        $jsonData['!pkd-context'] = $pkdContext;
        $body = json_encode($jsonData, JSON_UNESCAPED_SLASHES);

        return self::createSignedResponse(
            $serverKey,
            200,
            ['Content-Type' => 'application/json'],
            $body
        );
    }

    /**
     * Create a WebFinger response (no signature required).
     */
    public static function createWebFingerResponse(
        string $actor,
        string $hostname,
        string $canonicalUrl
    ): Response {
        $body = json_encode([
            'subject' => 'acct:' . $actor . '@' . $hostname,
            'links' => [[
                'rel' => 'self',
                'type' => 'application/activity+json',
                'href' => $canonicalUrl
            ]]
        ]);

        return new Response(200, ['Content-Type' => 'application/jrd+json'], $body);
    }

    /**
     * Create a signed public keys response.
     *
     * @param SecretKey $serverKey Server's signing key
     * @param string $actorId Canonical actor ID
     * @param array<int, array{public-key: string, key-id?: string, trusted?: bool}> $keys
     */
    public static function createPublicKeysResponse(
        SecretKey $serverKey,
        string $actorId,
        array $keys
    ): Response {
        return self::createSignedJsonResponse(
            $serverKey,
            [
                'actor-id' => $actorId,
                'public-keys' => $keys
            ],
            'fedi-e2ee:v1/api/actor/get-keys'
        );
    }

    /**
     * Create a signed auxiliary info response (list of aux data).
     *
     * @param SecretKey $serverKey Server's signing key
     * @param string $actorId Canonical actor ID
     * @param array<int, array{aux-id: string, aux-type: string}> $auxiliary
     */
    public static function createAuxInfoResponse(
        SecretKey $serverKey,
        string $actorId,
        array $auxiliary
    ): Response {
        return self::createSignedJsonResponse(
            $serverKey,
            [
                'actor-id' => $actorId,
                'auxiliary' => $auxiliary
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );
    }

    /**
     * Create a signed auxiliary data response.
     *
     * @param SecretKey $serverKey Server's signing key
     * @param string $actorId Canonical actor ID
     * @param string $auxId Auxiliary data ID
     * @param string $auxType Auxiliary data type
     * @param string $auxData The actual auxiliary data
     */
    public static function createAuxDataResponse(
        SecretKey $serverKey,
        string $actorId,
        string $auxId,
        string $auxType,
        string $auxData
    ): Response {
        return self::createSignedJsonResponse(
            $serverKey,
            [
                'actor-id' => $actorId,
                'aux-id' => $auxId,
                'aux-type' => $auxType,
                'aux-data' => $auxData
            ],
            'fedi-e2ee:v1/api/actor/get-aux'
        );
    }

    /**
     * Create a signed auxiliary info response with inclusion proofs.
     *
     * @param SecretKey $serverKey Server's signing key
     * @param string $actorId Canonical actor ID
     * @param array<int, array{
     *     aux-id: string,
     *     aux-type: string,
     *     aux-data: string,
     *     actor-id: string,
     *     inclusion-proof: array<string>,
     *     merkle-leaf: string,
     *     leaf-index: int
     * }> $auxiliary Array of aux data with proofs
     * @param string $merkleRoot The merkle root (prefixed)
     * @param int $treeSize Total tree size
     */
    public static function createAuxInfoWithProofsResponse(
        SecretKey $serverKey,
        string $actorId,
        array $auxiliary,
        string $merkleRoot,
        int $treeSize
    ): Response {
        return self::createSignedJsonResponse(
            $serverKey,
            [
                'actor-id' => $actorId,
                'auxiliary' => $auxiliary,
                'merkle-root' => $merkleRoot,
                'tree-size' => $treeSize
            ],
            'fedi-e2ee:v1/api/actor/aux-info'
        );
    }
}
