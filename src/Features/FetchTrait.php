<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Crypto\Exceptions\{
    JsonException,
    NetworkException,
};
use GuzzleHttp\Exception\GuzzleException;

/**
 *  Methods that clients will use for pulling messages from the Public key Directory
 */
trait FetchTrait
{
    use APTrait;

    /**
     * @throws ClientException
     * @throws JsonException
     * @throws NetworkException
     * @throws GuzzleException
     */
    public function fetchPublicKeys(string $actor): array
    {
        $this->ensureHttpClientConfigured();
        $canonical = $this->canonicalize($actor);
        $response = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/keys'
        );
        if ($response->getStatusCode() !== 200) {
            throw new ClientException('Could not retrieve public keys.');
        }
        $body = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/actor/get-keys');
        $this->assertKeysExist($body, ['actor-id', 'public-keys']);
        $publicKeys = [];
        foreach ($body['public-keys'] as $row) {
            // Create Public Key with metadata.
            $pk = PublicKey::fromString($row['public-key']);
            $meta = $row;
            unset($meta['public-key']);
            $pk->setMetadata($meta);
            $publicKeys[] = $pk;
        }
        return $publicKeys;
    }
}
