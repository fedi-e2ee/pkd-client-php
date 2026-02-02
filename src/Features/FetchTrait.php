<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\ExtensionException;
use FediE2EE\PKD\Values\AuxData;
use FediE2EE\PKD\Crypto\Exceptions\{
    HttpSignatureException,
    JsonException,
    NetworkException,
    NotImplementedException
};
use GuzzleHttp\Exception\GuzzleException;
use SodiumException;
use Throwable;
use function is_array, is_null, is_string, urlencode;

/**
 *  Methods that clients will use for pulling messages from the Public key Directory
 */
trait FetchTrait
{
    use APTrait;

    /**
     * @return PublicKey[]
     *
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function fetchPublicKeys(string $actor): array
    {
        $this->ensureHttpClientConfigured();
        $canonical = $this->canonicalize($actor);
        if (is_null($this->httpClient)) {
            throw new ClientException('HTTP client not set.');
        }
        $response = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/keys'
        );
        if ($response->getStatusCode() !== 200) {
            throw new ClientException('Could not retrieve public keys.');
        }
        $this->verifyHttpSignature($response);
        $body = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/actor/get-keys');
        $this->assertKeysExist($body, ['actor-id', 'public-keys']);
        if (!is_array($body['public-keys'])) {
            throw new ClientException('Invalid public-keys format');
        }
        $publicKeys = [];
        foreach ($body['public-keys'] as $row) {
            if (!is_array($row) || !isset($row['public-key']) || !is_string($row['public-key'])) {
                throw new ClientException('Invalid public key entry');
            }
            // Create Public Key with metadata.
            $pk = PublicKey::fromString($row['public-key']);
            $meta = $row;
            unset($meta['public-key']);
            $pk->setMetadata($meta);
            $publicKeys[] = $pk;
        }
        return $publicKeys;
    }

    /**
     * @param string $actor
     * @param string $auxDataType
     * @return AuxData[]
     * @throws ClientException
     * @throws ExtensionException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     */
    public function fetchAuxData(string $actor, string $auxDataType): array
    {
        $typeValidator = $this->registry->lookup($auxDataType);
        $this->ensureHttpClientConfigured();
        if (is_null($this->httpClient)) {
            throw new ClientException('HTTP client not set.');
        }
        $canonical = $this->canonicalize($actor);

        // Get the list of aux-data registered for this actor
        $auxDataListResponse = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/auxiliary'
        );
        if ($auxDataListResponse->getStatusCode() !== 200) {
            throw new ClientException('Could not retrieve public keys.');
        }
        $body = $this->parseJsonResponse($auxDataListResponse, 'fedi-e2ee:v1/api/actor/aux-info');
        $this->assertKeysExist($body, ['auxiliary']);
        // Note: 'auxiliary' is an array of items, each with 'aux-id' and 'aux-type'
        // The iteration below naturally handles missing keys by skipping incomplete entries

        // Grab the auxiliary data IDs
        $filter = $typeValidator->getAuxDataType();
        $auxIDs = [];
        if (!is_array($body['auxiliary'])) {
            throw new ClientException('Invalid auxiliary format');
        }
        foreach ($body['auxiliary'] as $aux) {
            if (!is_array($aux) || !isset($aux['aux-id'], $aux['aux-type'])) {
                continue; // Skip malformed entries
            }
            if (!is_string($aux['aux-id']) || !is_string($aux['aux-type'])) {
                continue; // Skip malformed entries
            }
            if ($aux['aux-type'] === $filter) {
                $auxIDs[] = $aux['aux-id'];
            }
        }
        if (empty($auxIDs)) {
            return [];
        }

        // Fetch the aux data:
        $data = [];
        foreach ($auxIDs as $auxID) {
            $fetched = $this->fetchAuxDataInternal($canonical, $auxID);
            if (is_null($fetched)) {
                continue;
            }
            if ($typeValidator->isValid($fetched->data)) {
                $data[] = $fetched;
            }
        }
        return $data;
    }

    /**
     * @param string $actor
     * @param string $auxDataTypeID
     * @return ?AuxData
     *
     * @throws ClientException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     */
    public function fetchAuxDataByID(string $actor, string $auxDataTypeID): ?AuxData
    {
        $this->ensureHttpClientConfigured();
        $canonical = $this->canonicalize($actor);
        return $this->fetchAuxDataInternal($canonical, $auxDataTypeID);
    }

    /**
     * @param string $canonical
     * @param string $auxDataID
     * @return ?AuxData
     *
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function fetchAuxDataInternal(
        string $canonical,
        string $auxDataID
    ): ?AuxData {
        if (is_null($this->httpClient)) {
            throw new ClientException('HTTP client not set.');
        }
        $auxDataResponse = $this->httpClient->get(
            $this->url . '/api/actor/' . urlencode($canonical) . '/auxiliary/' . urlencode($auxDataID)
        );
        if ($auxDataResponse->getStatusCode() !== 200) {
            return null;
        }
        $this->verifyHttpSignature($auxDataResponse);
        try {
            /** @var array{aux-type: string, aux-data: string, aux-id: string, actor-id: string} $body */
            $body = $this->parseJsonResponse($auxDataResponse, 'fedi-e2ee:v1/api/actor/get-aux');
            $this->assertKeysExist($body, ['aux-id', 'aux-type', 'aux-data', 'actor-id']);
            $typeValidator = $this->registry->lookup($body['aux-type']);
        } catch (Throwable) {
            return null;
        }
        if (!$typeValidator->isValid($body['aux-data'])) {
            return null;
        }
        return new AuxData(
            type: $body['aux-type'],
            data: $body['aux-data'],
            id: $body['aux-id'],
            actor: $body['actor-id'],
        );
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function fetchRecentMerkleRoot(): string
    {
        $this->ensureHttpClientConfigured();
        if (is_null($this->httpClient)) {
            throw new ClientException('The http client is not injected');
        }
        $response = $this->httpClient->get($this->url . '/api/history');
        $this->verifyHttpSignature($response);
        $body = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/history');
        if (!isset($body['merkle-root']) || !is_string($body['merkle-root'])) {
            throw new ClientException('Invalid merkle-root format');
        }
        return $body['merkle-root'];
    }
}
