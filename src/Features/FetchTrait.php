<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\ExtensionException;
use FediE2EE\PKD\Values\AuxData;
use FediE2EE\PKD\Crypto\Exceptions\{
    JsonException,
    NetworkException,
};
use GuzzleHttp\Exception\GuzzleException;
use Throwable;

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
        $this->assertKeysExist($body['auxiliary'], ['aux-id', 'aux-type']);

        // Grab the auxiliary data IDs
        $filter = $typeValidator->getAuxDataType();
        $auxIDs = [];
        foreach ($body['auxiliary'] as $aux) {
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

    public function fetchRecentMerkleRoot(): string
    {
        $this->ensureHttpClientConfigured();
        $response = $this->httpClient->get($this->url . '/api/history');
        $this->verifyHttpSignature($response);
        $body = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/history');
        return $body['merkle-root'];
    }
}
