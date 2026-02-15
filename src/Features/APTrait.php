<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\ActivityPub\WebFinger;
use FediE2EE\PKD\Crypto\HttpSignature;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    HttpSignatureException,
    JsonException,
    NetworkException,
    NotImplementedException
};
use FediE2EE\PKD\Exceptions\ClientException;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use ParagonIE\Certainty\Exception\CertaintyException;
use ParagonIE\Certainty\RemoteFetch;
use Psr\Http\Message\ResponseInterface;
use SodiumException;
use function array_key_exists, dirname, hash_equals, is_array, is_null, is_string, json_decode, json_last_error_msg;

trait APTrait
{
    public ?HttpClient $httpClient = null;

    /**
     * @throws CertaintyException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function canonicalize(string $actorName): string
    {
        $finger = new WebFinger($this->httpClient);
        return $finger->canonicalize($actorName);
    }

    /**
     * @throws CertaintyException
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws JsonException
     * @throws NetworkException
     * @throws SodiumException
     */
    public function getInboxUrl(string $actorName): string
    {
        if (is_null($this->httpClient)) {
            throw new ClientException('The http client is not injected');
        }
        // Canonicalize Actor ID just in case.
        $canonical = $this->canonicalize($actorName);
        $response = $this->httpClient->get($canonical, [
            'headers' => [
                'Accept' => 'application/activity+json',
            ]
        ]);
        $parsed = $this->parseJsonResponse($response);
        if (!array_key_exists('inbox', $parsed) || !is_string($parsed['inbox'])) {
            throw new ClientException('JSON response did not contain inbox field');
        }
        return $parsed['inbox'];
    }

    /**
     * @throws CertaintyException
     * @throws SodiumException
     */
    public function ensureHttpClientConfigured(): void
    {
        if (is_null($this->httpClient)) {
            // Default HTTP client configuration.
            // This uses paragonie/certainty to ensure CACert bundles are up to date.
            $this->httpClient = new HttpClient([
                'timeout' => 30.0,
                'connect_timeout' => 10.0,
                'verify' => (new RemoteFetch(
                    dirname(__DIR__, 2) . '/.data'
                ))
                    ->getLatestBundle()
                    ->getFilePath()
            ]);
        }
    }

    public function setHttpClient(HttpClient $httpClient): static
    {
        $this->httpClient = $httpClient;
        return $this;
    }

    /**
     * @throws ClientException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function verifyHttpSignature(ResponseInterface $response): void
    {
        $sig = new HttpSignature();
        if (!$sig->verify($this->pk, $response)) {
            throw new ClientException('Invalid HTTP Signature from server');
        }
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws ClientException
     */
    public function parseJsonResponse(ResponseInterface $response, ?string $expectedContext = null): array
    {
        $body = $response->getBody()->getContents();
        if (empty($body)) {
            throw new ClientException('Empty JSON response.');
        }
        $decoded = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ClientException('Invalid JSON response: ' . json_last_error_msg());
        }
        if (!is_array($decoded)) {
            throw new ClientException('Invalid JSON response: expected object or array');
        }
        if ($expectedContext !== null) {
            if (!array_key_exists('!pkd-context', $decoded) || !is_string($decoded['!pkd-context'])) {
                throw new ClientException('Invalid PKD context for response.');
            }
            if (!hash_equals($expectedContext, $decoded['!pkd-context'])) {
                throw new ClientException('Invalid PKD context for response.');
            }
        }
        return $decoded;
    }

    /**
     * @param array<array-key, mixed> $body
     * @param list<string> $keys
     *
     * @throws ClientException
     */
    public function assertKeysExist(array $body, array $keys): void
    {
        foreach ($keys as $key) {
            if (!array_key_exists($key, $body)) {
                throw new ClientException('Key is not set in body: ' . $key);
            }
        }
    }
}
