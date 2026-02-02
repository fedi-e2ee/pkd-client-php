<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\Exceptions\{
    HttpSignatureException,
    JsonException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\HttpSignature;
use FediE2EE\PKD\Crypto\Protocol\{
    Bundle,
    Handler,
    HPKEAdapter,
};
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Values\ServerHPKE;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HPKE\{
    AEAD\AES128GCM,
    AEAD\AES256GCM,
    AEAD\ChaCha20Poly1305,
    Hash,
    HPKE,
    KDF\HKDF,
    KEM\DHKEM\Curve,
    KEM\DHKEM\EncapsKey,
    KEM\DiffieHellmanKEM
};
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\{
    RequestInterface,
    ResponseInterface
};
use SodiumException;
use function array_key_exists, explode, hash_equals, in_array, is_null, is_string;

/**
 * Methods that clients will use for pushing messages to the Public key Directory
 */
trait PublishTrait
{
    use APTrait;

    protected ?Handler $handler = null;
    protected ?string $recentMerkleRoot = null;
    protected ?string $serverActorInbox = null;
    protected ?ServerHPKE $serverHPKE = null;

    /**
     * @throws ClientException
     * @throws JsonException
     */
    public function encryptBundle(Bundle $bundle): string
    {
        if (is_null($this->serverHPKE)) {
            throw new ClientException('HPKE config is not defined');
        }
        $adapter = new HPKEAdapter($this->serverHPKE->ciphersuite);
        return $adapter->seal($this->serverHPKE->encapsKey, $bundle->toJson());
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function publishBundle(
        SecretKey $httpSignatureSecretKey,
        Bundle $bundle
    ): ResponseInterface {
        if (in_array($bundle->getAction(), ['BurnDown', 'Checkpoint'], true)) {
            $body = $bundle->toJson();
        } else {
            $body = $this->encryptBundle($bundle);
        }
        return $this->publishString($httpSignatureSecretKey, $body);
    }

    /**
     * @throws ClientException
     * @throws ClientExceptionInterface
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function publishString(
        SecretKey $httpSignatureSecretKey,
        #[\SensitiveParameter] string $body
    ): ResponseInterface {
        if (is_null($this->httpClient)) {
            throw new ClientException('The http client is not injected');
        }
        if (is_null($this->serverActorInbox)) {
            throw new ClientException('The actor inbox URL is not set');
        }
        $request = new Request(
            'POST',
            $this->serverActorInbox,
            [
                'Content-Type' => 'application/json',
            ],
            $body
        );
        $signed = (new HttpSignature())->sign($httpSignatureSecretKey, $request);
        if (!($signed instanceof RequestInterface)) {
            throw new ClientException('An unexpected error has occurred with PKDCrypto.');
        }
        return $this->httpClient->sendRequest($signed);
    }

    protected function assertSecretKeySet(): void
    {
        if (!($this->sk instanceof SecretKey)) {
            throw new ClientException('The secret key must be set');
        }
    }

    protected function getHandler(): Handler
    {
        if (is_null($this->handler)) {
            $this->handler = new Handler();
        }
        return $this->handler;
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function fetchServerInfo(): void
    {
        if (is_null($this->httpClient)) {
            throw new ClientException('The http client is not injected');
        }
        if (!property_exists($this, 'url')) {
            throw new ClientException('Property "url" not defined');
        }
        // ActivityPub Actor for PKD Server:
        if (is_null($this->serverActorInbox)) {
            $response = $this->httpClient->get($this->url . '/api/info');
            $this->verifyHttpSignature($response);
            $info = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/info');
            if (!array_key_exists('actor', $info) || !is_string($info['actor'])) {
                throw new ClientException('The server actor does not exist');
            }
            if (!array_key_exists('public-key', $info) || !is_string($info['public-key'])) {
                throw new ClientException('The server public key does not exist');
            }
            if (!hash_equals($this->pk->toString(), $info['public-key'])) {
                // This SHOULD be caught by the HTTP Signature above, but just to be pedantic:
                throw new ClientException('The server public key does not match');
            }
            $this->serverActorInbox = $this->getInboxUrl($info['actor']);
        }

        // HPKE info:
        if (is_null($this->serverHPKE)) {
            $response = $this->httpClient->get($this->url . '/api/server-public-key');
            $this->verifyHttpSignature($response);
            $results = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/server-public-key');
            if (!array_key_exists('hpke-public-key', $results) || !is_string($results['hpke-public-key'])) {
                throw new ClientException('The server public key does not exist');
            }
            $ciphersuite = $results['hpke-ciphersuite'] ?? 'Curve25519_SHA256_ChachaPoly';
            if (!is_string($ciphersuite)) {
                throw new ClientException('Invalid ciphersuite format');
            }
            $this->serverHPKE = $this->getInternalHpke($ciphersuite, $results['hpke-public-key']);
        }
    }

    protected function getInternalHpke(string $ciphersuite, string $pk): ServerHPKE
    {
        [$curveName, $hash, $aead] = explode('_', $ciphersuite);
        $curveName = strtolower($curveName);
        if ($curveName !== 'curve25519' && $curveName !== 'x25519') {
            throw new ClientException('Invalid curve: ' . $curveName);
        }
        $kdf = new HKDF(Hash::from(strtolower($hash)));
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE(
            $kem,
            $kdf,
            match(strtolower($aead)) {
                'aes128gcm' => new AES128GCM(),
                'aes256gcm' => new AES256GCM(),
                'chachapoly' => new ChaCha20Poly1305(),
                default => throw new ClientException('Invalid AEAD: ' . $aead),
            }
        );
        $encapsKey = new EncapsKey(Curve::X25519, Base64UrlSafe::decodeNoPadding($pk));
        return new ServerHPKE($hpke, $encapsKey);
    }

    /**
     * @throws ClientException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    protected function getRecentMerkleRoot(): string
    {
        if (is_null($this->recentMerkleRoot)) {
            if (!method_exists($this, 'fetchRecentMerkleRoot')) {
                throw new ClientException(
                    'Method "fetchRecentMerkleRoot" does not exist on ' . get_class($this)
                );
            }
            $this->recentMerkleRoot = $this->fetchRecentMerkleRoot();
        }
        return $this->recentMerkleRoot;
    }

    public function withRecentMerkleRoot(?string $recent): static
    {
        $this->recentMerkleRoot = $recent;
        return $this;
    }

    public function withServerActorInbox(string $actorInboxUrl): static
    {
        $this->serverActorInbox = $actorInboxUrl;
        return $this;
    }

    public function withServerHPKE(ServerHPKE $serverHPKE): static
    {
        $this->serverHPKE = $serverHPKE;
        return $this;
    }
}
