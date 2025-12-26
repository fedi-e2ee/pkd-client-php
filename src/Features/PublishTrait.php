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

    public function encryptBundle(Bundle $bundle): string
    {
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
        // ActivityPub Actor for PKD Server:
        if (is_null($this->serverActorInbox)) {
            $response = $this->httpClient->get($this->url . '/api/info');
            $this->verifyHttpSignature($response);
            $info = $this->parseJsonResponse($response, 'fedi-e2ee:v1/api/info');
            if (!array_key_exists('actor', $info)) {
                throw new ClientException('The server actor does not exist');
            }
            if (!array_key_exists('public-key', $info)) {
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
            if (!array_key_exists('hpke-public-key', $results)) {
                throw new ClientException('The server public key does not exist');
            }
            $this->serverHPKE = $this->getInternalHpke(
                $results['hpke-ciphersuite'] ?? 'Curve25519_SHA256_ChachaPoly',
                $results['hpke-public-key'],
            );
        }
    }

    protected function getInternalHpke(string $ciphersuite, string $pk): ServerHPKE
    {
        [$curveName, $hash, $aead] = explode('_', $ciphersuite);
        if ($curveName === 'Curve25519') {
            throw new ClientException('Invalid curve: ' . $curveName);
        }
        $kdf = new HKDF(Hash::from($hash));
        $kem = new DiffieHellmanKEM(Curve::X25519, $kdf);
        $hpke = new HPKE(
            $kem,
            $kdf,
            match($aead) {
                'Aes128GCM' => new AES128GCM(),
                'Aes256GCM' => new AES256GCM(),
                'ChaChaPoly' => new ChaCha20Poly1305(),
            }
        );
        $encapsKey = new EncapsKey(Curve::X25519, Base64UrlSafe::decodeNoPadding($pk));
        return new ServerHPKE($hpke, $encapsKey);
    }

    protected function getRecentMerkleRoot(): string
    {
        if (is_null($this->recentMerkleRoot)) {
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
