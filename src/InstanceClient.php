<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\Features\FetchTrait;
use FediE2EE\PKD\Features\ProtocolTrait;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use SensitiveParameter;
use SodiumException;

/**
 * This class should be used by Fediverse instance software.
 *
 * @api
 */
final class InstanceClient extends AbstractClient
{
    use FetchTrait;
    use ProtocolTrait;

    protected ?SecretKey $sk = null;

    public function __construct(
        string $url,
        PublicKey $pk,
        ?Registry $registry = null,
        ?SecretKey $sk = null,
    ) {
        $this->url = $url;
        $this->pk = $pk;
        $this->sk = $sk;
        if (is_null($registry)) {
            $registry = new Registry();
        }
        $this->registry = $registry;
    }

    /**
     * After creating a protocol message (whether with EndUserClient or InstanceClient), use this method
     * to actually publish the protocol message to the Public Key Directory server.
     *
     * @param string $encryptedOrJson
     * @param SecretKey $httpSignatureSecretKey
     * @return ResponseInterface
     *
     * @throws ClientExceptionInterface
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws Exceptions\ClientException
     * @throws SodiumException
     */
    public function publish(string $encryptedOrJson, SecretKey $httpSignatureSecretKey): ResponseInterface
    {
        return $this->publishString($httpSignatureSecretKey, $encryptedOrJson);
    }

    public function burnDown(
        string $actorToBurn,
        string $operator,
        #[SensitiveParameter] ?string $otp = null
    ): string {
        return $this->createBurnDown($actorToBurn, $operator, $otp)->toString();
    }

    /**
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\JsonException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws Exceptions\ClientException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function checkpoint(
        PublicKey $fromPublicKey,
        string $fromDirectoryUrl,
        string $fromMerkleRoot,
        string $toDirectoryUrl,
        string $toValidatedMerkleRoot
    ): string {
        return $this->createCheckpoint(
            $fromPublicKey,
            $fromDirectoryUrl,
            $fromMerkleRoot,
            $toDirectoryUrl,
            $toValidatedMerkleRoot
        )->toString();
    }
}
