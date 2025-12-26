<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\Features\FetchTrait;
use FediE2EE\PKD\Features\ProtocolTrait;
use GuzzleHttp\Exception\GuzzleException;
use SodiumException;

/**
 * This class should be used by end users, not fediverse instance software.
 *
 * @api
 */
final class EndUserClient extends AbstractClient
{
    use FetchTrait;
    use ProtocolTrait;

    protected ?SecretKey $sk = null;
    protected ?string $actor = null;

    public function __construct(
        string $url,
        PublicKey $pk,
        ?Registry $registry = null,
        ?SecretKey $sk = null,
        ?string $actor = null,
    ) {
        $this->url = $url;
        $this->pk = $pk;
        $this->sk = $sk;
        if (is_null($registry)) {
            $registry = new Registry();
        }
        $this->registry = $registry;
        $this->actor = $actor;
    }

    /**
     * @api
     *
     * @throws ClientException
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\JsonException
     * @throws Crypto\Exceptions\NetworkException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function addKey(PublicKey $newPublicKey, ?string $actor = null): string
    {
        return $this->encryptBundle(
            $this->createAddKey($newPublicKey, $this->flattenActor($actor))
        );
    }

    /**
     * @api
     *
     * @throws ClientException
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function addAuxData(string $data, string $type, ?string $actor = null): string
    {
        return $this->encryptBundle(
            $this->createAddAuxData($data, $type, $this->flattenActor($actor))
        );
    }

    /**
     * @api
     * @throws ClientException
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\JsonException
     * @throws Crypto\Exceptions\NetworkException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function revokeKey(PublicKey $publicKeyToRevoke, ?string $actor = null): string
    {
        return $this->encryptBundle(
            $this->createRevokeKey($publicKeyToRevoke, $this->flattenActor($actor))
        );
    }

    /**
     * @api
     * @throws ClientException
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\JsonException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function revokeKeyThirdParty(string $revocationToken): string
    {
        return $this->createRevokeKeyThirdParty($revocationToken)->toString();
    }

    /**
     * @api
     * @throws ClientException
     * @throws Crypto\Exceptions\CryptoException
     * @throws Crypto\Exceptions\HttpSignatureException
     * @throws Crypto\Exceptions\JsonException
     * @throws Crypto\Exceptions\NetworkException
     * @throws Crypto\Exceptions\NotImplementedException
     * @throws GuzzleException
     * @throws SodiumException
     */
    public function moveIdentity(string $newActor, ?string $oldActor = null): string
    {
        return $this->encryptBundle(
            $this->createMoveIdentity($newActor, $this->flattenActor($oldActor))
        );
    }

    /**
     * @api
     * @throws ClientException
     */
    public function burnDown(): never
    {
        throw new ClientException(
            'BurnDown is an instance-only action, and must not be generated client-side!'
        );
    }

    /**
     * @api
     * @throws ClientException
     */
    public function fireproof(?string $actor = null): string
    {
        return $this->encryptBundle(
            $this->createFireproof($this->flattenActor($actor))
        );
    }

    /**
     * @api
     * @throws ClientException
     */
    public function undoFireproof(?string $actor = null): string
    {
        return $this->encryptBundle(
            $this->createUndoFireproof($this->flattenActor($actor))
        );
    }

    /**
     * @throws ClientException
     */
    protected function flattenActor(?string $actor): string
    {
        if (!is_null($actor)) {
            return $actor;
        }
        if (!is_null($this->actor)) {
            return $this->actor;
        }
        throw new ClientException('Actor ID is mandatory, either at the constructor or each method call');
    }
}
