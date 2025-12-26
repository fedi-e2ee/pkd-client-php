<?php

namespace FediE2EE\PKD\Features;

use FediE2EE\PKD\Crypto\AttributeEncryption\AttributeKeyMap;
use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    HttpSignatureException,
    JsonException,
    NetworkException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\Protocol\Actions\{
    AddAuxData,
    AddKey,
    BurnDown,
    Checkpoint,
    Fireproof,
    MoveIdentity,
    RevokeAuxData,
    RevokeKey,
    RevokeKeyThirdParty,
    UndoFireproof
};
use FediE2EE\PKD\Crypto\Protocol\Bundle;
use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Exceptions\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use SodiumException;

/**
 * @property SecretKey $sk
 */
trait ProtocolTrait
{
    use PublishTrait;

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createAddKey(PublicKey $newPublicKey, string $actor): Bundle
    {
        $recent = $this->preamble();
        $actor = $this->canonicalize($actor);
        $addKey = new AddKey($actor, $newPublicKey);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        return $this->getHandler()->handle($addKey, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createRevokeKey(PublicKey $publicKeyToRevoke, string $actor): Bundle
    {
        $recent = $this->preamble();
        $actor = $this->canonicalize($actor);
        $revokeKey = new RevokeKey($actor, $publicKeyToRevoke);

        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('public-key');

        return $this->getHandler()->handle($revokeKey, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createRevokeKeyThirdParty(string $token): Bundle
    {
        $recent = $this->preamble();
        $rktp = new RevokeKeyThirdParty($token);
        return $this->getHandler()->handle($rktp, $this->sk, new AttributeKeyMap(), $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws JsonException
     * @throws NetworkException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createMoveIdentity(string $oldActor, string $newActor): Bundle
    {
        $recent = $this->preamble();
        $moveIdentity = new MoveIdentity($this->canonicalize($oldActor), $this->canonicalize($newActor));
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('old-actor')
            ->addRandomKey('new-actor');

        return $this->getHandler()->handle($moveIdentity, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createBurnDown(string $actorToBurn, string $operator, ?string $otp = null): Bundle
    {
        $recent = $this->preamble();
        $burnDown = new BurnDown($actorToBurn, $operator, null, $otp);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('operator');
        return $this->getHandler()->handle($burnDown, $this->sk, $keyring, $recent);
    }

    protected function createFireproof(string $actor): Bundle
    {
        $recent = $this->preamble();
        $fireproof = new Fireproof($actor);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor');

        return $this->getHandler()->handle($fireproof, $this->sk, $keyring, $recent);
    }

    protected function createUndoFireproof(string $actor): Bundle
    {
        $recent = $this->preamble();
        $fireproof = new UndoFireproof($actor);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor');

        return $this->getHandler()->handle($fireproof, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createAddAuxData(string $actor, string $type, string $data): Bundle
    {
        $recent = $this->preamble();
        $addAuxData = new AddAuxData($actor, $type, $data);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('aux-data');

        return $this->getHandler()->handle($addAuxData, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createRevokeAuxData(
        string $actor,
        string $type,
        ?string $data = null,
        ?string $auxDataId = null
    ): Bundle {
        $recent = $this->preamble();
        if (is_null($data) && is_null($auxDataId)) {
            throw new ClientException('Either the data or ID must be provided');
        }
        $revokeAuxData = new RevokeAuxData($actor, $type, $data, $auxDataId);
        $keyring = (new AttributeKeyMap())
            ->addRandomKey('actor')
            ->addRandomKey('aux-data');

        return $this->getHandler()->handle($revokeAuxData, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws CryptoException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    protected function createCheckpoint(
        PublicKey $fromPublicKey,
        string $fromDirectoryUrl,
        string $fromMerkleRoot,
        string $toDirectoryUrl,
        string $toValidatedMerkleRoot
    ): Bundle {
        $recent = $this->preamble();
        $checkpoint = new Checkpoint(
            $fromDirectoryUrl,
            $fromMerkleRoot,
            $fromPublicKey,
            $toDirectoryUrl,
            $toValidatedMerkleRoot,
        );
        $keyring = (new AttributeKeyMap()); // empty
        return $this->getHandler()->handle($checkpoint, $this->sk, $keyring, $recent);
    }

    /**
     * @throws ClientException
     * @throws GuzzleException
     * @throws HttpSignatureException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    private function preamble(): string
    {
        $this->assertSecretKeySet();
        $this->fetchServerInfo();
        return $this->getRecentMerkleRoot();
    }
}
