<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\Features\FetchTrait;
use FediE2EE\PKD\Features\VerifyTrait;
use function is_null;

/**
 * A client for fetching data from the Public Key Directory, and not writing.
 * @api
 */
final class ReadOnlyClient extends AbstractClient
{
    use FetchTrait;
    use VerifyTrait;

    public function __construct(
        string $url,
        PublicKey $pk,
        ?Registry $registry = null
    ) {
        $this->url = $url;
        $this->pk = $pk;
        if (is_null($registry)) {
            $registry = new Registry();
        }
        $this->registry = $registry;
    }
}
