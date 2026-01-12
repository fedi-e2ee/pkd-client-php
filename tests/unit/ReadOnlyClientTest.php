<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests;

use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\ReadOnlyClient;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

#[CoversClass(ReadOnlyClient::class)]
#[Group('unit')]
class ReadOnlyClientTest extends TestCase
{
    public function testConstructor(): void
    {
        $secret = SecretKey::generate();
        $public = $secret->getPublicKey();
        $client = new ReadOnlyClient('https://pkd.exaple.com', $public);
        $this->assertTrue(method_exists($client, 'fetchPublicKeys'));
        $this->assertTrue(method_exists($client, 'fetchAuxData'));
        $this->assertTrue(method_exists($client, 'fetchAuxDataByID'));
    }
}
