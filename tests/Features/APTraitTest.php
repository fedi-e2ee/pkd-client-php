<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Features;

use FediE2EE\PKD\Features\APTrait;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
class APTraitTest extends TestCase
{
    use APTrait;

    public function testGetInbox(): void
    {
        $this->ensureHttpClientConfigured();
        $url = $this->getInboxUrl('soatok@furry.engineer');
        $this->assertSame('https://furry.engineer/users/soatok/inbox', $url);
    }
}