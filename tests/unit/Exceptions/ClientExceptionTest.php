<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Tests\Exceptions;

use FediE2EE\PKD\Exceptions\ClientException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;
use Exception;

#[CoversClass(ClientException::class)]
#[Group('unit')]
class ClientExceptionTest extends TestCase
{
    public function testExceptionCanBeThrown(): void
    {
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Test error message');

        throw new ClientException('Test error message');
    }

    public function testExceptionWithCode(): void
    {
        $exception = new ClientException('Error', 42);

        $this->assertSame('Error', $exception->getMessage());
        $this->assertSame(42, $exception->getCode());
    }

    public function testExceptionWithPrevious(): void
    {
        $previous = new Exception('Previous error');
        $exception = new ClientException('Current error', 0, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testExceptionIsException(): void
    {
        $exception = new ClientException('Test');

        $this->assertInstanceOf(Exception::class, $exception);
    }
}
