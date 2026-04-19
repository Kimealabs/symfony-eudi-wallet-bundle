<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Nonce;

use Kimealabs\EudiWalletBundle\Exception\InvalidNonceException;
use Kimealabs\EudiWalletBundle\Nonce\NonceManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

final class NonceManagerTest extends TestCase
{
    private RequestStack $requestStack;
    private NonceManager $manager;

    protected function setUp(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($session);

        $this->requestStack = new RequestStack();
        $this->requestStack->push($request);

        $this->manager = new NonceManager($this->requestStack, ttl: 300);
    }

    public function testGenerateReturnsCryptographicallyRandomString(): void
    {
        $nonce1 = $this->manager->generate();
        $nonce2 = $this->manager->generate();

        $this->assertNotEmpty($nonce1);
        $this->assertNotSame($nonce1, $nonce2);
        $this->assertSame(64, \strlen($nonce1)); // 32 bytes = 64 hex chars
    }

    public function testValidateSucceedsWithCorrectNonce(): void
    {
        $nonce = $this->manager->generate();

        $this->expectNotToPerformAssertions();
        $this->manager->validate($nonce);
    }

    public function testValidateThrowsOnMismatch(): void
    {
        $this->manager->generate();

        $this->expectException(InvalidNonceException::class);
        $this->manager->validate('wrong_nonce_value');
    }

    public function testValidateThrowsWhenNoNonceInSession(): void
    {
        $this->expectException(InvalidNonceException::class);
        $this->manager->validate('any_nonce');
    }

    public function testNonceIsConsumedAfterValidation(): void
    {
        $nonce = $this->manager->generate();
        $this->manager->validate($nonce);

        $this->expectException(InvalidNonceException::class);
        $this->manager->validate($nonce);
    }

    public function testConsumeReturnsNonceAndRemovesItFromSession(): void
    {
        $nonce = $this->manager->generate();
        $consumed = $this->manager->consume();

        $this->assertSame($nonce, $consumed);

        $this->expectException(InvalidNonceException::class);
        $this->manager->consume();
    }

    public function testConsumeThrowsWhenNoNonceInSession(): void
    {
        $this->expectException(InvalidNonceException::class);
        $this->manager->consume();
    }
}
