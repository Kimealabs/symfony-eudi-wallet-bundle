<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Security;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Security\EudiWalletAuthenticator;
use Kimealabs\EudiWalletBundle\Verifier\VpTokenVerifierInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class EudiWalletAuthenticatorTest extends TestCase
{
    private VpTokenVerifierInterface $verifier;
    private EudiWalletAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->verifier = $this->createMock(VpTokenVerifierInterface::class);

        $this->authenticator = new EudiWalletAuthenticator(
            verifier: $this->verifier,
            callbackPath: '/wallet/callback',
            loginPath: '/login',
        );
    }

    public function testSupportsTrueForPostToCallbackPath(): void
    {
        $request = Request::create('/wallet/callback', 'POST');

        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsFalseForGetRequest(): void
    {
        $request = Request::create('/wallet/callback', 'GET');

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testSupportsFalseForWrongPath(): void
    {
        $request = Request::create('/other/path', 'POST');

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testAuthenticateCreatesPassportFromPresentation(): void
    {
        $presentation = new VerifiedPresentation('vc+sd-jwt', ['sub' => 'user-123'], 'https://issuer.example.com');

        $this->verifier->method('verifyFromRequest')->willReturn($presentation);

        $request = Request::create('/wallet/callback', 'POST', ['vp_token' => 'fake~token~']);
        $request->setSession(new Session(new MockArraySessionStorage()));

        $passport = $this->authenticator->authenticate($request);

        $this->assertNotNull($passport);
    }

    public function testAuthenticateThrowsCustomExceptionOnVerificationFailure(): void
    {
        $this->verifier->method('verifyFromRequest')
            ->willThrowException(InvalidVpTokenException::missingToken());

        $request = Request::create('/wallet/callback', 'POST');
        $request->setSession(new Session(new MockArraySessionStorage()));

        $this->expectException(\Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testOnAuthenticationFailureSetsSessionErrorAndRedirects(): void
    {
        $session = new Session(new MockArraySessionStorage());
        $request = Request::create('/wallet/callback', 'POST');
        $request->setSession($session);

        $exception = new AuthenticationException('Wallet error');

        $response = $this->authenticator->onAuthenticationFailure($request, $exception);

        $this->assertNotNull($response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/login', $response->headers->get('Location'));
        $this->assertNotEmpty($session->get('eudi_wallet_error'));
    }

    public function testOnAuthenticationSuccessReturnsNull(): void
    {
        $request = Request::create('/wallet/callback', 'POST');
        $token = $this->createMock(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class);

        $response = $this->authenticator->onAuthenticationSuccess($request, $token, 'main');

        $this->assertNull($response);
    }
}
