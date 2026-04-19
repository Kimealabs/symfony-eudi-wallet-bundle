<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Nonce\NonceManagerInterface;
use Kimealabs\EudiWalletBundle\Verifier\MDocVerifierInterface;
use Kimealabs\EudiWalletBundle\Verifier\SdJwtVerifierInterface;
use Kimealabs\EudiWalletBundle\Verifier\VpTokenVerifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class VpTokenVerifierTest extends TestCase
{
    private NonceManagerInterface $nonceManager;
    private SdJwtVerifierInterface $sdJwtVerifier;
    private MDocVerifierInterface $mdocVerifier;
    private VpTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->nonceManager = $this->createMock(NonceManagerInterface::class);
        $this->sdJwtVerifier = $this->createMock(SdJwtVerifierInterface::class);
        $this->mdocVerifier = $this->createMock(MDocVerifierInterface::class);

        $this->verifier = new VpTokenVerifier(
            nonceManager: $this->nonceManager,
            sdJwtVerifier: $this->sdJwtVerifier,
            mdocVerifier: $this->mdocVerifier,
            clientId: 'https://rp.example.com',
        );
    }

    public function testVerifyFromRequestThrowsWhenVpTokenMissing(): void
    {
        $request = Request::create('/wallet/callback', 'POST');

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verifyFromRequest($request);
    }

    public function testVerifyFromRequestAcceptsTokenFromPost(): void
    {
        $sdJwt = $this->buildFakeSdJwt('test-nonce');

        $request = Request::create('/wallet/callback', 'POST', ['vp_token' => $sdJwt]);

        $presentation = new VerifiedPresentation('vc+sd-jwt', [], 'https://issuer.example.com');

        $this->nonceManager->expects($this->once())
            ->method('validate')
            ->with('test-nonce');

        $this->sdJwtVerifier->expects($this->once())
            ->method('verify')
            ->willReturn($presentation);

        $result = $this->verifier->verifyFromRequest($request);

        $this->assertSame($presentation, $result);
    }

    public function testVerifyFromRequestAcceptsTokenFromQueryString(): void
    {
        $sdJwt = $this->buildFakeSdJwt('qnonce');

        $request = Request::create('/wallet/callback', 'GET', ['vp_token' => $sdJwt]);

        $presentation = new VerifiedPresentation('vc+sd-jwt', [], 'https://issuer.example.com');

        $this->nonceManager->method('validate');
        $this->sdJwtVerifier->method('verify')->willReturn($presentation);

        $result = $this->verifier->verifyFromRequest($request);

        $this->assertSame($presentation, $result);
    }

    public function testVerifyThrowsOnMalformedToken(): void
    {
        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verifyFromRequest(
            Request::create('/wallet/callback', 'POST', ['vp_token' => 'not-a-jwt'])
        );
    }

    public function testVerifyDispatchesToSdJwtVerifierForSdJwtFormat(): void
    {
        $sdJwt = $this->buildFakeSdJwt('nonce-abc');

        $presentation = new VerifiedPresentation('vc+sd-jwt', [], 'https://issuer.example.com');

        $this->nonceManager->method('validate');

        $this->sdJwtVerifier->expects($this->once())
            ->method('verify')
            ->with($sdJwt, 'nonce-abc', 'https://rp.example.com')
            ->willReturn($presentation);

        $this->verifier->verify($sdJwt, 'nonce-abc');
    }

    public function testUnsupportedFormatThrows(): void
    {
        // Plain JWT without ~ is detected as jwt_vp (unsupported)
        $plainJwt = base64_encode('{"alg":"ES256"}').'.'.base64_encode('{"nonce":"n","iss":"i"}').'.sig';

        $this->nonceManager->method('validate');

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify($plainJwt, 'n');
    }

    private function buildFakeSdJwt(string $nonce): string
    {
        $header = rtrim(strtr(base64_encode('{"alg":"ES256","typ":"vc+sd-jwt"}'), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'iss' => 'https://issuer.example.com',
            'nonce' => $nonce,
            'aud' => 'https://rp.example.com',
        ])), '+/', '-_'), '=');

        return $header.'.'.$payload.'.fakesig~';
    }
}
