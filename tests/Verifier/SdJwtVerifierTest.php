<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Exception\PresentationVerificationException;
use Kimealabs\EudiWalletBundle\Trust\TrustedIssuersListProviderInterface;
use Kimealabs\EudiWalletBundle\Verifier\JwtSignatureVerifierInterface;
use Kimealabs\EudiWalletBundle\Verifier\SdJwtVerifier;
use PHPUnit\Framework\TestCase;

final class SdJwtVerifierTest extends TestCase
{
    private TrustedIssuersListProviderInterface $trustedIssuers;
    private JwtSignatureVerifierInterface $signatureVerifier;
    private SdJwtVerifier $verifier;

    protected function setUp(): void
    {
        $this->trustedIssuers = $this->createMock(TrustedIssuersListProviderInterface::class);
        $this->signatureVerifier = $this->createMock(JwtSignatureVerifierInterface::class);
        $this->verifier = new SdJwtVerifier($this->trustedIssuers, $this->signatureVerifier);
    }

    public function testVerifyThrowsOnMalformedToken(): void
    {
        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify('not.a.valid~token', 'nonce', 'audience');
    }

    public function testVerifyThrowsOnExpiredCredential(): void
    {
        $this->trustedIssuers->method('assertTrusted');

        $payload = [
            'iss' => 'https://issuer.example.com',
            'exp' => time() - 3600,
            'nonce' => 'test-nonce',
            'aud' => 'https://rp.example.com',
        ];

        $sdJwt = $this->buildSdJwt($payload);

        $this->expectException(PresentationVerificationException::class);

        $this->verifier->verify($sdJwt, 'test-nonce', 'https://rp.example.com');
    }

    public function testVerifyThrowsOnNonceMismatch(): void
    {
        $this->trustedIssuers->method('assertTrusted');

        $payload = [
            'iss' => 'https://issuer.example.com',
            'nonce' => 'expected-nonce',
            'aud' => 'https://rp.example.com',
        ];

        $sdJwt = $this->buildSdJwt($payload);

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify($sdJwt, 'wrong-nonce', 'https://rp.example.com');
    }

    public function testVerifyReconstructsDisclosedClaims(): void
    {
        $this->trustedIssuers->method('assertTrusted');

        // Build a disclosure for family_name = Dupont
        $disclosure = $this->buildDisclosure('salt1', 'family_name', 'Dupont');
        $hash = base64_encode(hash('sha256', $disclosure, true));

        $payload = [
            'iss' => 'https://issuer.example.com',
            'nonce' => 'test-nonce',
            'aud' => 'https://rp.example.com',
            '_sd_alg' => 'sha-256',
            '_sd' => [$hash],
        ];

        $sdJwt = $this->buildSdJwt($payload).'~'.$disclosure.'~';

        $presentation = $this->verifier->verify($sdJwt, 'test-nonce', 'https://rp.example.com');

        $this->assertSame('Dupont', $presentation->getClaim('family_name'));
        $this->assertSame('https://issuer.example.com', $presentation->getIssuer());
        $this->assertSame('vc+sd-jwt', $presentation->getFormat());
    }

    private function buildSdJwt(array $payload): string
    {
        $header = base64_encode(json_encode(['alg' => 'ES256', 'typ' => 'vc+sd-jwt']));
        $body = base64_encode(json_encode($payload));

        return \sprintf('%s.%s.fakesignature', $header, $body);
    }

    private function buildDisclosure(string $salt, string $name, mixed $value): string
    {
        $disclosure = json_encode([$salt, $name, $value]);

        return rtrim(strtr(base64_encode($disclosure), '+/', '-_'), '=');
    }
}
