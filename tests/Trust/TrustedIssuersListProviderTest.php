<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Trust;

use Kimealabs\EudiWalletBundle\Exception\UntrustedIssuerException;
use Kimealabs\EudiWalletBundle\Trust\TrustedIssuersListProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class TrustedIssuersListProviderTest extends TestCase
{
    private function makeProvider(array $issuers): TrustedIssuersListProvider
    {
        $body = json_encode(array_map(static fn (string $iss) => ['issuer' => $iss], $issuers));

        $httpClient = new MockHttpClient([
            new MockResponse($body, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        return new TrustedIssuersListProvider(
            httpClient: $httpClient,
            cache: new ArrayAdapter(),
            trustedIssuersListUri: 'https://verifier.eudiw.dev/trusted-issuers',
        );
    }

    public function testAssertTrustedPassesForKnownIssuer(): void
    {
        $provider = $this->makeProvider(['https://issuer.example.com']);

        $this->expectNotToPerformAssertions();

        $provider->assertTrusted('https://issuer.example.com');
    }

    public function testAssertTrustedThrowsForUnknownIssuer(): void
    {
        $provider = $this->makeProvider(['https://other.example.com']);

        $this->expectException(UntrustedIssuerException::class);

        $provider->assertTrusted('https://issuer.example.com');
    }

    public function testIsTrustedNormalizesTrailingSlash(): void
    {
        $provider = $this->makeProvider(['https://issuer.example.com/']);

        $this->assertTrue($provider->isTrusted('https://issuer.example.com'));
        $this->assertTrue($provider->isTrusted('https://issuer.example.com/'));
    }

    public function testIsTrustedReturnsFalseForUnknown(): void
    {
        $provider = $this->makeProvider(['https://issuer.example.com']);

        $this->assertFalse($provider->isTrusted('https://evil.example.com'));
    }

    public function testGetTrustedIssuersReturnsList(): void
    {
        $provider = $this->makeProvider([
            'https://issuer-a.example.com',
            'https://issuer-b.example.com',
        ]);

        $issuers = $provider->getTrustedIssuers();

        $this->assertContains('https://issuer-a.example.com', $issuers);
        $this->assertContains('https://issuer-b.example.com', $issuers);
    }

    public function testGetTrustedIssuersUsesCache(): void
    {
        $body = json_encode([['issuer' => 'https://issuer.example.com']]);

        // Only one response queued — second call must use cache
        $httpClient = new MockHttpClient([
            new MockResponse($body, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new TrustedIssuersListProvider(
            httpClient: $httpClient,
            cache: new ArrayAdapter(),
            trustedIssuersListUri: 'https://verifier.eudiw.dev/trusted-issuers',
        );

        $provider->getTrustedIssuers();
        $provider->getTrustedIssuers(); // Should not make a second HTTP request

        $this->assertTrue($provider->isTrusted('https://issuer.example.com'));
    }

    public function testFetchFailureThrowsRuntimeException(): void
    {
        $httpClient = new MockHttpClient([
            new MockResponse('', ['http_code' => 500]),
        ]);

        $provider = new TrustedIssuersListProvider(
            httpClient: $httpClient,
            cache: new ArrayAdapter(),
            trustedIssuersListUri: 'https://verifier.eudiw.dev/trusted-issuers',
        );

        $this->expectException(\RuntimeException::class);

        $provider->getTrustedIssuers();
    }
}
