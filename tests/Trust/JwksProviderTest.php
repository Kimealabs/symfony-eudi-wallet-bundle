<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Trust;

use Kimealabs\EudiWalletBundle\Trust\JwksProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class JwksProviderTest extends TestCase
{
    private array $sampleJwks = [
        'keys' => [
            ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'abc', 'y' => 'def', 'kid' => 'key1'],
        ],
    ];

    public function testGetJwksFromJwtIssuerEndpoint(): void
    {
        $jwksUri = 'https://issuer.example.com/jwks';
        $metadata = json_encode(['jwks_uri' => $jwksUri]);
        $jwks = json_encode($this->sampleJwks);

        $httpClient = new MockHttpClient([
            new MockResponse($metadata, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new JwksProvider(httpClient: $httpClient, cache: new ArrayAdapter());

        $result = $provider->getJwks('https://issuer.example.com');

        $this->assertArrayHasKey('keys', $result);
    }

    public function testGetJwksFallsBackToOidcConfiguration(): void
    {
        $jwksUri = 'https://issuer.example.com/jwks';
        $oidcMetadata = json_encode(['jwks_uri' => $jwksUri]);
        $jwks = json_encode($this->sampleJwks);

        $httpClient = new MockHttpClient([
            new MockResponse('', ['http_code' => 404]),          // jwt-issuer fails
            new MockResponse($oidcMetadata, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new JwksProvider(httpClient: $httpClient, cache: new ArrayAdapter());

        $result = $provider->getJwks('https://issuer.example.com');

        $this->assertArrayHasKey('keys', $result);
    }

    public function testGetJwksFallsBackToDefaultJwksJson(): void
    {
        $jwks = json_encode($this->sampleJwks);

        $httpClient = new MockHttpClient([
            new MockResponse('', ['http_code' => 404]),   // jwt-issuer fails
            new MockResponse('', ['http_code' => 404]),   // oidc-config fails
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new JwksProvider(httpClient: $httpClient, cache: new ArrayAdapter());

        $result = $provider->getJwks('https://issuer.example.com');

        $this->assertArrayHasKey('keys', $result);
    }

    public function testGetJwksUsesCache(): void
    {
        $jwksUri = 'https://issuer.example.com/jwks';
        $metadata = json_encode(['jwks_uri' => $jwksUri]);
        $jwks = json_encode($this->sampleJwks);

        // Only two responses — subsequent calls must use cache
        $httpClient = new MockHttpClient([
            new MockResponse($metadata, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new JwksProvider(httpClient: $httpClient, cache: new ArrayAdapter());

        $provider->getJwks('https://issuer.example.com');
        $result = $provider->getJwks('https://issuer.example.com');

        $this->assertArrayHasKey('keys', $result);
    }

    public function testInvalidateAllowsRefetch(): void
    {
        $jwksUri = 'https://issuer.example.com/jwks';
        $metadata = json_encode(['jwks_uri' => $jwksUri]);
        $jwks = json_encode($this->sampleJwks);

        $httpClient = new MockHttpClient([
            new MockResponse($metadata, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($metadata, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
            new MockResponse($jwks, ['http_code' => 200, 'response_headers' => ['Content-Type: application/json']]),
        ]);

        $provider = new JwksProvider(httpClient: $httpClient, cache: new ArrayAdapter());

        $provider->getJwks('https://issuer.example.com');
        $provider->invalidate('https://issuer.example.com');
        $result = $provider->getJwks('https://issuer.example.com');

        $this->assertArrayHasKey('keys', $result);
    }
}
