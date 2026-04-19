<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Trust;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Fetches and caches the JSON Web Key Set (JWKS) for a given issuer.
 * The JWKS is used to verify the cryptographic signature of SD-JWT credentials.
 */
final class JwksProvider implements JwksProviderInterface
{
    private const CACHE_TTL = 3600;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
    ) {
    }

    /**
     * Returns the JWKS for a given issuer as an array.
     * Tries /.well-known/jwt-issuer first, then /.well-known/openid-configuration.
     */
    public function getJwks(string $issuer): array
    {
        $cacheKey = 'eudi_wallet.jwks.'.hash('sha256', $issuer);

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($issuer): array {
            $item->expiresAfter(self::CACHE_TTL);

            return $this->fetchJwks($issuer);
        });
    }

    public function invalidate(string $issuer): void
    {
        $cacheKey = 'eudi_wallet.jwks.'.hash('sha256', $issuer);
        $this->cache->delete($cacheKey);
    }

    private function fetchJwks(string $issuer): array
    {
        $issuer = rtrim($issuer, '/');

        // Try JWT Issuer metadata (RFC 8414 / IETF SD-JWT VC)
        $jwksUri = $this->discoverJwksUri($issuer);

        try {
            $response = $this->httpClient->request('GET', $jwksUri, [
                'timeout' => 10,
                'headers' => ['Accept' => 'application/json'],
            ]);

            return $response->toArray();
        } catch (\Throwable $e) {
            throw new \RuntimeException(\sprintf('Failed to fetch JWKS from "%s" for issuer "%s": %s', $jwksUri, $issuer, $e->getMessage()), 0, $e);
        }
    }

    private function discoverJwksUri(string $issuer): string
    {
        // Try /.well-known/jwt-issuer (SD-JWT VC spec)
        $metadataUri = $issuer.'/.well-known/jwt-issuer';

        try {
            $response = $this->httpClient->request('GET', $metadataUri, ['timeout' => 5]);
            $metadata = $response->toArray();

            if (isset($metadata['jwks_uri'])) {
                return $metadata['jwks_uri'];
            }

            if (isset($metadata['jwks'])) {
                return $metadataUri; // embedded JWKS, will re-fetch but that's fine
            }
        } catch (\Throwable) {
            // Fall through to next discovery method
        }

        // Try OpenID Connect discovery
        $oidcUri = $issuer.'/.well-known/openid-configuration';

        try {
            $response = $this->httpClient->request('GET', $oidcUri, ['timeout' => 5]);
            $metadata = $response->toArray();

            if (isset($metadata['jwks_uri'])) {
                return $metadata['jwks_uri'];
            }
        } catch (\Throwable) {
            // Fall through to default
        }

        // Default: assume JWKS at /.well-known/jwks.json
        return $issuer.'/.well-known/jwks.json';
    }
}
