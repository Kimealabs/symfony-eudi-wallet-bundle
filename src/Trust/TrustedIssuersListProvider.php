<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Trust;

use Kimealabs\EudiWalletBundle\Exception\UntrustedIssuerException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Loads and caches the EU Trusted Issuers List.
 * Used to verify that credential issuers are officially recognized.
 */
final class TrustedIssuersListProvider implements TrustedIssuersListProviderInterface
{
    private const CACHE_KEY = 'eudi_wallet.trusted_issuers_list';
    private const CACHE_TTL = 3600; // 1 hour

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly string $trustedIssuersListUri,
    ) {
    }

    /**
     * Assert that the given issuer is in the EU Trusted Issuers List.
     *
     * @throws UntrustedIssuerException
     */
    public function assertTrusted(string $issuer): void
    {
        if (!$this->isTrusted($issuer)) {
            throw UntrustedIssuerException::forIssuer($issuer);
        }
    }

    public function isTrusted(string $issuer): bool
    {
        $trustedIssuers = $this->getTrustedIssuers();

        foreach ($trustedIssuers as $trustedIssuer) {
            if ($this->matchesIssuer($issuer, $trustedIssuer)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the full list of trusted issuer identifiers.
     *
     * @return string[]
     */
    public function getTrustedIssuers(): array
    {
        return $this->cache->get(self::CACHE_KEY, function (ItemInterface $item): array {
            $item->expiresAfter(self::CACHE_TTL);

            return $this->fetchTrustedIssuers();
        });
    }

    /**
     * Force refresh of the trusted issuers list from the remote endpoint.
     */
    public function refresh(): void
    {
        $this->cache->delete(self::CACHE_KEY);
        $this->getTrustedIssuers();
    }

    private function fetchTrustedIssuers(): array
    {
        try {
            $response = $this->httpClient->request('GET', $this->trustedIssuersListUri, [
                'timeout' => 10,
                'headers' => ['Accept' => 'application/json'],
            ]);

            $data = $response->toArray();

            return $this->extractIssuerIdentifiers($data);
        } catch (\Throwable $e) {
            throw new \RuntimeException(\sprintf('Failed to fetch EU Trusted Issuers List from "%s": %s', $this->trustedIssuersListUri, $e->getMessage()), 0, $e);
        }
    }

    private function extractIssuerIdentifiers(array $data): array
    {
        $issuers = [];

        // EUDIW Trusted Issuers List format
        // https://verifier.eudiw.dev/trusted-issuers returns an array of issuer objects
        foreach ($data as $entry) {
            if (isset($entry['issuer'])) {
                $issuers[] = $entry['issuer'];
            } elseif (isset($entry['iss'])) {
                $issuers[] = $entry['iss'];
            } elseif (\is_string($entry)) {
                $issuers[] = $entry;
            }
        }

        return array_unique($issuers);
    }

    private function matchesIssuer(string $issuer, string $trustedIssuer): bool
    {
        // Exact match
        if ($issuer === $trustedIssuer) {
            return true;
        }

        // Normalize trailing slashes
        return rtrim($issuer, '/') === rtrim($trustedIssuer, '/');
    }
}
