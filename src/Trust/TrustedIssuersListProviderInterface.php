<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Trust;

use Kimealabs\EudiWalletBundle\Exception\UntrustedIssuerException;

interface TrustedIssuersListProviderInterface
{
    /** @throws UntrustedIssuerException */
    public function assertTrusted(string $issuer): void;

    public function isTrusted(string $issuer): bool;

    /** @return string[] */
    public function getTrustedIssuers(): array;

    public function refresh(): void;
}
