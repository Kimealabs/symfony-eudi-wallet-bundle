<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Exception;

class UntrustedIssuerException extends EudiWalletException
{
    public static function forIssuer(string $issuer): self
    {
        return new self(\sprintf('Issuer "%s" is not in the EU Trusted Issuers List.', $issuer));
    }
}
