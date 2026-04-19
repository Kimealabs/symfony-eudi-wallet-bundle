<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Exception;

class PresentationVerificationException extends EudiWalletException
{
    public static function missingRequiredClaim(string $claim): self
    {
        return new self(\sprintf('Required claim "%s" is missing from the presentation.', $claim));
    }

    public static function expiredCredential(): self
    {
        return new self('The presented credential has expired.');
    }
}
