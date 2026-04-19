<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Exception\PresentationVerificationException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;

interface SdJwtVerifierInterface
{
    /**
     * @throws InvalidVpTokenException
     * @throws PresentationVerificationException
     */
    public function verify(string $sdJwt, string $expectedNonce, string $expectedAudience): VerifiedPresentation;
}
