<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Exception\PresentationVerificationException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;

interface MDocVerifierInterface
{
    /**
     * @throws InvalidVpTokenException
     * @throws PresentationVerificationException
     */
    public function verify(string $deviceResponse, string $nonce, string $audience): VerifiedPresentation;
}
