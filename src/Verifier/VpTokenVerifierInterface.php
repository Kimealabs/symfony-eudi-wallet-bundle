<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Symfony\Component\HttpFoundation\Request;

interface VpTokenVerifierInterface
{
    /** @throws InvalidVpTokenException */
    public function verifyFromRequest(Request $request): VerifiedPresentation;

    /** @throws InvalidVpTokenException */
    public function verify(string $vpToken, string $nonce): VerifiedPresentation;
}
