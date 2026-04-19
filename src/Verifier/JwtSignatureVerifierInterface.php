<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;

interface JwtSignatureVerifierInterface
{
    /** @throws InvalidVpTokenException */
    public function verifyWithJwk(string $jwt, array $jwkData): void;

    /** @throws InvalidVpTokenException */
    public function verify(string $jwt, string $issuer): void;
}
