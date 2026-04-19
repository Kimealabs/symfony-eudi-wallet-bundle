<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Exception;

class InvalidVpTokenException extends EudiWalletException
{
    public static function missingToken(): self
    {
        return new self('VP token is missing from the response.');
    }

    public static function invalidSignature(): self
    {
        return new self('VP token signature verification failed.');
    }

    public static function malformed(string $reason): self
    {
        return new self(\sprintf('VP token is malformed: %s', $reason));
    }
}
