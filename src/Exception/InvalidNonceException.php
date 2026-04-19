<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Exception;

class InvalidNonceException extends EudiWalletException
{
    public static function mismatch(): self
    {
        return new self('Nonce mismatch: the response nonce does not match the request nonce.');
    }

    public static function expired(): self
    {
        return new self('Nonce has expired.');
    }

    public static function notFound(): self
    {
        return new self('Nonce not found in session.');
    }
}
