<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Nonce;

use Kimealabs\EudiWalletBundle\Exception\InvalidNonceException;

interface NonceManagerInterface
{
    public function generate(): string;

    /** @throws InvalidNonceException */
    public function validate(string $nonce): void;

    /** Returns and invalidates the current session nonce without comparing it to a provided value. */
    public function consume(): string;
}
