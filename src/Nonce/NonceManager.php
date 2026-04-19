<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Nonce;

use Kimealabs\EudiWalletBundle\Exception\InvalidNonceException;
use Symfony\Component\HttpFoundation\RequestStack;

final class NonceManager implements NonceManagerInterface
{
    private const SESSION_KEY = 'eudi_wallet_nonce';

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly int $ttl = 300,
    ) {
    }

    public function generate(): string
    {
        $nonce = bin2hex(random_bytes(32));
        $session = $this->requestStack->getSession();
        $session->set(self::SESSION_KEY, [
            'value' => $nonce,
            'expires_at' => time() + $this->ttl,
        ]);

        return $nonce;
    }

    public function validate(string $nonce): void
    {
        $session = $this->requestStack->getSession();
        $stored = $session->get(self::SESSION_KEY);

        if (null === $stored) {
            throw InvalidNonceException::notFound();
        }

        $session->remove(self::SESSION_KEY);

        if (time() > $stored['expires_at']) {
            throw InvalidNonceException::expired();
        }

        if (!hash_equals($stored['value'], $nonce)) {
            throw InvalidNonceException::mismatch();
        }
    }

    public function consume(): string
    {
        $session = $this->requestStack->getSession();
        $stored = $session->get(self::SESSION_KEY);

        if (null === $stored) {
            throw InvalidNonceException::notFound();
        }

        $session->remove(self::SESSION_KEY);

        if (time() > $stored['expires_at']) {
            throw InvalidNonceException::expired();
        }

        return $stored['value'];
    }
}
