<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Symfony UserProvider for EUDI Wallet authentication.
 *
 * EUDI Wallet sessions are stateless — users are not persisted between requests.
 * This provider only supports refreshing an existing EudiWalletUser within the same session.
 *
 * Usage in security.yaml:
 *
 *   providers:
 *     eudi_wallet:
 *       id: Kimealabs\EudiWalletBundle\Security\EudiWalletUserProvider
 */
/** @implements UserProviderInterface<EudiWalletUser> */
final class EudiWalletUserProvider implements UserProviderInterface
{
    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        throw new UserNotFoundException(\sprintf('EUDI Wallet users cannot be loaded by identifier "%s". Use the authenticator to create the user.', $identifier));
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof EudiWalletUser) {
            throw new UnsupportedUserException(\sprintf('Instances of "%s" are not supported by this provider.', $user::class));
        }

        // Wallet credentials are verified per-request via the authenticator.
        // The session carries the user identity between requests — we return it as-is.
        return $user;
    }

    public function supportsClass(string $class): bool
    {
        return EudiWalletUser::class === $class || is_subclass_of($class, EudiWalletUser::class);
    }
}
