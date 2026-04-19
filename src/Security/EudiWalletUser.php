<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Security;

use Kimealabs\EudiWalletBundle\Model\PidIdentity;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Symfony UserInterface implementation populated from a verified EUDI Wallet presentation.
 */
final class EudiWalletUser implements UserInterface
{
    public function __construct(
        private readonly VerifiedPresentation $presentation,
        private readonly array $roles = ['ROLE_USER'],
    ) {
    }

    public static function fromPresentation(VerifiedPresentation $presentation, array $roles = ['ROLE_USER']): self
    {
        return new self($presentation, $roles);
    }

    public function getUserIdentifier(): string
    {
        $pid = $this->presentation->getPidIdentity();

        if (null !== $pid) {
            return \sprintf('%s_%s_%s',
                strtolower($pid->getFamilyName()),
                strtolower($pid->getGivenName()),
                $pid->getBirthDate()->format('Ymd')
            );
        }

        // Fallback: use issuer + sub claim
        $sub = $this->presentation->getClaim('sub');

        return $sub ?? hash('sha256', (string) json_encode($this->presentation->getClaims()));
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
        // No credentials to erase — identity comes from verified VC
    }

    public function getPresentation(): VerifiedPresentation
    {
        return $this->presentation;
    }

    public function getPidIdentity(): ?PidIdentity
    {
        return $this->presentation->getPidIdentity();
    }

    public function getFamilyName(): ?string
    {
        return $this->presentation->getPidIdentity()?->getFamilyName();
    }

    public function getGivenName(): ?string
    {
        return $this->presentation->getPidIdentity()?->getGivenName();
    }

    public function isAgeOver18(): ?bool
    {
        return $this->presentation->getPidIdentity()?->isAgeOver18();
    }
}
