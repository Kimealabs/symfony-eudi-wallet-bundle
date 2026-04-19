<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Model;

final class VerifiedPresentation
{
    public function __construct(
        private readonly string $format,
        private readonly array $claims,
        private readonly string $issuer,
        private readonly ?PidIdentity $pidIdentity = null,
        private readonly array $disclosedAttributes = [],
    ) {
    }

    public function getFormat(): string
    {
        return $this->format;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getPidIdentity(): ?PidIdentity
    {
        return $this->pidIdentity;
    }

    public function getDisclosedAttributes(): array
    {
        return $this->disclosedAttributes;
    }

    public function hasClaim(string $name): bool
    {
        return isset($this->claims[$name]);
    }

    public function getClaim(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }
}
