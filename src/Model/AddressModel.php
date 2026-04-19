<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Model;

final class AddressModel
{
    public function __construct(
        private readonly ?string $streetAddress = null,
        private readonly ?string $locality = null,
        private readonly ?string $region = null,
        private readonly ?string $postalCode = null,
        private readonly ?string $country = null,
    ) {
    }

    public static function fromClaims(array $claims): self
    {
        return new self(
            streetAddress: $claims['street_address'] ?? null,
            locality: $claims['locality'] ?? null,
            region: $claims['region'] ?? null,
            postalCode: $claims['postal_code'] ?? null,
            country: $claims['country'] ?? null,
        );
    }

    public function getStreetAddress(): ?string
    {
        return $this->streetAddress;
    }

    public function getLocality(): ?string
    {
        return $this->locality;
    }

    public function getRegion(): ?string
    {
        return $this->region;
    }

    public function getPostalCode(): ?string
    {
        return $this->postalCode;
    }

    public function getCountry(): ?string
    {
        return $this->country;
    }
}
