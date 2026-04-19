<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Model;

/**
 * Person Identification Data (PID) extracted from a verified EUDI Wallet presentation.
 * Maps to the EU PID credential specification (ARF 1.4+).
 */
final class PidIdentity
{
    public function __construct(
        private readonly string $familyName,
        private readonly string $givenName,
        private readonly \DateTimeImmutable $birthDate,
        private readonly ?string $familyNameBirth = null,
        private readonly ?string $givenNameBirth = null,
        private readonly ?string $birthPlace = null,
        private readonly ?string $nationality = null,
        private readonly ?bool $ageOver18 = null,
        private readonly ?bool $ageOver15 = null,
        private readonly ?bool $ageOver21 = null,
        private readonly ?int $ageInYears = null,
        private readonly ?string $gender = null,
        private readonly ?AddressModel $address = null,
        private readonly ?string $issuingCountry = null,
        private readonly ?string $issuingAuthority = null,
        private readonly ?\DateTimeImmutable $issuanceDate = null,
        private readonly ?\DateTimeImmutable $expiryDate = null,
        private readonly array $rawClaims = [],
    ) {
    }

    public static function fromClaims(array $claims): self
    {
        return new self(
            familyName: $claims['family_name'] ?? throw new \InvalidArgumentException('Missing claim: family_name'),
            givenName: $claims['given_name'] ?? throw new \InvalidArgumentException('Missing claim: given_name'),
            birthDate: isset($claims['birth_date'])
                ? new \DateTimeImmutable($claims['birth_date'])
                : throw new \InvalidArgumentException('Missing claim: birth_date'),
            familyNameBirth: $claims['family_name_birth'] ?? null,
            givenNameBirth: $claims['given_name_birth'] ?? null,
            birthPlace: $claims['birth_place'] ?? null,
            nationality: $claims['nationality'] ?? null,
            ageOver18: $claims['age_over_18'] ?? null,
            ageOver15: $claims['age_over_15'] ?? null,
            ageOver21: $claims['age_over_21'] ?? null,
            ageInYears: isset($claims['age_in_years']) ? (int) $claims['age_in_years'] : null,
            gender: $claims['gender'] ?? null,
            address: isset($claims['address']) ? AddressModel::fromClaims($claims['address']) : null,
            issuingCountry: $claims['issuing_country'] ?? null,
            issuingAuthority: $claims['issuing_authority'] ?? null,
            issuanceDate: isset($claims['issuance_date']) ? new \DateTimeImmutable($claims['issuance_date']) : null,
            expiryDate: isset($claims['expiry_date']) ? new \DateTimeImmutable($claims['expiry_date']) : null,
            rawClaims: $claims,
        );
    }

    public function getFamilyName(): string
    {
        return $this->familyName;
    }

    public function getGivenName(): string
    {
        return $this->givenName;
    }

    public function getFullName(): string
    {
        return $this->givenName.' '.$this->familyName;
    }

    public function getBirthDate(): \DateTimeImmutable
    {
        return $this->birthDate;
    }

    public function getFamilyNameBirth(): ?string
    {
        return $this->familyNameBirth;
    }

    public function getGivenNameBirth(): ?string
    {
        return $this->givenNameBirth;
    }

    public function getBirthPlace(): ?string
    {
        return $this->birthPlace;
    }

    public function getNationality(): ?string
    {
        return $this->nationality;
    }

    public function isAgeOver18(): ?bool
    {
        return $this->ageOver18;
    }

    public function isAgeOver15(): ?bool
    {
        return $this->ageOver15;
    }

    public function isAgeOver21(): ?bool
    {
        return $this->ageOver21;
    }

    public function getAgeInYears(): ?int
    {
        return $this->ageInYears;
    }

    public function getGender(): ?string
    {
        return $this->gender;
    }

    public function getAddress(): ?AddressModel
    {
        return $this->address;
    }

    public function getIssuingCountry(): ?string
    {
        return $this->issuingCountry;
    }

    public function getIssuingAuthority(): ?string
    {
        return $this->issuingAuthority;
    }

    public function getIssuanceDate(): ?\DateTimeImmutable
    {
        return $this->issuanceDate;
    }

    public function getExpiryDate(): ?\DateTimeImmutable
    {
        return $this->expiryDate;
    }

    public function isExpired(): bool
    {
        if (null === $this->expiryDate) {
            return false;
        }

        return $this->expiryDate < new \DateTimeImmutable();
    }

    public function getClaim(string $name): mixed
    {
        return $this->rawClaims[$name] ?? null;
    }

    public function getRawClaims(): array
    {
        return $this->rawClaims;
    }
}
