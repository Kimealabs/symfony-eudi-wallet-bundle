<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Model;

use Kimealabs\EudiWalletBundle\Model\PidIdentity;
use PHPUnit\Framework\TestCase;

final class PidIdentityTest extends TestCase
{
    public function testFromClaimsWithMinimalData(): void
    {
        $claims = [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
        ];

        $identity = PidIdentity::fromClaims($claims);

        $this->assertSame('Dupont', $identity->getFamilyName());
        $this->assertSame('Jean', $identity->getGivenName());
        $this->assertSame('Jean Dupont', $identity->getFullName());
        $this->assertSame('1985-03-15', $identity->getBirthDate()->format('Y-m-d'));
        $this->assertNull($identity->isAgeOver18());
        $this->assertNull($identity->getNationality());
    }

    public function testFromClaimsWithFullData(): void
    {
        $claims = [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
            'age_over_18' => true,
            'age_over_15' => true,
            'age_in_years' => 40,
            'nationality' => 'FR',
            'issuing_country' => 'FR',
            'issuing_authority' => 'Ministère de l\'Intérieur',
            'expiry_date' => '2030-01-01',
        ];

        $identity = PidIdentity::fromClaims($claims);

        $this->assertTrue($identity->isAgeOver18());
        $this->assertTrue($identity->isAgeOver15());
        $this->assertSame(40, $identity->getAgeInYears());
        $this->assertSame('FR', $identity->getNationality());
        $this->assertSame('FR', $identity->getIssuingCountry());
        $this->assertFalse($identity->isExpired());
    }

    public function testIsExpiredReturnsFalseWhenNoExpiryDate(): void
    {
        $claims = [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
        ];

        $identity = PidIdentity::fromClaims($claims);

        $this->assertFalse($identity->isExpired());
    }

    public function testIsExpiredReturnsTrueForPastDate(): void
    {
        $claims = [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
            'expiry_date' => '2000-01-01',
        ];

        $identity = PidIdentity::fromClaims($claims);

        $this->assertTrue($identity->isExpired());
    }

    public function testFromClaimsThrowsOnMissingFamilyName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing claim: family_name');

        PidIdentity::fromClaims([
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
        ]);
    }

    public function testFromClaimsThrowsOnMissingBirthDate(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing claim: birth_date');

        PidIdentity::fromClaims([
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
        ]);
    }

    public function testGetRawClaims(): void
    {
        $claims = [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
            'birth_date' => '1985-03-15',
            'custom_claim' => 'custom_value',
        ];

        $identity = PidIdentity::fromClaims($claims);

        $this->assertSame('custom_value', $identity->getClaim('custom_claim'));
        $this->assertNull($identity->getClaim('nonexistent'));
        $this->assertSame($claims, $identity->getRawClaims());
    }
}
