<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Security;

use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Security\EudiWalletUser;
use Kimealabs\EudiWalletBundle\Security\EudiWalletUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class EudiWalletUserProviderTest extends TestCase
{
    private EudiWalletUserProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new EudiWalletUserProvider();
    }

    public function testSupportsEudiWalletUserClass(): void
    {
        $this->assertTrue($this->provider->supportsClass(EudiWalletUser::class));
    }

    public function testDoesNotSupportOtherClasses(): void
    {
        $this->assertFalse($this->provider->supportsClass(\stdClass::class));
    }

    public function testRefreshUserReturnsTheSameEudiWalletUser(): void
    {
        $presentation = new VerifiedPresentation('vc+sd-jwt', ['sub' => 'user-abc'], 'https://issuer.example.com');
        $user = EudiWalletUser::fromPresentation($presentation);

        $refreshed = $this->provider->refreshUser($user);

        $this->assertSame($user, $refreshed);
    }

    public function testRefreshUserThrowsForUnsupportedUserType(): void
    {
        $unsupported = $this->createMock(\Symfony\Component\Security\Core\User\UserInterface::class);

        $this->expectException(UnsupportedUserException::class);

        $this->provider->refreshUser($unsupported);
    }

    public function testLoadUserByIdentifierThrowsUserNotFoundException(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->provider->loadUserByIdentifier('any-identifier');
    }
}
