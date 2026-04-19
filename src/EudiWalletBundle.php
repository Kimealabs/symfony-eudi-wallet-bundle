<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle;

use Kimealabs\EudiWalletBundle\DependencyInjection\EudiWalletExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class EudiWalletBundle extends AbstractBundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new EudiWalletExtension();
    }
}
