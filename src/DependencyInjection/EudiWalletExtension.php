<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

final class EudiWalletExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../../config'));
        $loader->load('services.yaml');

        $rp = $config['relying_party'];
        $container->setParameter('eudi_wallet.relying_party.client_id', $rp['client_id']);
        $container->setParameter('eudi_wallet.relying_party.redirect_uri', $rp['redirect_uri']);
        $container->setParameter('eudi_wallet.relying_party.certificate_path', $rp['certificate_path']);
        $container->setParameter('eudi_wallet.relying_party.callback_path', $rp['callback_path']);
        $container->setParameter('eudi_wallet.relying_party.login_path', $rp['login_path']);
        $container->setParameter('eudi_wallet.trusted_issuers_list_uri', $config['trusted_issuers_list_uri']);
        $container->setParameter('eudi_wallet.nonce_ttl', $config['nonce_ttl']);
    }

    public function getAlias(): string
    {
        return 'eudi_wallet';
    }
}
