<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('eudi_wallet');
        $rootNode = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->arrayNode('relying_party')
                    ->isRequired()
                    ->children()
                        ->scalarNode('client_id')
                            ->info('Your Relying Party client_id (e.g. https://myservice.example.com)')
                            ->isRequired()
                            ->cannotBeEmpty()
                        ->end()
                        ->scalarNode('redirect_uri')
                            ->info('Full callback URI receiving the vp_token (e.g. https://myservice.example.com/wallet/callback)')
                            ->isRequired()
                            ->cannotBeEmpty()
                        ->end()
                        ->scalarNode('certificate_path')
                            ->info('Path to your RP certificate (.p12 or .pem) — required for production')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('callback_path')
                            ->info('Path (without domain) of the callback route')
                            ->defaultValue('/wallet/callback')
                        ->end()
                        ->scalarNode('login_path')
                            ->info('Path to redirect to on authentication failure')
                            ->defaultValue('/login')
                        ->end()
                    ->end()
                ->end()
                ->scalarNode('trusted_issuers_list_uri')
                    ->info('EU Trusted Issuers List endpoint')
                    ->defaultValue('https://verifier.eudiw.dev/trusted-issuers')
                ->end()
                ->integerNode('nonce_ttl')
                    ->info('Nonce TTL in seconds')
                    ->defaultValue(300)
                    ->min(60)
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
