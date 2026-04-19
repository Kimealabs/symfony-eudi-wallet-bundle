<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\RelyingParty;

use Kimealabs\EudiWalletBundle\Nonce\NonceManagerInterface;
use Kimealabs\EudiWalletBundle\RelyingParty\PresentationDefinition;
use Kimealabs\EudiWalletBundle\RelyingParty\PresentationRequest;
use Kimealabs\EudiWalletBundle\RelyingParty\PresentationRequestBuilder;
use PHPUnit\Framework\TestCase;

final class PresentationRequestBuilderTest extends TestCase
{
    private NonceManagerInterface $nonceManager;
    private PresentationRequestBuilder $builder;

    protected function setUp(): void
    {
        $this->nonceManager = $this->createMock(NonceManagerInterface::class);
        $this->builder = new PresentationRequestBuilder(
            nonceManager: $this->nonceManager,
            clientId: 'https://rp.example.com',
            redirectUri: 'https://rp.example.com/wallet/callback',
        );
    }

    public function testBuildReturnsAPresentationRequest(): void
    {
        $this->nonceManager->method('generate')->willReturn('abc123');

        $definition = PresentationDefinition::create()->requestPid(['family_name', 'given_name']);
        $request = $this->builder->build($definition);

        $this->assertInstanceOf(PresentationRequest::class, $request);
        $this->assertSame('abc123', $request->getNonce());
        $this->assertSame('https://rp.example.com', $request->getClientId());
        $this->assertSame('https://rp.example.com/wallet/callback', $request->getRedirectUri());
    }

    public function testBuildPidRequestUsesDefaultAttributes(): void
    {
        $this->nonceManager->method('generate')->willReturn('nonce1');

        $request = $this->builder->buildPidRequest();

        $params = $request->toQueryParams();
        $definition = json_decode($params['presentation_definition'], true);

        $fields = $definition['input_descriptors'][0]['constraints']['fields'];
        $paths = array_column($fields, 'path');
        $paths = array_merge(...$paths);

        $this->assertContains('$.family_name', $paths);
        $this->assertContains('$.given_name', $paths);
        $this->assertContains('$.birth_date', $paths);
    }

    public function testBuildPidRequestWithCustomAttributes(): void
    {
        $this->nonceManager->method('generate')->willReturn('nonce2');

        $request = $this->builder->buildPidRequest(['age_over_18']);

        $params = $request->toQueryParams();
        $definition = json_decode($params['presentation_definition'], true);

        $fields = $definition['input_descriptors'][0]['constraints']['fields'];
        $paths = array_merge(...array_column($fields, 'path'));

        $this->assertContains('$.age_over_18', $paths);
    }

    public function testEachBuildGeneratesUniqueState(): void
    {
        $this->nonceManager->method('generate')->willReturn('same-nonce');

        $r1 = $this->builder->buildPidRequest();
        $r2 = $this->builder->buildPidRequest();

        $this->assertNotSame($r1->getState(), $r2->getState());
    }

    public function testToQueryParamsContainsRequiredOpenId4VpFields(): void
    {
        $this->nonceManager->method('generate')->willReturn('mynonce');

        $request = $this->builder->buildPidRequest();
        $params = $request->toQueryParams();

        $this->assertSame('vp_token', $params['response_type']);
        $this->assertSame('direct_post', $params['response_mode']);
        $this->assertSame('https://rp.example.com', $params['client_id']);
        $this->assertSame('https://rp.example.com/wallet/callback', $params['response_uri']);
        $this->assertSame('mynonce', $params['nonce']);
    }

    public function testToDeeplinkReturnsOpenId4VpScheme(): void
    {
        $this->nonceManager->method('generate')->willReturn('n');

        $request = $this->builder->buildPidRequest();

        $this->assertStringStartsWith('openid4vp://authorize?', $request->toDeeplink());
    }
}
