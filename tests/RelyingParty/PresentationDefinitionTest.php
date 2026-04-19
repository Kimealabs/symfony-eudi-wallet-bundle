<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\RelyingParty;

use Kimealabs\EudiWalletBundle\RelyingParty\PresentationDefinition;
use PHPUnit\Framework\TestCase;

final class PresentationDefinitionTest extends TestCase
{
    public function testCreateGeneratesUniqueId(): void
    {
        $def1 = PresentationDefinition::create();
        $def2 = PresentationDefinition::create();

        $this->assertNotSame($def1->getId(), $def2->getId());
    }

    public function testCreateWithCustomId(): void
    {
        $def = PresentationDefinition::create('my-custom-id');

        $this->assertSame('my-custom-id', $def->getId());
    }

    public function testRequestPidBuildsCorrectDescriptor(): void
    {
        $def = PresentationDefinition::create('test')
            ->requestPid(['family_name', 'age_over_18']);

        $array = $def->toArray();

        $this->assertSame('test', $array['id']);
        $this->assertCount(1, $array['input_descriptors']);

        $descriptor = $array['input_descriptors'][0];
        $this->assertSame('eu.europa.ec.eudi.pid.1', $descriptor['id']);
        $this->assertSame('required', $descriptor['constraints']['limit_disclosure']);
        $this->assertCount(2, $descriptor['constraints']['fields']);
        $this->assertSame(['$.family_name'], $descriptor['constraints']['fields'][0]['path']);
        $this->assertSame(['$.age_over_18'], $descriptor['constraints']['fields'][1]['path']);
    }

    public function testRequestCustomCredential(): void
    {
        $def = PresentationDefinition::create('test')
            ->requestCredential('my.credential.1', 'MyCredential', ['degree', 'institution']);

        $array = $def->toArray();
        $descriptor = $array['input_descriptors'][0];

        $this->assertSame('my.credential.1', $descriptor['id']);
        $this->assertCount(2, $descriptor['constraints']['fields']);
    }
}
