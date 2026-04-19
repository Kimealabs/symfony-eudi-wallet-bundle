<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\RelyingParty;

use Kimealabs\EudiWalletBundle\Nonce\NonceManagerInterface;

/**
 * Builds OpenID4VP Authorization Requests for the Relying Party.
 */
final class PresentationRequestBuilder
{
    public function __construct(
        private readonly NonceManagerInterface $nonceManager,
        private readonly string $clientId,
        private readonly string $redirectUri,
    ) {
    }

    /**
     * Build a request asking for PID attributes.
     *
     * @param string[] $attributes The PID attributes to request (e.g. ['family_name', 'age_over_18'])
     */
    public function buildPidRequest(array $attributes = ['family_name', 'given_name', 'birth_date']): PresentationRequest
    {
        $definition = PresentationDefinition::create()
            ->requestPid($attributes);

        return $this->build($definition);
    }

    /**
     * Build a request from a custom PresentationDefinition.
     */
    public function build(PresentationDefinition $definition): PresentationRequest
    {
        $nonce = $this->nonceManager->generate();
        $state = bin2hex(random_bytes(16));

        return new PresentationRequest(
            nonce: $nonce,
            state: $state,
            clientId: $this->clientId,
            redirectUri: $this->redirectUri,
            presentationDefinition: $definition,
            createdAt: new \DateTimeImmutable(),
        );
    }
}
