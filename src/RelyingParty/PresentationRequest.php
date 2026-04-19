<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\RelyingParty;

/**
 * Represents a generated OpenID4VP Authorization Request.
 * Contains all the data needed to display a QR code or deeplink to the user.
 */
final class PresentationRequest
{
    public function __construct(
        private readonly string $nonce,
        private readonly string $state,
        private readonly string $clientId,
        private readonly string $redirectUri,
        private readonly PresentationDefinition $presentationDefinition,
        private readonly \DateTimeImmutable $createdAt,
    ) {
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    public function getPresentationDefinition(): PresentationDefinition
    {
        return $this->presentationDefinition;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    /**
     * Returns the full OpenID4VP Authorization Request as a query string.
     * Used to build the QR code or deeplink.
     */
    public function toQueryParams(): array
    {
        return [
            'response_type' => 'vp_token',
            'response_mode' => 'direct_post',
            'client_id' => $this->clientId,
            'response_uri' => $this->redirectUri,
            'nonce' => $this->nonce,
            'state' => $this->state,
            'presentation_definition' => json_encode($this->presentationDefinition->toArray()),
        ];
    }

    /**
     * Returns the openid4vp:// deeplink for same-device flow.
     */
    public function toDeeplink(): string
    {
        return 'openid4vp://authorize?'.http_build_query($this->toQueryParams());
    }

    /**
     * Returns the HTTPS authorization request URI for cross-device (QR code) flow.
     */
    public function toRequestUri(): string
    {
        return $this->clientId.'/wallet/request?'.http_build_query($this->toQueryParams());
    }

    /**
     * Returns a data URI (data:image/png;base64,...) PNG QR code for the cross-device flow.
     */
    public function toQrCodeData(): string
    {
        $writer = new \Endroid\QrCode\Writer\PngWriter();
        $result = $writer->write(
            \Endroid\QrCode\QrCode::create($this->toDeeplink())
                ->setSize(300)
                ->setMargin(10),
        );

        return $result->getDataUri();
    }
}
