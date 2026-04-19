<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Nonce\NonceManagerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Entry point for VP token verification.
 * Handles the direct_post callback from the wallet, dispatches to the appropriate format verifier.
 */
final class VpTokenVerifier implements VpTokenVerifierInterface
{
    public function __construct(
        private readonly NonceManagerInterface $nonceManager,
        private readonly SdJwtVerifierInterface $sdJwtVerifier,
        private readonly MDocVerifierInterface $mdocVerifier,
        private readonly string $clientId,
    ) {
    }

    /**
     * Verify the VP token from an incoming HTTP callback request (direct_post response_mode).
     *
     * @throws InvalidVpTokenException
     */
    public function verifyFromRequest(Request $request): VerifiedPresentation
    {
        $vpToken = $request->request->get('vp_token')
            ?? $request->query->get('vp_token');

        if (null === $vpToken || '' === $vpToken) {
            throw InvalidVpTokenException::missingToken();
        }

        $vpToken = (string) $vpToken;
        $format = $this->detectFormat($vpToken);

        // mDoc nonce is validated inside the DeviceAuth — consume session nonce and pass to verifier
        if ('mso_mdoc' === $format) {
            $nonce = $this->nonceManager->consume();

            return $this->mdocVerifier->verify($vpToken, $nonce, $this->clientId);
        }

        $nonce = $this->extractNonce($vpToken);
        $this->nonceManager->validate($nonce);

        return $this->verifyToken($vpToken, $nonce);
    }

    /**
     * Verify a raw VP token string directly.
     *
     * @throws InvalidVpTokenException
     */
    public function verify(string $vpToken, string $nonce): VerifiedPresentation
    {
        $this->nonceManager->validate($nonce);

        return $this->verifyToken($vpToken, $nonce);
    }

    private function verifyToken(string $vpToken, string $nonce): VerifiedPresentation
    {
        $format = $this->detectFormat($vpToken);

        return match ($format) {
            'vc+sd-jwt' => $this->sdJwtVerifier->verify($vpToken, $nonce, $this->clientId),
            'mso_mdoc' => $this->mdocVerifier->verify($vpToken, $nonce, $this->clientId),
            default => throw InvalidVpTokenException::malformed(\sprintf('Unsupported VP token format: %s', $format)),
        };
    }

    private function detectFormat(string $vpToken): string
    {
        // SD-JWT contains '~' separator
        if (str_contains($vpToken, '~')) {
            return 'vc+sd-jwt';
        }

        // CBOR-encoded mDoc starts with a specific byte sequence
        if ($this->looksLikeCbor($vpToken)) {
            return 'mso_mdoc';
        }

        // Plain JWT (3 base64url parts separated by '.')
        if (2 === substr_count($vpToken, '.')) {
            return 'jwt_vp';
        }

        throw InvalidVpTokenException::malformed('Cannot detect VP token format.');
    }

    private function extractNonce(string $vpToken): string
    {
        $parts = explode('~', $vpToken);
        $jwt = $parts[0];

        $jwtParts = explode('.', $jwt);
        if (\count($jwtParts) < 2) {
            throw InvalidVpTokenException::malformed('Cannot extract nonce: invalid JWT structure.');
        }

        $payload = json_decode(
            base64_decode(strtr($jwtParts[1], '-_', '+/')),
            true
        );

        if (!\is_array($payload) || !isset($payload['nonce'])) {
            throw InvalidVpTokenException::malformed('Cannot extract nonce from VP token payload.');
        }

        return (string) $payload['nonce'];
    }

    private function looksLikeCbor(string $data): bool
    {
        $decoded = base64_decode($data, true);
        if (false === $decoded) {
            return false;
        }

        // CBOR map starts with 0xa0-0xbf range
        return isset($decoded[0]) && (\ord($decoded[0]) & 0xE0) === 0xA0;
    }
}
