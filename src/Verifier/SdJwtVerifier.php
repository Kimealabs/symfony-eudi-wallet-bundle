<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Exception\PresentationVerificationException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Trust\TrustedIssuersListProviderInterface;

/**
 * Verifies SD-JWT Verifiable Presentations as defined in the OpenID4VP + SD-JWT VC spec.
 *
 * SD-JWT format: <issuer-signed-jwt>~<disclosure1>~<disclosure2>~[<kb-jwt>]
 */
final class SdJwtVerifier implements SdJwtVerifierInterface
{
    public function __construct(
        private readonly TrustedIssuersListProviderInterface $trustedIssuers,
        private readonly JwtSignatureVerifierInterface $signatureVerifier,
    ) {
    }

    /**
     * Verify an SD-JWT VP token and return the disclosed claims.
     *
     * @throws InvalidVpTokenException
     * @throws PresentationVerificationException
     */
    public function verify(string $sdJwt, string $expectedNonce, string $expectedAudience): VerifiedPresentation
    {
        // SD-JWT format: <issuer-signed-jwt>~[<disclosure>~]*[<kb-jwt>]
        // Trailing ~ before KB-JWT is significant for sd_hash computation
        $hasTrailingTilde = str_ends_with($sdJwt, '~');
        $parts = explode('~', $sdJwt);

        // Remove trailing empty string from trailing ~
        if ($hasTrailingTilde && '' === end($parts)) {
            array_pop($parts);
        }

        if (\count($parts) < 1 || empty($parts[0])) {
            throw InvalidVpTokenException::malformed('SD-JWT must contain at least the issuer-signed JWT.');
        }

        $issuerSignedJwt = $parts[0];
        $disclosures = \array_slice($parts, 1);

        // Remove optional key-binding JWT (last element if it looks like a JWT and no trailing ~)
        $kbJwt = null;
        if (!$hasTrailingTilde && !empty($disclosures)) {
            $last = end($disclosures);
            if ($this->isJwt($last)) {
                $kbJwt = $last;
                array_pop($disclosures);
            }
        }

        // Raw SD-JWT without KB-JWT (used for sd_hash computation)
        $rawSdJwtWithoutKb = $issuerSignedJwt.'~'.implode('~', $disclosures).'~';

        $payload = $this->decodeJwtPayload($issuerSignedJwt);

        $this->validatePayload($payload, $expectedNonce, $expectedAudience);

        $issuer = $payload['iss'] ?? throw InvalidVpTokenException::malformed('Missing "iss" claim.');

        $this->trustedIssuers->assertTrusted($issuer);
        $this->signatureVerifier->verify($issuerSignedJwt, $issuer);

        if (null !== $kbJwt) {
            $this->validateKbJwt($kbJwt, $payload, $rawSdJwtWithoutKb, $expectedNonce, $expectedAudience);
        }

        $disclosedClaims = $this->reconstructClaims($payload, $disclosures);

        $pidIdentity = null;
        $credentialType = $payload['vct'] ?? null;
        if ($credentialType && str_contains($credentialType, 'pid')) {
            try {
                $pidIdentity = \Kimealabs\EudiWalletBundle\Model\PidIdentity::fromClaims($disclosedClaims);
            } catch (\InvalidArgumentException) {
                // Not all PID claims were disclosed — that's valid (selective disclosure)
            }
        }

        return new VerifiedPresentation(
            format: 'vc+sd-jwt',
            claims: $disclosedClaims,
            issuer: $issuer,
            pidIdentity: $pidIdentity,
            disclosedAttributes: array_keys($disclosedClaims),
        );
    }

    private function validatePayload(array $payload, string $expectedNonce, string $expectedAudience): void
    {
        $now = time();

        if (isset($payload['exp']) && $payload['exp'] < $now) {
            throw PresentationVerificationException::expiredCredential();
        }

        if (isset($payload['nbf']) && $payload['nbf'] > $now) {
            throw InvalidVpTokenException::malformed('Credential is not yet valid (nbf).');
        }

        $nonce = $payload['nonce'] ?? null;
        if (null === $nonce || $nonce !== $expectedNonce) {
            throw InvalidVpTokenException::malformed('Nonce mismatch in SD-JWT payload.');
        }

        $aud = $payload['aud'] ?? null;
        if (null !== $aud) {
            $audiences = \is_array($aud) ? $aud : [$aud];
            if (!\in_array($expectedAudience, $audiences, true)) {
                throw InvalidVpTokenException::malformed('Audience mismatch in SD-JWT payload.');
            }
        }
    }

    /**
     * Reconstruct disclosed claims by matching _sd hashes to disclosure values.
     */
    private function reconstructClaims(array $payload, array $disclosures): array
    {
        $sdAlg = $payload['_sd_alg'] ?? 'sha-256';
        $hashAlgo = $this->normalizeHashAlgo($sdAlg);

        $disclosureMap = [];
        foreach ($disclosures as $disclosure) {
            $hash = base64_encode(hash($hashAlgo, $disclosure, true));
            $decoded = json_decode(base64_decode(strtr($disclosure, '-_', '+/')), true);
            if (\is_array($decoded) && \count($decoded) >= 3) {
                $disclosureMap[$hash] = [$decoded[1], $decoded[2]]; // [claim_name, claim_value]
            }
        }

        $claims = [];

        foreach ($payload as $key => $value) {
            if ('_sd' === $key || '_sd_alg' === $key || str_starts_with($key, '_')) {
                continue;
            }
            $claims[$key] = $value;
        }

        if (isset($payload['_sd']) && \is_array($payload['_sd'])) {
            foreach ($payload['_sd'] as $sdHash) {
                if (isset($disclosureMap[$sdHash])) {
                    [$name, $val] = $disclosureMap[$sdHash];
                    $claims[$name] = $val;
                }
            }
        }

        return $claims;
    }

    private function validateKbJwt(string $kbJwt, array $issuerPayload, string $rawSdJwtWithoutKb, string $expectedNonce, string $expectedAudience): void
    {
        $header = $this->decodeJwtHeader($kbJwt);
        $payload = $this->decodeJwtPayload($kbJwt);

        if (($header['typ'] ?? '') !== 'kb+jwt') {
            throw InvalidVpTokenException::malformed('KB-JWT must have typ "kb+jwt".');
        }

        if (($payload['nonce'] ?? null) !== $expectedNonce) {
            throw InvalidVpTokenException::malformed('KB-JWT nonce mismatch.');
        }

        $aud = $payload['aud'] ?? null;
        if (null === $aud) {
            throw InvalidVpTokenException::malformed('KB-JWT missing "aud" claim.');
        }
        $audiences = \is_array($aud) ? $aud : [$aud];
        if (!\in_array($expectedAudience, $audiences, true)) {
            throw InvalidVpTokenException::malformed('KB-JWT audience mismatch.');
        }

        $iat = $payload['iat'] ?? null;
        if (null === $iat || (time() - (int) $iat) > 300) {
            throw InvalidVpTokenException::malformed('KB-JWT is missing or too old (iat).');
        }

        $sdAlg = $issuerPayload['_sd_alg'] ?? 'sha-256';
        $hashAlgo = $this->normalizeHashAlgo($sdAlg);
        $expectedSdHash = rtrim(strtr(base64_encode(hash($hashAlgo, $rawSdJwtWithoutKb, true)), '+/', '-_'), '=');

        if (($payload['sd_hash'] ?? null) !== $expectedSdHash) {
            throw InvalidVpTokenException::malformed('KB-JWT sd_hash mismatch.');
        }

        $cnfJwk = $issuerPayload['cnf']['jwk'] ?? null;
        if (null !== $cnfJwk) {
            $this->signatureVerifier->verifyWithJwk($kbJwt, $cnfJwk);
        }
    }

    private function decodeJwtHeader(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (3 !== \count($parts)) {
            throw InvalidVpTokenException::malformed('JWT must have 3 parts.');
        }

        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);

        if (!\is_array($header)) {
            throw InvalidVpTokenException::malformed('JWT header is not valid JSON.');
        }

        return $header;
    }

    private function decodeJwtPayload(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (3 !== \count($parts)) {
            throw InvalidVpTokenException::malformed('Issuer-signed JWT must have 3 parts.');
        }

        $payload = json_decode(
            base64_decode(strtr($parts[1], '-_', '+/')),
            true
        );

        if (!\is_array($payload)) {
            throw InvalidVpTokenException::malformed('JWT payload is not valid JSON.');
        }

        return $payload;
    }

    private function isJwt(string $value): bool
    {
        return 2 === substr_count($value, '.');
    }

    private function normalizeHashAlgo(string $sdAlg): string
    {
        return match (strtolower($sdAlg)) {
            'sha-256' => 'sha256',
            'sha-384' => 'sha384',
            'sha-512' => 'sha512',
            default => 'sha256',
        };
    }
}
