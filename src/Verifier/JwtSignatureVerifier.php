<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Verifier;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Trust\JwksProviderInterface;

/**
 * Verifies the cryptographic signature of a JWT using the issuer's JWKS.
 * Supports ES256, ES384, ES512, RS256, RS384, RS512.
 */
final class JwtSignatureVerifier implements JwtSignatureVerifierInterface
{
    private readonly JWSVerifier $jwsVerifier;
    private readonly JWSSerializerManager $serializerManager;

    public function __construct(
        private readonly JwksProviderInterface $jwksProvider,
    ) {
        $algorithmManager = new AlgorithmManager([
            new ES256(),
            new ES384(),
            new ES512(),
            new RS256(),
            new RS384(),
            new RS512(),
        ]);

        $this->jwsVerifier = new JWSVerifier($algorithmManager);
        $this->serializerManager = new JWSSerializerManager([new CompactSerializer()]);
    }

    /**
     * Verify the signature of a compact JWT using a single raw JWK array (e.g. from a cnf claim).
     *
     * @throws InvalidVpTokenException if the signature is invalid
     */
    public function verifyWithJwk(string $jwt, array $jwkData): void
    {
        try {
            $jws = $this->serializerManager->unserialize($jwt);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Cannot deserialize JWT: %s', $e->getMessage()));
        }

        try {
            $jwk = new \Jose\Component\Core\JWK($jwkData);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Invalid JWK in cnf claim: %s', $e->getMessage()));
        }

        try {
            $verified = $this->jwsVerifier->verifyWithKey($jws, $jwk, 0);
        } catch (\Throwable) {
            $verified = false;
        }

        if (!$verified) {
            throw InvalidVpTokenException::invalidSignature();
        }
    }

    /**
     * Verify the signature of a compact JWT using the issuer's public JWKS.
     *
     * @throws InvalidVpTokenException if the signature is invalid
     */
    public function verify(string $jwt, string $issuer): void
    {
        try {
            $jws = $this->serializerManager->unserialize($jwt);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Cannot deserialize JWT: %s', $e->getMessage()));
        }

        $jwksData = $this->jwksProvider->getJwks($issuer);

        try {
            $jwkSet = JWKSet::createFromKeyData($jwksData);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Invalid JWKS for issuer "%s": %s', $issuer, $e->getMessage()));
        }

        $verified = false;
        foreach ($jwkSet->all() as $jwk) {
            try {
                if ($this->jwsVerifier->verifyWithKey($jws, $jwk, 0)) {
                    $verified = true;
                    break;
                }
            } catch (\Throwable) {
                // Try next key
            }
        }

        if (!$verified) {
            throw InvalidVpTokenException::invalidSignature();
        }
    }
}
