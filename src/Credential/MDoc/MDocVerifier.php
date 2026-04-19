<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Credential\MDoc;

use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\StringStream;
use CBOR\Tag\TagManager;
use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Trust\JwksProviderInterface;
use Kimealabs\EudiWalletBundle\Trust\TrustedIssuersListProviderInterface;
use Kimealabs\EudiWalletBundle\Verifier\MDocVerifierInterface;

/**
 * Verifies ISO 18013-5 mDoc DeviceResponse tokens per the OpenID4VP mso_mdoc profile.
 *
 * DeviceResponse (CBOR):
 *   { "version", "documents": [{ "docType", "issuerSigned": { "nameSpaces", "issuerAuth": COSE_Sign1 } }] }
 *
 * COSE_Sign1 verification uses ES256 + OpenSSL — no extra dependency required.
 */
final class MDocVerifier implements MDocVerifierInterface
{
    public function __construct(
        private readonly TrustedIssuersListProviderInterface $trustedIssuers,
        private readonly JwksProviderInterface $jwksProvider,
    ) {
    }

    public function verify(string $deviceResponse, string $nonce, string $audience): VerifiedPresentation
    {
        $raw = base64_decode(strtr($deviceResponse, '-_', '+/'), true) ?: $deviceResponse;

        try {
            $cbor = $this->decode($raw);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Cannot decode mDoc CBOR: %s', $e->getMessage()));
        }

        if (!$cbor instanceof MapObject) {
            throw InvalidVpTokenException::malformed('DeviceResponse must be a CBOR map.');
        }

        $dr = $cbor->normalize();

        if (!\is_array($dr['documents'] ?? null) || [] === $dr['documents']) {
            throw InvalidVpTokenException::malformed('DeviceResponse missing or empty "documents".');
        }

        // Work with the first document
        $doc = $dr['documents'][0];

        $docType = $doc['docType'] ?? throw InvalidVpTokenException::malformed('Missing "docType".');
        $issuerSigned = $doc['issuerSigned'] ?? throw InvalidVpTokenException::malformed('Missing "issuerSigned".');

        // issuerAuth normalized: [protected_bytes, unprotected_array, payload_bytes, signature_bytes]
        $issuerAuth = $issuerSigned['issuerAuth'] ?? throw InvalidVpTokenException::malformed('Missing "issuerAuth".');

        if (!\is_array($issuerAuth) || \count($issuerAuth) < 4) {
            throw InvalidVpTokenException::malformed('COSE_Sign1 must have 4 elements.');
        }

        [$protectedBytes, , $payloadBytes, $signatureBytes] = $issuerAuth;

        if (!\is_string($protectedBytes) || !\is_string($payloadBytes) || !\is_string($signatureBytes)) {
            throw InvalidVpTokenException::malformed('COSE_Sign1 elements must be byte strings.');
        }

        // Decode MSO payload (Mobile Security Object)
        try {
            $msoCbor = $this->decode($payloadBytes);
        } catch (\Throwable $e) {
            throw InvalidVpTokenException::malformed(\sprintf('Cannot decode MSO: %s', $e->getMessage()));
        }

        if (!$msoCbor instanceof MapObject) {
            throw InvalidVpTokenException::malformed('MSO must be a CBOR map.');
        }

        $mso = $msoCbor->normalize();
        $issuer = $mso['issuer'] ?? throw InvalidVpTokenException::malformed('Missing "issuer" in MSO.');

        if (!\is_string($issuer)) {
            throw InvalidVpTokenException::malformed('MSO "issuer" must be a string.');
        }

        // Fetch issuer JWKS and verify COSE_Sign1 signature
        $jwksData = $this->jwksProvider->getJwks($issuer);

        if (!isset($jwksData['keys']) || !\is_array($jwksData['keys'])) {
            throw InvalidVpTokenException::malformed(\sprintf('No keys found in JWKS for issuer "%s".', $issuer));
        }

        $sigStructure = $this->buildSigStructure($protectedBytes, $payloadBytes);
        $verified = false;

        foreach ($jwksData['keys'] as $jwk) {
            if ($this->verifyEs256($sigStructure, $signatureBytes, $jwk)) {
                $verified = true;
                break;
            }
        }

        if (!$verified) {
            throw InvalidVpTokenException::invalidSignature();
        }

        $this->trustedIssuers->assertTrusted($issuer);

        $claims = $this->extractClaims($issuerSigned['nameSpaces'] ?? [], $mso);
        $claims['docType'] = (string) $docType;

        return new VerifiedPresentation('mso_mdoc', $claims, $issuer);
    }

    /**
     * Build COSE Sig_Structure for ES256 verification.
     * Sig_Structure = CBOR(["Signature1", protected_header_bstr, external_aad_bstr(empty), payload_bstr]).
     */
    private function buildSigStructure(string $protectedBytes, string $payloadBytes): string
    {
        return pack('C', 0x84)
            .$this->cborText('Signature1')
            .$this->cborBstr($protectedBytes)
            .$this->cborBstr('')
            .$this->cborBstr($payloadBytes);
    }

    /** Verify an ES256 COSE signature (raw r||s 64 bytes) against a JWK EC P-256 public key. */
    private function verifyEs256(string $data, string $rawSignature, array $jwk): bool
    {
        if (($jwk['kty'] ?? '') !== 'EC' || ($jwk['crv'] ?? '') !== 'P-256') {
            return false;
        }

        if (!isset($jwk['x'], $jwk['y'])) {
            return false;
        }

        $x = base64_decode(strtr($jwk['x'], '-_', '+/'), true);
        $y = base64_decode(strtr($jwk['y'], '-_', '+/'), true);

        if (false === $x || false === $y || 32 !== \strlen($x) || 32 !== \strlen($y)) {
            return false;
        }

        // Build DER SubjectPublicKeyInfo for P-256
        $point = "\x04".$x.$y;
        $oid = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
        $bitString = "\x03".$this->derLen(\strlen($point) + 1)."\x00".$point;
        $spki = "\x30".$this->derLen(\strlen($oid) + \strlen($bitString)).$oid.$bitString;

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($spki), 64, "\n")
            ."-----END PUBLIC KEY-----\n";

        $pubKey = openssl_pkey_get_public($pem);
        if (false === $pubKey) {
            return false;
        }

        if (64 !== \strlen($rawSignature)) {
            return false;
        }

        $r = substr($rawSignature, 0, 32);
        $s = substr($rawSignature, 32, 32);

        return 1 === openssl_verify($data, $this->rawToDer($r, $s), $pubKey, \OPENSSL_ALGO_SHA256);
    }

    /** Convert raw r||s ECDSA bytes to DER-encoded ECDSA-Sig-Value. */
    private function rawToDer(string $r, string $s): string
    {
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if (\ord($r[0]) > 0x7F) {
            $r = "\x00".$r;
        }
        if (\ord($s[0]) > 0x7F) {
            $s = "\x00".$s;
        }

        $rDer = "\x02".\chr(\strlen($r)).$r;
        $sDer = "\x02".\chr(\strlen($s)).$s;

        return "\x30".\chr(\strlen($rDer) + \strlen($sDer)).$rDer.$sDer;
    }

    private function derLen(int $len): string
    {
        if ($len < 0x80) {
            return \chr($len);
        }
        if ($len < 0x100) {
            return "\x81".\chr($len);
        }

        return "\x82".\chr($len >> 8).\chr($len & 0xFF);
    }

    /**
     * Extract claims from IssuerNameSpaces, verifying digests against MSO.
     * Each item is a CBOR byte string encoding an IssuerSignedItem map.
     *
     * @param array<string, mixed> $nameSpaces normalized nameSpaces map
     * @param array<string, mixed> $mso        normalized MSO
     *
     * @return array<string, mixed>
     */
    private function extractClaims(array $nameSpaces, array $mso): array
    {
        $claims = [];
        $valueDigests = \is_array($mso['valueDigests'] ?? null) ? $mso['valueDigests'] : [];
        $digestAlg = $this->normalizeHashAlgo((string) ($mso['digestAlgorithm'] ?? 'SHA-256'));

        foreach ($nameSpaces as $ns => $items) {
            if (!\is_array($items)) {
                continue;
            }

            foreach ($items as $itemBytes) {
                if (!\is_string($itemBytes) || '' === $itemBytes) {
                    continue;
                }

                try {
                    $itemCbor = $this->decode($itemBytes);
                } catch (\Throwable) {
                    continue;
                }

                if (!$itemCbor instanceof MapObject) {
                    continue;
                }

                $item = $itemCbor->normalize();
                $digestId = $item['digestID'] ?? null;
                $elementId = $item['elementIdentifier'] ?? null;
                $elementValue = $item['elementValue'] ?? null;

                if (null === $elementId || null === $elementValue) {
                    continue;
                }

                // Verify digest against MSO if available
                $nsKey = (string) $ns;
                if (isset($valueDigests[$nsKey][$digestId])) {
                    $expectedDigest = $valueDigests[$nsKey][$digestId];
                    $actualDigest = hash($digestAlg, $itemBytes, true);
                    if (!\is_string($expectedDigest) || !hash_equals($expectedDigest, $actualDigest)) {
                        continue;
                    }
                }

                $claims[(string) $elementId] = $elementValue;
            }
        }

        return $claims;
    }

    private function decode(string $bytes): \CBOR\CBORObject
    {
        return (new Decoder(new TagManager(), new OtherObjectManager()))
            ->decode(StringStream::create($bytes));
    }

    private function normalizeHashAlgo(string $alg): string
    {
        return match (strtolower($alg)) {
            'sha-256' => 'sha256',
            'sha-384' => 'sha384',
            'sha-512' => 'sha512',
            default => 'sha256',
        };
    }

    private function cborText(string $text): string
    {
        $len = \strlen($text);
        if ($len < 24) {
            return \chr(0x60 | $len).$text;
        }

        return \chr(0x78).\chr($len).$text;
    }

    private function cborBstr(string $bytes): string
    {
        $len = \strlen($bytes);
        if ($len < 24) {
            return \chr(0x40 | $len).$bytes;
        }
        if ($len < 0x100) {
            return \chr(0x58).\chr($len).$bytes;
        }
        if ($len < 0x10000) {
            return \chr(0x59).\chr($len >> 8).\chr($len & 0xFF).$bytes;
        }

        return \chr(0x5A).pack('N', $len).$bytes;
    }
}
