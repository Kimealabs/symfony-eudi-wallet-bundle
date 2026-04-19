<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Verifier;

use Kimealabs\EudiWalletBundle\Credential\MDoc\MDocVerifier;
use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Model\VerifiedPresentation;
use Kimealabs\EudiWalletBundle\Trust\JwksProviderInterface;
use Kimealabs\EudiWalletBundle\Trust\TrustedIssuersListProviderInterface;
use PHPUnit\Framework\TestCase;

final class MDocVerifierTest extends TestCase
{
    private TrustedIssuersListProviderInterface $trustedIssuers;
    private JwksProviderInterface $jwksProvider;
    private MDocVerifier $verifier;

    protected function setUp(): void
    {
        $this->trustedIssuers = $this->createMock(TrustedIssuersListProviderInterface::class);
        $this->jwksProvider = $this->createMock(JwksProviderInterface::class);
        $this->verifier = new MDocVerifier($this->trustedIssuers, $this->jwksProvider);
    }

    public function testVerifyThrowsOnMalformedCbor(): void
    {
        $this->expectException(InvalidVpTokenException::class);

        // Not valid CBOR
        $this->verifier->verify('not-valid-cbor-at-all!!!', 'nonce', 'audience');
    }

    public function testVerifyThrowsOnMissingDocuments(): void
    {
        // Valid CBOR map but missing "documents" key: {0: "1.0"}
        $cbor = "\xa1\x00\x63\x31\x2e\x30"; // {0: "1.0"}

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify(base64_encode($cbor), 'nonce', 'audience');
    }

    public function testVerifyThrowsOnEmptyDocuments(): void
    {
        // CBOR: {"version": "1.0", "documents": [], "status": 0}
        $cbor = $this->buildDeviceResponseCbor([]);

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify(base64_encode($cbor), 'nonce', 'audience');
    }

    public function testVerifySucceedsWithValidDeviceResponse(): void
    {
        [$privateKey, $publicJwk] = $this->generateEcKeyPair();

        $issuer = 'https://issuer.example.com';
        $nonce = 'test-nonce-123';
        $audience = 'https://rp.example.com';

        $this->trustedIssuers->method('assertTrusted');
        $this->jwksProvider->method('getJwks')->willReturn(['keys' => [$publicJwk]]);

        $deviceResponse = $this->buildSignedDeviceResponse($privateKey, $issuer, $nonce, [
            'family_name' => 'Dupont',
            'given_name' => 'Jean',
        ]);

        $result = $this->verifier->verify(base64_encode($deviceResponse), $nonce, $audience);

        $this->assertInstanceOf(VerifiedPresentation::class, $result);
        $this->assertSame('mso_mdoc', $result->getFormat());
        $this->assertSame($issuer, $result->getIssuer());
        $this->assertSame('Dupont', $result->getClaim('family_name'));
        $this->assertSame('Jean', $result->getClaim('given_name'));
    }

    public function testVerifyThrowsOnInvalidSignature(): void
    {
        [, $wrongJwk] = $this->generateEcKeyPair(); // different key pair

        $issuer = 'https://issuer.example.com';
        [$signingKey] = $this->generateEcKeyPair(); // sign with a different key

        $this->trustedIssuers->method('assertTrusted');
        $this->jwksProvider->method('getJwks')->willReturn(['keys' => [$wrongJwk]]);

        $deviceResponse = $this->buildSignedDeviceResponse($signingKey, $issuer, 'nonce', []);

        $this->expectException(InvalidVpTokenException::class);

        $this->verifier->verify(base64_encode($deviceResponse), 'nonce', 'https://rp.example.com');
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** @return array{0: \OpenSSLAsymmetricKey, 1: array<string, string>} */
    private function generateEcKeyPair(): array
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
        ]);

        $details = openssl_pkey_get_details($key);
        $ec = $details['ec'];

        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($ec['x']), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($ec['y']), '+/', '-_'), '='),
        ];

        return [$key, $jwk];
    }

    /**
     * Build a minimal but valid CBOR DeviceResponse with a real COSE_Sign1 issuerAuth.
     *
     * @param array<string, string> $claims
     */
    private function buildSignedDeviceResponse(\OpenSSLAsymmetricKey $key, string $issuer, string $nonce, array $claims): string
    {
        $docType = 'org.iso.18013.5.1.mDL';
        $namespace = 'org.iso.18013.5.1';

        // Build IssuerSignedItems CBOR list
        $itemsBytes = '';
        $digestId = 0;
        $itemBytesForDigest = [];

        foreach ($claims as $name => $value) {
            $item = $this->cborMap([
                'digestID' => $this->cborUint($digestId),
                'random' => $this->cborBstr(random_bytes(16)),
                'elementIdentifier' => $this->cborText($name),
                'elementValue' => $this->cborText($value),
            ]);
            $itemBytesForDigest[$digestId] = $item;
            // Each item is a CBOR bstr (tag 24 would be ideal but bstr works for our parser)
            $itemsBytes .= $this->cborBstr($item);
            ++$digestId;
        }

        // Build nameSpaces map: { namespace: [items] }
        $nameSpaceList = $this->cborArrayRaw($itemsBytes, \count($claims));
        $nameSpacesMap = $this->cborMap([$namespace => $nameSpaceList]);

        // Build MSO (Mobile Security Object) — the issuerAuth payload
        $valueDigests = [];
        foreach ($itemBytesForDigest as $id => $itemBytes) {
            $valueDigests[$id] = hash('sha256', $itemBytes, true);
        }

        $mso = $this->cborMap([
            'version' => $this->cborText('1.0'),
            'digestAlgorithm' => $this->cborText('SHA-256'),
            'valueDigests' => $this->cborMap([$namespace => $this->cborMapRaw($valueDigests)]),
            'docType' => $this->cborText($docType),
            'issuer' => $this->cborText($issuer),
            'validityInfo' => $this->cborMap([
                'signed' => $this->cborText((new \DateTimeImmutable())->format(\DateTimeInterface::ISO8601)),
            ]),
        ]);

        // Build COSE_Sign1 protected header: {1: -7} (alg: ES256)
        $protectedHeader = $this->cborMap([1 => $this->cborNegInt(7)]); // 1: -7 (ES256)

        // Build Sig_Structure for signing
        $sigStructure = pack('C', 0x84)
            .$this->cborText('Signature1')
            .$this->cborBstr($protectedHeader)
            .$this->cborBstr('')
            .$this->cborBstr($mso);

        // Sign with ES256 (SHA-256 + ECDSA)
        openssl_sign($sigStructure, $derSignature, $key, \OPENSSL_ALGO_SHA256);

        // Convert DER ECDSA signature to raw r||s (64 bytes)
        $rawSignature = $this->derToRawSignature($derSignature);

        // COSE_Sign1: [protected_bstr, {}, payload_bstr, signature_bstr]
        $issuerAuth = pack('C', 0x84)
            .$this->cborBstr($protectedHeader)
            .$this->cborMap([])           // empty unprotected header
            .$this->cborBstr($mso)
            .$this->cborBstr($rawSignature);

        // issuerSigned: { nameSpaces, issuerAuth }
        $issuerSigned = $this->cborMap([
            'nameSpaces' => $nameSpacesMap,
            'issuerAuth' => $issuerAuth,
        ]);

        // document: { docType, issuerSigned }
        $document = $this->cborMap([
            'docType' => $this->cborText($docType),
            'issuerSigned' => $issuerSigned,
        ]);

        // DeviceResponse: { version, documents: [document], status: 0 }
        $docArray = pack('C', 0x81).$document; // array(1)

        return $this->cborMap([
            'version' => $this->cborText('1.0'),
            'documents' => $docArray,
            'status' => $this->cborUint(0),
        ]);
    }

    private function buildDeviceResponseCbor(array $documents): string
    {
        $docsBytes = '';
        foreach ($documents as $doc) {
            $docsBytes .= $doc;
        }
        $docsArray = pack('C', 0x80 | \count($documents)).$docsBytes;

        return $this->cborMap([
            'version' => $this->cborText('1.0'),
            'documents' => $docsArray,
            'status' => $this->cborUint(0),
        ]);
    }

    private function derToRawSignature(string $der): string
    {
        // DER: 0x30 len 0x02 rlen r 0x02 slen s
        $offset = 2; // skip 0x30 and total length
        ++$offset; // skip 0x02
        $rLen = \ord($der[$offset++]);
        $r = substr($der, $offset, $rLen);
        $offset += $rLen;
        ++$offset; // skip 0x02
        $sLen = \ord($der[$offset++]);
        $s = substr($der, $offset, $sLen);

        // Pad/trim to 32 bytes each
        $r = str_pad(ltrim($r, "\x00"), 32, "\x00", \STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), 32, "\x00", \STR_PAD_LEFT);

        return $r.$s;
    }

    // Minimal CBOR encoding helpers for test fixtures

    private function cborMap(array $map): string
    {
        $count = \count($map);
        $result = $count < 24 ? \chr(0xA0 | $count) : \chr(0xB8).\chr($count);
        foreach ($map as $k => $v) {
            if (\is_int($k)) {
                $result .= $this->cborUint($k);
            } else {
                $result .= $this->cborText((string) $k);
            }
            $result .= \is_string($v) ? $v : $this->cborText((string) $v);
        }

        return $result;
    }

    /** @param array<int, string> $map */
    private function cborMapRaw(array $map): string
    {
        $count = \count($map);
        $result = $count < 24 ? \chr(0xA0 | $count) : \chr(0xB8).\chr($count);
        foreach ($map as $k => $v) {
            $result .= $this->cborUint($k);
            $result .= $this->cborBstr($v);
        }

        return $result;
    }

    private function cborArrayRaw(string $itemsBytes, int $count): string
    {
        return ($count < 24 ? \chr(0x80 | $count) : \chr(0x98).\chr($count)).$itemsBytes;
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

    private function cborUint(int $value): string
    {
        if ($value < 24) {
            return \chr($value);
        }
        if ($value < 0x100) {
            return \chr(0x18).\chr($value);
        }

        return \chr(0x19).\chr($value >> 8).\chr($value & 0xFF);
    }

    private function cborNegInt(int $n): string
    {
        // -1 - n encoded as major type 1
        return \chr(0x20 | ($n < 24 ? $n : 24)).($n >= 24 ? \chr($n) : '');
    }
}
