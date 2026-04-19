<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Tests\Verifier;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Kimealabs\EudiWalletBundle\Exception\InvalidVpTokenException;
use Kimealabs\EudiWalletBundle\Trust\JwksProviderInterface;
use Kimealabs\EudiWalletBundle\Verifier\JwtSignatureVerifier;
use PHPUnit\Framework\TestCase;

final class JwtSignatureVerifierTest extends TestCase
{
    private JWK $privateKey;
    private JWK $publicKey;
    private JwtSignatureVerifier $verifier;

    protected function setUp(): void
    {
        // Generate a fresh EC P-256 key pair for each test
        $keyPair = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
        ]);

        $details = openssl_pkey_get_details($keyPair);
        $ec = $details['ec'];

        $this->privateKey = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($ec['x']), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($ec['y']), '+/', '-_'), '='),
            'd' => rtrim(strtr(base64_encode($ec['d']), '+/', '-_'), '='),
        ]);

        $this->publicKey = $this->privateKey->toPublic();

        $jwksProvider = $this->createMock(JwksProviderInterface::class);
        $jwksProvider->method('getJwks')->willReturn([
            'keys' => [$this->publicKey->jsonSerialize()],
        ]);

        $this->verifier = new JwtSignatureVerifier($jwksProvider);
    }

    public function testVerifySucceedsWithValidSignature(): void
    {
        $jwt = $this->buildSignedJwt(['iss' => 'https://issuer.example.com', 'sub' => 'test']);

        $this->expectNotToPerformAssertions();
        $this->verifier->verify($jwt, 'https://issuer.example.com');
    }

    public function testVerifyThrowsWithTamperedPayload(): void
    {
        $jwt = $this->buildSignedJwt(['iss' => 'https://issuer.example.com']);

        // Tamper with the payload part
        $parts = explode('.', $jwt);
        $parts[1] = rtrim(strtr(base64_encode(json_encode(['iss' => 'https://evil.example.com'])), '+/', '-_'), '=');
        $tamperedJwt = implode('.', $parts);

        $this->expectException(InvalidVpTokenException::class);
        $this->verifier->verify($tamperedJwt, 'https://issuer.example.com');
    }

    public function testVerifyThrowsWithWrongKey(): void
    {
        // Sign with the correct key but provide a different public key
        $jwt = $this->buildSignedJwt(['iss' => 'https://issuer.example.com']);

        $otherKey = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => \OPENSSL_KEYTYPE_EC,
        ]);
        $otherDetails = openssl_pkey_get_details($otherKey);
        $otherEc = $otherDetails['ec'];
        $otherPublicJwk = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => rtrim(strtr(base64_encode($otherEc['x']), '+/', '-_'), '='),
            'y' => rtrim(strtr(base64_encode($otherEc['y']), '+/', '-_'), '='),
        ]);

        $jwksProvider = $this->createMock(JwksProviderInterface::class);
        $jwksProvider->method('getJwks')->willReturn([
            'keys' => [$otherPublicJwk->jsonSerialize()],
        ]);

        $verifier = new JwtSignatureVerifier($jwksProvider);

        $this->expectException(InvalidVpTokenException::class);
        $verifier->verify($jwt, 'https://issuer.example.com');
    }

    private function buildSignedJwt(array $payload): string
    {
        $algorithmManager = new AlgorithmManager([new ES256()]);
        $builder = new JWSBuilder($algorithmManager);

        $jws = $builder
            ->create()
            ->withPayload(json_encode($payload))
            ->addSignature($this->privateKey, ['alg' => 'ES256'])
            ->build();

        return (new CompactSerializer())->serialize($jws);
    }
}
