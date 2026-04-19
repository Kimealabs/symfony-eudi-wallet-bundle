# EUDI Wallet Bundle for Symfony

[![PHP](https://img.shields.io/badge/PHP-8.3+-blue)](https://php.net)
[![Symfony](https://img.shields.io/badge/Symfony-7.x-black)](https://symfony.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-in%20development-orange)]()

The first PHP/Symfony bundle for [EUDI Wallet](https://github.com/eu-digital-identity-wallet) integration (eIDAS 2.0).

No PHP implementation exists today for OpenID4VP or OpenID4VCI. This bundle fills that gap.

---

## What it does

The bundle lets any Symfony application act as a **Relying Party** — a service that requests and verifies identity credentials from a user's EUDI Wallet (e.g. France Identité).

```yaml
# config/packages/eudi_wallet.yaml
eudi_wallet:
    relying_party:
        client_id: "https://myservice.example.com"
        redirect_uri: "https://myservice.example.com/wallet/callback"
    trusted_issuers_list_uri: "https://verifier.eudiw.dev/trusted-issuers"
```

```php
// Generate a presentation request (QR code or deeplink)
$request = $verifier->createPresentationRequest(['family_name', 'given_name', 'age_over_18']);
return $this->render('login.html.twig', ['qr' => $request->toQrCode()]);

// Verify the response from the wallet
$identity = $verifier->verify($request);
$identity->getFamilyName(); // "Dupont"
$identity->isAgeOver18();   // true
```

---

## Features

### Phase 1 — Relying Party (in development)
- [ ] OpenID4VP Authorization Request generation
- [ ] QR code & deeplink (same-device / cross-device)
- [ ] VP Token verification (SD-JWT)
- [ ] VP Token verification (mDoc / ISO 18013-5)
- [ ] Nonce & state management
- [ ] EU Trusted Issuers List integration

### Phase 2 — Symfony Security integration
- [ ] Native `security.yaml` authenticator
- [ ] User provider from wallet claims
- [ ] Selective disclosure attribute mapping

### Phase 3 — Issuer (planned)
- [ ] OpenID4VCI credential offer
- [ ] SD-JWT credential issuance
- [ ] Credential status list (revocation)

---

## Installation

```bash
composer require kimealabs/symfony-eudi-wallet-bundle
```

Requires PHP 8.3+ and Symfony 7.x.

---

## Compatibility

| Component | Protocol | Format |
|-----------|----------|--------|
| Relying Party | OpenID4VP | SD-JWT, mDoc |
| Issuer | OpenID4VCI | SD-JWT |
| Trust | EU ARF | Trusted Issuers List |

Tested against the [France Identité Playground](https://playground.france-identite.gouv.fr).

---

## Why this bundle?

eIDAS 2.0 requires all EU Member States to provide a digital identity wallet by end of 2026. France is deploying France Identité to 5M+ users. Every Symfony service that needs identity verification will need this integration.

Today, implementations exist in Java, Kotlin, Swift, Go and TypeScript. **Nothing in PHP.** This bundle is the missing piece for the Symfony ecosystem.

---

## Contributing

The project is in early development. Issues, feedback and PRs are very welcome.

```bash
git clone https://github.com/Kimealabs/symfony-eudi-wallet-bundle
cd symfony-eudi-wallet-bundle
composer install
```

---

## License

MIT — see [LICENSE](LICENSE).
