<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Security;

use Kimealabs\EudiWalletBundle\Exception\EudiWalletException;
use Kimealabs\EudiWalletBundle\Verifier\VpTokenVerifierInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Symfony Security authenticator for EUDI Wallet via OpenID4VP.
 *
 * Usage in security.yaml:
 *
 *   firewalls:
 *     main:
 *       custom_authenticators:
 *         - Kimealabs\EudiWalletBundle\Security\EudiWalletAuthenticator
 */
final class EudiWalletAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly VpTokenVerifierInterface $verifier,
        private readonly string $callbackPath = '/wallet/callback',
        private readonly string $loginPath = '/login',
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->getPathInfo() === $this->callbackPath
            && $request->isMethod('POST');
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $presentation = $this->verifier->verifyFromRequest($request);
        } catch (EudiWalletException $e) {
            throw new CustomUserMessageAuthenticationException($e->getMessage(), [], 0, $e);
        }

        $user = EudiWalletUser::fromPresentation($presentation);

        return new SelfValidatingPassport(
            new UserBadge($user->getUserIdentifier(), static fn () => $user)
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // Return null to let Symfony handle the redirect (e.g. to the originally requested URL)
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->set('eudi_wallet_error', strtr($exception->getMessageKey(), $exception->getMessageData()));

        return new RedirectResponse($this->loginPath);
    }
}
