<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use OxidEsales\AuthComponent\Security\User\ApiUserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenExtractorInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly TokenServiceInterface $tokenService,
        private readonly ApiUserProviderInterface $userProvider,
        private readonly AccessTokenExtractorInterface $tokenExtractor,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $this->tokenExtractor->extractAccessToken($request) !== null;
    }

    public function authenticate(Request $request): Passport
    {
        $token = $this->tokenExtractor->extractAccessToken($request);

        if ($token === null) {
            throw new AuthenticationException('Invalid authorization header format');
        }

        $parsedToken = $this->tokenService->parseToken($token);

        $userId = $parsedToken->claims()->get('userId');

        if (!is_string($userId) || $userId === '') {
            throw new AuthenticationException('Token missing userId claim');
        }

        return new SelfValidatingPassport(
            new UserBadge($userId, fn() => $this->userProvider->loadByOxid($userId))
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(
            ['error' => 'Authentication failed'],
            Response::HTTP_UNAUTHORIZED
        );
    }
}
