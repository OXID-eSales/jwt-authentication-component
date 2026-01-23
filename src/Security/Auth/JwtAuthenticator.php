<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use OxidEsales\AuthComponent\Security\Auth\Exception\InvalidTokenException;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JwtAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly TokenServiceInterface $tokenService,
        private readonly ApiUserProvider $userProvider
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization');

        if (!str_starts_with($authHeader, 'Bearer ')) {
            throw new AuthenticationException('Invalid authorization header format');
        }

        $token = substr($authHeader, 7);

        try {
            $parsedToken = $this->tokenService->parseToken($token);
        } catch (InvalidTokenException $e) {
            throw new AuthenticationException($e->getMessage(), 0, $e);
        }

        $username = $parsedToken->claims()->get('username');

        return new SelfValidatingPassport(
            new UserBadge($username, fn() => $this->userProvider->loadUserByIdentifier($username))
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(
            ['error' => 'Authentication failed', 'message' => $exception->getMessage()],
            Response::HTTP_UNAUTHORIZED
        );
    }
}
