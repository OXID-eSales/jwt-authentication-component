<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security;

use OxidEsales\AuthComponent\Security\Auth\TokenServiceInterface;
use OxidEsales\AuthComponent\Security\User\Exception\InvalidCredentialsException;
use OxidEsales\AuthComponent\Security\User\CredentialValidatorInterface;
use OxidEsales\AuthComponent\Security\User\RoleResolverInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final readonly class LoginController
{
    public function __construct(
        private CredentialValidatorInterface $credentialValidator,
        private TokenServiceInterface        $tokenService,
        private RoleResolverInterface        $roleResolver
    ) {
    }

    #[Route('/api/login', methods: ['POST'])]
    public function login(Request $request): Response
    {
        $data = json_decode($request->getContent(), true);

        if (!isset($data['username']) || !isset($data['password'])) {
            return new JsonResponse(
                ['error' => 'Username and password are required'],
                Response::HTTP_BAD_REQUEST
            );
        }

        try {
            $user = $this->credentialValidator->validateCredentials($data['username'], $data['password']);
        } catch (InvalidCredentialsException) {
            return new JsonResponse(
                ['error' => 'Invalid credentials'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        $roles = $this->roleResolver->resolveRoles($user['OXRIGHTS']);

        $token = $this->tokenService->generateToken(
            $user['OXID'],
            $user['OXUSERNAME'],
            $roles
        );

        return new JsonResponse([
            'token' => $token,
            'user' => [
                'id' => $user['OXID'],
                'username' => $user['OXUSERNAME'],
                'roles' => $roles
            ]
        ]);
    }
}
