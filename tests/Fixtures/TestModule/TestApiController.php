<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Fixtures\TestModule;

use OxidEsales\AuthComponent\Security\User\ApiUser;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final readonly class TestApiController
{
    #[Route('/api/test/public', methods: ['GET'])]
    public function publicEndpoint(): Response
    {
        return new JsonResponse([
            'message' => 'Public endpoint - no authentication required',
            'timestamp' => time(),
        ]);
    }

    #[IsGranted('ROLE_USER')]
    #[Route('/api/test/user', methods: ['GET'])]
    public function userEndpoint(#[CurrentUser] ApiUser $user): Response
    {
        return new JsonResponse([
            'message' => 'User endpoint - ROLE_USER required',
            'user' => [
                'username' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
            ],
            'timestamp' => time(),
        ]);
    }

    #[IsGranted('ROLE_ADMIN')]
    #[Route('/api/test/admin', methods: ['GET'])]
    public function adminEndpoint(#[CurrentUser] ApiUser $user): Response
    {
        return new JsonResponse([
            'message' => 'Admin endpoint - ROLE_ADMIN required',
            'user' => [
                'username' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
            ],
            'timestamp' => time(),
        ]);
    }

    #[Route('/api/test/info', methods: ['GET'])]
    public function infoEndpoint(#[CurrentUser] ?ApiUser $user): Response
    {
        return new JsonResponse([
            'message' => 'Info endpoint - optional authentication',
            'authenticated' => $user !== null,
            'user' => $user ? [
                'username' => $user->getUserIdentifier(),
                'roles' => $user->getRoles(),
            ] : null,
            'timestamp' => time(),
        ]);
    }
}
