<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security;

use OxidEsales\AuthComponent\Security\User\ApiUser;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final readonly class AdminController
{
    #[Route('/api/admin/settings', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    public function getSettings(#[CurrentUser] ApiUser $user): Response
    {
        return new JsonResponse([
            'admin_user' => $user->getUserIdentifier(),
        ]);
    }

    #[Route('/api/admin/info', methods: ['GET'])]
    public function getPublicInfo(): Response
    {
        return new JsonResponse([
            'version' => '1.0.0',
            'status' => 'operational',
        ]);
    }
}
