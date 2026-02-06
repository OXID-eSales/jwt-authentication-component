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

final readonly class ProfileController
{
    #[Route('/api/profile', methods: ['GET'])]
    #[IsGranted('IS_AUTHENTICATED')]
    public function getProfile(#[CurrentUser] ApiUser $user): Response
    {
        return new JsonResponse([
            'username' => $user->getUserIdentifier(),
            'roles' => $user->getRoles()
        ]);
    }
}
