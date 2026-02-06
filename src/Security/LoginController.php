<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security;

use Symfony\Component\Routing\Attribute\Route;

/**
 * Login endpoint placeholder.
 * Authentication is handled by JsonLoginAuthenticator which intercepts requests to this route.
 */
final class LoginController
{
    #[Route('/api/login', methods: ['POST'])]
    public function login(): void
    {
    }
}
