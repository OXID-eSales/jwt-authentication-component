<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use Lcobucci\JWT\Token\Plain;

interface TokenServiceInterface
{
    public function generateToken(string $userId, string $username, array $roles = ['ROLE_USER']): string;

    public function parseToken(string $token): Plain;

    public function validateToken(string $token): bool;
}
