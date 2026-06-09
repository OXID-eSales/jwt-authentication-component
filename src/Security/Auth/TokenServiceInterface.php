<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\AuthComponent\Security\Auth;

use Lcobucci\JWT\Token\Plain;
use OxidEsales\AuthComponent\Security\User\OxidAwareUserInterface;

interface TokenServiceInterface
{
    public function generateToken(OxidAwareUserInterface $user): string;

    public function parseToken(string $token): Plain;

    public function validateToken(string $token): bool;
}
