<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

interface RoleResolverInterface
{
    public function resolveRoles(string $rights): array;
}
