<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

final readonly class RoleResolver implements RoleResolverInterface
{
    public function resolveRoles(string $rights): array
    {
        $roles = ['ROLE_USER'];

        if ($rights === 'malladmin') {
            $roles[] = 'ROLE_ADMIN_MALL';
        }

        if ($rights === '1') {
            $roles[] = 'ROLE_ADMIN';
        }

        return $roles;
    }
}
