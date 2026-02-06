<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\AuthComponent\Security\User;

interface RoleResolverInterface
{
    public function resolveRoles(string $rights): array;
}
