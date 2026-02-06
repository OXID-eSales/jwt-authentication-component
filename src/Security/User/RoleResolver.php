<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use OxidEsales\EshopCommunity\Internal\Transition\Utility\ContextInterface;

final readonly class RoleResolver implements RoleResolverInterface
{
    /**
     * @param array<string, list<string>> $roleMapping Map of rights string to additional roles
     */
    public function __construct(
        private ContextInterface $context,
        private array $roleMapping = []
    ) {
    }

    public function resolveRoles(string $rights): array
    {
        $roles = array_merge(['ROLE_USER'], $this->roleMapping[$rights] ?? []);

        if ($rights === (string) $this->context->getCurrentShopId()) {
            $roles[] = 'ROLE_ADMIN';
        }

        return $roles;
    }
}
