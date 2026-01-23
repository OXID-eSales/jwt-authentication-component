<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

readonly class ApiUserProvider implements UserProviderInterface
{
    public function __construct(
        private QueryBuilderFactoryInterface $queryBuilderFactory,
        private RoleResolverInterface $roleResolver
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->select('OXID', 'OXUSERNAME', 'OXRIGHTS')
            ->from('oxuser')
            ->where('OXUSERNAME = :username')
            ->andWhere('OXACTIVE = 1')
            ->setParameter('username', $identifier);

        $userData = $queryBuilder->execute()->fetchAssociative();

        if (!$userData) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier));
        }

        $roles = $this->roleResolver->resolveRoles($userData['OXRIGHTS']);

        return new ApiUser(
            $userData['OXID'],
            $userData['OXUSERNAME'],
            $roles
        );
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof ApiUser) {
            throw new \InvalidArgumentException('Invalid user class');
        }

        return $this->loadUserByIdentifier($user->getUserIdentifier());
    }

    public function supportsClass(string $class): bool
    {
        return ApiUser::class === $class;
    }
}
