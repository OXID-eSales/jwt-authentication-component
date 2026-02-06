<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\EshopCommunity\Internal\Transition\Utility\ContextInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

readonly class ApiUserProvider implements ApiUserProviderInterface
{
    public function __construct(
        private QueryBuilderFactoryInterface $queryBuilderFactory,
        private RoleResolverInterface $roleResolver,
        private ContextInterface $context,
    ) {
    }

    public function loadUserByIdentifier(string $identifier): UserInterface
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->select('OXID', 'OXUSERNAME', 'OXPASSWORD', 'OXRIGHTS')
            ->from('oxuser')
            ->where('OXUSERNAME = :username')
            ->andWhere('OXACTIVE = 1')
            ->andWhere('(OXSHOPID = :shopId OR OXRIGHTS = :mallAdmin)')
            ->setParameter('username', $identifier)
            ->setParameter('shopId', $this->context->getCurrentShopId())
            ->setParameter('mallAdmin', 'malladmin');

        $userData = $queryBuilder->execute()->fetchAssociative();

        if (!$userData) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier));
        }

        return $this->createApiUser($userData);
    }

    public function loadByOxid(string $oxid): UserInterface
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->select('OXID', 'OXUSERNAME', 'OXRIGHTS')
            ->from('oxuser')
            ->where('OXID = :userId')
            ->andWhere('OXACTIVE = 1')
            ->andWhere('(OXSHOPID = :shopId OR OXRIGHTS = :mallAdmin)')
            ->setParameter('userId', $oxid)
            ->setParameter('shopId', $this->context->getCurrentShopId())
            ->setParameter('mallAdmin', 'malladmin');

        $userData = $queryBuilder->execute()->fetchAssociative();

        if (!$userData) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $oxid));
        }

        return $this->createApiUser($userData);
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof ApiUser) {
            throw new UnsupportedUserException();
        }

        return $this->loadByOxid($user->getOxid());
    }

    public function supportsClass(string $class): bool
    {
        return ApiUser::class === $class;
    }

    private function createApiUser(array $userData): ApiUser
    {
        $roles = $this->roleResolver->resolveRoles($userData['OXRIGHTS']);

        return new ApiUser(
            $userData['OXID'],
            $userData['OXUSERNAME'],
            $roles,
            $userData['OXPASSWORD'] ?? null
        );
    }
}
