<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

final readonly class ApiUser implements UserInterface
{
    public function __construct(
        private string $userId,
        private string $username,
        private array  $roles
    ) {
    }

    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function eraseCredentials(): void
    {
    }
}
