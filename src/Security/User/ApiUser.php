<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class ApiUser implements UserInterface, PasswordAuthenticatedUserInterface
{
    public function __construct(
        private readonly string $oxid,
        private readonly string $username,
        private readonly array $roles,
        #[\SensitiveParameter] private ?string $password = null
    ) {
    }

    public function getOxid(): string
    {
        return $this->oxid;
    }

    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function eraseCredentials(): void
    {
        $this->password = null;
    }
}
