<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

final class ApiUser implements OxidAwareUserInterface, PasswordAuthenticatedUserInterface
{
    public function __construct(
        private readonly string $oxid,
        private readonly string $username,
        private readonly array $roles,
        #[\SensitiveParameter] private readonly ?string $password = null
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

    #[\Deprecated]
    public function eraseCredentials(): void
    {
    }

    public function __serialize(): array
    {
        return [
            'oxid' => $this->oxid,
            'username' => $this->username,
            'roles' => $this->roles,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->oxid = $data['oxid'];
        $this->username = $data['username'];
        $this->roles = $data['roles'];
        $this->password = null;
    }
}
