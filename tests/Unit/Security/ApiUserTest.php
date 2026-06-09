<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\User\ApiUser;
use OxidEsales\AuthComponent\Security\User\OxidAwareUserInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

final class ApiUserTest extends TestCase
{
    public function testImplementsRequiredInterfaces(): void
    {
        $user = new ApiUser('oxid', 'user@example.com', ['ROLE_USER']);

        $this->assertInstanceOf(OxidAwareUserInterface::class, $user);
        $this->assertInstanceOf(PasswordAuthenticatedUserInterface::class, $user);
    }

    public function testGetOxidReturnsOxid(): void
    {
        $user = new ApiUser('id123', 'user@example.com', ['ROLE_USER']);

        $this->assertSame('id123', $user->getOxid());
    }

    public function testGetUserIdentifierReturnsUsername(): void
    {
        $user = new ApiUser('id123', 'user@example.com', ['ROLE_USER']);

        $this->assertSame('user@example.com', $user->getUserIdentifier());
    }

    public function testGetRoles(): void
    {
        $roles = ['ROLE_USER', 'ROLE_ADMIN'];
        $user = new ApiUser('id', 'user@example.com', $roles);

        $this->assertSame($roles, $user->getRoles());
    }

    public function testGetPasswordWithPassword(): void
    {
        $user = new ApiUser('id', 'user@example.com', ['ROLE_USER'], 'hashedpassword');

        $this->assertSame('hashedpassword', $user->getPassword());
    }

    public function testGetPasswordWithoutPassword(): void
    {
        $user = new ApiUser('id', 'user@example.com', ['ROLE_USER']);

        $this->assertNull($user->getPassword());
    }

    public function testEraseCredentials(): void
    {
        $user = new ApiUser('id', 'user@example.com', ['ROLE_USER'], 'hashedpassword');

        $user->eraseCredentials();

        $this->assertNull($user->getPassword());
    }
}
