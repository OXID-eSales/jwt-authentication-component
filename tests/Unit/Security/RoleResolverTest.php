<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\User\RoleResolver;
use PHPUnit\Framework\TestCase;

final class RoleResolverTest extends TestCase
{
    public function testResolveRolesForRegularUser(): void
    {
        $resolver = new RoleResolver();
        $roles = $resolver->resolveRoles('user');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertFalse(in_array('ROLE_ADMIN', $roles, true));
        $this->assertFalse(in_array('ROLE_ADMIN_MALL', $roles, true));
    }

    public function testResolveRolesForMallAdmin(): void
    {
        $resolver = new RoleResolver();
        $roles = $resolver->resolveRoles('malladmin');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN_MALL', $roles);
        $this->assertFalse(in_array('ROLE_ADMIN', $roles, true));
    }

    public function testResolveRolesForNumericAdmin(): void
    {
        $resolver = new RoleResolver();
        $roles = $resolver->resolveRoles('1');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertFalse(in_array('ROLE_ADMIN_MALL', $roles, true));
    }

    public function testResolveRolesForEmptyRights(): void
    {
        $resolver = new RoleResolver();
        $roles = $resolver->resolveRoles('');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertSame(1, count($roles));
    }

    public function testResolveRolesAlwaysContainsRoleUser(): void
    {
        $resolver = new RoleResolver();

        $this->assertContains('ROLE_USER', $resolver->resolveRoles('user'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('malladmin'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('1'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles(''));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('unknown'));
    }
}
