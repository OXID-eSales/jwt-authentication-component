<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\User\RoleResolver;
use OxidEsales\EshopCommunity\Internal\Transition\Utility\ContextInterface;
use PHPUnit\Framework\TestCase;

final class RoleResolverTest extends TestCase
{
    private array $defaultRoleMapping = [
        'malladmin' => ['ROLE_ADMIN', 'ROLE_ADMIN_MALL'],
    ];

    private ContextInterface $context;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = $this->createMock(ContextInterface::class);
        $this->context->method('getCurrentShopId')->willReturn(1);
    }

    public function testResolveRolesForRegularUser(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);
        $roles = $resolver->resolveRoles('user');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertFalse(in_array('ROLE_ADMIN', $roles, true));
        $this->assertFalse(in_array('ROLE_ADMIN_MALL', $roles, true));
    }

    public function testResolveRolesForMallAdmin(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);
        $roles = $resolver->resolveRoles('malladmin');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertContains('ROLE_ADMIN_MALL', $roles);
    }

    public function testResolveRolesForNumericAdminMatchingCurrentShop(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);
        $roles = $resolver->resolveRoles('1');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertContains('ROLE_ADMIN', $roles);
        $this->assertFalse(in_array('ROLE_ADMIN_MALL', $roles, true));
    }

    public function testResolveRolesForNumericAdminNotMatchingCurrentShop(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);
        $roles = $resolver->resolveRoles('2');

        $this->assertSame(['ROLE_USER'], $roles);
    }

    public function testResolveRolesForEmptyRights(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);
        $roles = $resolver->resolveRoles('');

        $this->assertContains('ROLE_USER', $roles);
        $this->assertSame(1, count($roles));
    }

    public function testResolveRolesAlwaysContainsRoleUser(): void
    {
        $resolver = new RoleResolver($this->context, $this->defaultRoleMapping);

        $this->assertContains('ROLE_USER', $resolver->resolveRoles('user'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('malladmin'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('1'));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles(''));
        $this->assertContains('ROLE_USER', $resolver->resolveRoles('unknown'));
    }

    public function testResolveRolesWithCustomMapping(): void
    {
        $customMapping = [
            'superuser' => ['ROLE_SUPER', 'ROLE_ADMIN'],
            'editor' => ['ROLE_EDITOR'],
        ];
        $resolver = new RoleResolver($this->context, $customMapping);

        $superuserRoles = $resolver->resolveRoles('superuser');
        $this->assertContains('ROLE_USER', $superuserRoles);
        $this->assertContains('ROLE_SUPER', $superuserRoles);
        $this->assertContains('ROLE_ADMIN', $superuserRoles);

        $editorRoles = $resolver->resolveRoles('editor');
        $this->assertContains('ROLE_USER', $editorRoles);
        $this->assertContains('ROLE_EDITOR', $editorRoles);
        $this->assertFalse(in_array('ROLE_ADMIN', $editorRoles, true));
    }

    public function testResolveRolesWithEmptyMapping(): void
    {
        $resolver = new RoleResolver($this->context, []);
        $roles = $resolver->resolveRoles('malladmin');

        $this->assertSame(['ROLE_USER'], $roles);
    }
}
