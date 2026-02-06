<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\User\ApiUser;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use OxidEsales\AuthComponent\Security\User\RoleResolverInterface;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\EshopCommunity\Internal\Transition\Utility\ContextInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;

final class ApiUserProviderTest extends TestCase
{
    private ApiUserProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = new ApiUserProvider(
            $this->createMock(QueryBuilderFactoryInterface::class),
            $this->createMock(RoleResolverInterface::class),
            $this->createMock(ContextInterface::class),
        );
    }

    public function testRefreshUserThrowsExceptionForNonApiUser(): void
    {
        $this->expectException(UnsupportedUserException::class);

        $this->provider->refreshUser($this->createMock(UserInterface::class));
    }

    public function testSupportsClassReturnsTrueForApiUser(): void
    {
        $this->assertTrue($this->provider->supportsClass(ApiUser::class));
    }

    public function testSupportsClassReturnsFalseForOtherClasses(): void
    {
        $this->assertFalse($this->provider->supportsClass(\stdClass::class));
    }
}
