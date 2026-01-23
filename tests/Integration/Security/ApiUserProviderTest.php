<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Integration\Security;

use OxidEsales\EshopCommunity\Internal\Container\ContainerFactory;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use OxidEsales\AuthComponent\Security\User\RoleResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class ApiUserProviderTest extends TestCase
{
    private QueryBuilderFactoryInterface $queryBuilderFactory;
    private ApiUserProvider $userProvider;
    private string $testUserId;
    private string $testUsername;
    private string $testMallAdminId;
    private string $testMallAdminUsername;
    private string $testAdminId;
    private string $testAdminUsername;

    protected function setUp(): void
    {
        parent::setUp();

        $container = ContainerFactory::getInstance()->getContainer();
        $this->queryBuilderFactory = $container->get(QueryBuilderFactoryInterface::class);

        $roleResolver = new RoleResolver();
        $this->userProvider = new ApiUserProvider($this->queryBuilderFactory, $roleResolver);

        $timestamp = uniqid('', true);
        $this->testUsername = "test-user-provider-{$timestamp}@example.com";
        $this->testMallAdminUsername = "test-malladmin-{$timestamp}@example.com";
        $this->testAdminUsername = "test-admin-{$timestamp}@example.com";

        $this->createTestUsers();
    }

    protected function tearDown(): void
    {
        $this->deleteTestUsers();
        parent::tearDown();
    }

    public function testLoadUserByIdentifierReturnsApiUser(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testUsername);

        $this->assertSame($this->testUsername, $user->getUserIdentifier());
        $this->assertSame($this->testUserId, $user->getUserId());
        $this->assertContains('ROLE_USER', $user->getRoles());
    }

    public function testLoadUserByIdentifierWithMallAdminRights(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testMallAdminUsername);

        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertContains('ROLE_ADMIN_MALL', $user->getRoles());
    }

    public function testLoadUserByIdentifierWithNumericAdminRights(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testAdminUsername);

        $this->assertContains('ROLE_USER', $user->getRoles());
        $this->assertContains('ROLE_ADMIN', $user->getRoles());
    }

    public function testLoadUserByIdentifierThrowsExceptionForNonExistentUser(): void
    {
        $username = 'nonexistent@example.com';

        $this->expectException(UserNotFoundException::class);

        $this->userProvider->loadUserByIdentifier($username);
    }

    public function testRefreshUserReloadsUserData(): void
    {
        $originalUser = new ApiUser($this->testUserId, $this->testUsername, ['ROLE_USER']);
        $refreshedUser = $this->userProvider->refreshUser($originalUser);

        $this->assertSame($this->testUsername, $refreshedUser->getUserIdentifier());
        $this->assertSame($this->testUserId, $refreshedUser->getUserId());
    }

    public function testSupportsClassReturnsTrueForApiUser(): void
    {
        $this->assertTrue($this->userProvider->supportsClass(ApiUser::class));
    }

    public function testSupportsClassReturnsFalseForOtherClasses(): void
    {
        $this->assertFalse($this->userProvider->supportsClass(\stdClass::class));
        $this->assertFalse($this->userProvider->supportsClass('SomeOtherClass'));
    }

    public function testLoadUserByIdentifierReturnsUserWithCorrectId(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testUsername);

        $this->assertSame($this->testUserId, $user->getUserId());
    }

    public function testRefreshUserWithMallAdmin(): void
    {
        $originalUser = new ApiUser($this->testMallAdminId, $this->testMallAdminUsername, ['ROLE_USER', 'ROLE_ADMIN_MALL']);
        $refreshedUser = $this->userProvider->refreshUser($originalUser);

        $this->assertContains('ROLE_USER', $refreshedUser->getRoles());
        $this->assertContains('ROLE_ADMIN_MALL', $refreshedUser->getRoles());
    }

    public function testRefreshUserWithNumericAdmin(): void
    {
        $originalUser = new ApiUser($this->testAdminId, $this->testAdminUsername, ['ROLE_USER', 'ROLE_ADMIN']);
        $refreshedUser = $this->userProvider->refreshUser($originalUser);

        $this->assertContains('ROLE_USER', $refreshedUser->getRoles());
        $this->assertContains('ROLE_ADMIN', $refreshedUser->getRoles());
    }

    private function createTestUsers(): void
    {
        $connection = $this->queryBuilderFactory->create()->getConnection();

        $this->testUserId = uniqid('user_', true);
        $connection->insert('oxuser', [
            'OXID' => $this->testUserId,
            'OXUSERNAME' => $this->testUsername,
            'OXPASSWORD' => hash('sha512', 'testpassword'),
            'OXRIGHTS' => 'user',
            'OXACTIVE' => 1,
        ]);

        $this->testMallAdminId = uniqid('malladmin_', true);
        $connection->insert('oxuser', [
            'OXID' => $this->testMallAdminId,
            'OXUSERNAME' => $this->testMallAdminUsername,
            'OXPASSWORD' => hash('sha512', 'testpassword'),
            'OXRIGHTS' => 'malladmin',
            'OXACTIVE' => 1,
        ]);

        $this->testAdminId = uniqid('admin_', true);
        $connection->insert('oxuser', [
            'OXID' => $this->testAdminId,
            'OXUSERNAME' => $this->testAdminUsername,
            'OXPASSWORD' => hash('sha512', 'testpassword'),
            'OXRIGHTS' => '1',
            'OXACTIVE' => 1,
        ]);
    }

    private function deleteTestUsers(): void
    {
        if (isset($this->testUserId, $this->testMallAdminId, $this->testAdminId)) {
            $queryBuilder = $this->queryBuilderFactory->create();
            $queryBuilder
                ->delete('oxuser')
                ->where('OXID IN (:ids)')
                ->setParameter('ids', [$this->testUserId, $this->testMallAdminId, $this->testAdminId], \Doctrine\DBAL\Connection::PARAM_STR_ARRAY)
                ->execute();
        }
    }
}
