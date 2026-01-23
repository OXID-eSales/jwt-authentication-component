<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Integration\Security;

use OxidEsales\EshopCommunity\Internal\Container\ContainerFactory;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\AuthComponent\Security\User\Exception\InvalidCredentialsException;
use OxidEsales\AuthComponent\Security\User\CredentialValidator;
use PHPUnit\Framework\TestCase;

final class CredentialValidatorTest extends TestCase
{
    private QueryBuilderFactoryInterface $queryBuilderFactory;
    private CredentialValidator $credentialValidator;
    private string $testUserId;
    private string $testUsername;
    private string $testPassword = 'testpassword';
    private string $testUserIdInactive;
    private string $testUsernameInactive;

    protected function setUp(): void
    {
        parent::setUp();

        $container = ContainerFactory::getInstance()->getContainer();
        $this->queryBuilderFactory = $container->get(QueryBuilderFactoryInterface::class);
        $this->credentialValidator = new CredentialValidator($this->queryBuilderFactory);

        $timestamp = uniqid('', true);
        $this->testUsername = "test-credential-{$timestamp}@example.com";
        $this->testUsernameInactive = "test-credential-inactive-{$timestamp}@example.com";

        $this->createTestUsers();
    }

    protected function tearDown(): void
    {
        $this->deleteTestUsers();
        parent::tearDown();
    }

    public function testValidateCredentialsWithValidPassword(): void
    {
        $result = $this->credentialValidator->validateCredentials(
            $this->testUsername,
            $this->testPassword
        );

        $this->assertSame($this->testUserId, $result['OXID']);
        $this->assertSame($this->testUsername, $result['OXUSERNAME']);
        $this->assertSame('user', $result['OXRIGHTS']);
    }

    public function testValidateCredentialsWithInvalidPassword(): void
    {
        $this->expectException(InvalidCredentialsException::class);

        $this->credentialValidator->validateCredentials(
            $this->testUsername,
            'wrongpassword'
        );
    }

    public function testValidateCredentialsWithNonExistentUser(): void
    {
        $this->expectException(InvalidCredentialsException::class);

        $this->credentialValidator->validateCredentials(
            'nonexistent@example.com',
            'somepassword'
        );
    }

    public function testValidateCredentialsWithInactiveUser(): void
    {
        $this->expectException(InvalidCredentialsException::class);

        $this->credentialValidator->validateCredentials(
            $this->testUsernameInactive,
            'password'
        );
    }

    public function testValidateCredentialsDoesNotReturnPassword(): void
    {
        $result = $this->credentialValidator->validateCredentials(
            $this->testUsername,
            $this->testPassword
        );

        $this->assertArrayNotHasKey('OXPASSWORD', $result);
    }

    public function testValidateCredentialsWithEmptyPassword(): void
    {
        $this->expectException(InvalidCredentialsException::class);

        $this->credentialValidator->validateCredentials(
            $this->testUsername,
            ''
        );
    }

    public function testValidateCredentialsReturnsRequiredUserData(): void
    {
        $result = $this->credentialValidator->validateCredentials(
            $this->testUsername,
            $this->testPassword
        );

        $this->assertArrayHasKey('OXID', $result);
        $this->assertArrayHasKey('OXUSERNAME', $result);
        $this->assertArrayHasKey('OXRIGHTS', $result);
        $this->assertArrayNotHasKey('OXPASSWORD', $result);
    }

    private function createTestUsers(): void
    {
        $connection = $this->queryBuilderFactory->create()->getConnection();

        $this->testUserId = uniqid('user_', true);
        $connection->insert('oxuser', [
            'OXID' => $this->testUserId,
            'OXUSERNAME' => $this->testUsername,
            'OXPASSWORD' => hash('sha512', $this->testPassword),
            'OXRIGHTS' => 'user',
            'OXACTIVE' => 1,
        ]);

        $this->testUserIdInactive = uniqid('inactive_', true);
        $connection->insert('oxuser', [
            'OXID' => $this->testUserIdInactive,
            'OXUSERNAME' => $this->testUsernameInactive,
            'OXPASSWORD' => hash('sha512', 'password'),
            'OXRIGHTS' => 'user',
            'OXACTIVE' => 0,
        ]);
    }

    private function deleteTestUsers(): void
    {
        if (isset($this->testUserId, $this->testUserIdInactive)) {
            $queryBuilder = $this->queryBuilderFactory->create();
            $queryBuilder
                ->delete('oxuser')
                ->where('OXID IN (:ids)')
                ->setParameter('ids', [$this->testUserId, $this->testUserIdInactive], \Doctrine\DBAL\Connection::PARAM_STR_ARRAY)
                ->execute();
        }
    }
}
