<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Integration\Security;

use OxidEsales\EshopCommunity\Internal\Container\ContainerFactory;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\AuthComponent\Security\AdminController;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\User\CredentialValidator;
use OxidEsales\AuthComponent\Security\LoginController;
use OxidEsales\AuthComponent\Security\User\RoleResolver;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class ApiAuthenticationTest extends TestCase
{
    private string $testUserId;
    private string $testUsername = 'test-api-user@example.com';
    private string $testPassword = 'testpassword123';
    private TokenService $tokenService;
    private ApiUserProvider $userProvider;
    private LoginController $loginController;
    private AdminController $adminController;
    private QueryBuilderFactoryInterface $queryBuilderFactory;
    private string $testAdminId;
    private string $testAdminUsername = 'admin@example.com';
    private string $testAdminPassword = 'adminpassword123';

    protected function setUp(): void
    {
        parent::setUp();

        $container = ContainerFactory::getInstance()->getContainer();
        $this->queryBuilderFactory = $container->get(QueryBuilderFactoryInterface::class);

        $roleResolver = new RoleResolver();
        $credentialValidator = new CredentialValidator($this->queryBuilderFactory);
        $this->tokenService = new TokenService('test-secret-key-for-integration-tests-must-be-at-least-256-bits-long', 3600);
        $this->userProvider = new ApiUserProvider($this->queryBuilderFactory, $roleResolver);
        $this->loginController = new LoginController($credentialValidator, $this->tokenService, $roleResolver);
        $this->adminController = new AdminController();

        $this->createTestUser();
        $this->createTestAdmin();
    }

    protected function tearDown(): void
    {
        $this->deleteTestUser();
        $this->deleteTestAdmin();
        parent::tearDown();
    }

    public function testLoginWithValidCredentials(): void
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'username' => $this->testUsername,
                'password' => $this->testPassword,
            ])
        );

        $response = $this->loginController->login($request);

        $this->assertSame(200, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertSame($this->testUsername, $data['user']['username']);
        $this->assertContains('ROLE_USER', $data['user']['roles']);
    }

    public function testLoginWithInvalidCredentials(): void
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'username' => $this->testUsername,
                'password' => 'wrongpassword',
            ])
        );

        $response = $this->loginController->login($request);

        $this->assertSame(401, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertSame('Invalid credentials', $data['error']);
    }

    public function testLoginWithMissingCredentials(): void
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode(['username' => $this->testUsername])
        );

        $response = $this->loginController->login($request);

        $this->assertSame(400, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertSame('Username and password are required', $data['error']);
    }

    public function testTokenServiceGeneratesValidToken(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com', ['ROLE_USER']);

        $parsedToken = $this->tokenService->parseToken($token);
        $this->assertSame('user123', $parsedToken->claims()->get('uid'));
        $this->assertSame('test@example.com', $parsedToken->claims()->get('username'));
    }

    public function testTokenServiceValidatesToken(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');

        $this->assertSame(true, $this->tokenService->validateToken($token));
        $this->assertFalse($this->tokenService->validateToken('invalid.token.here'));
    }

    public function testUserProviderLoadsUserByUsername(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testUsername);

        $this->assertSame($this->testUsername, $user->getUserIdentifier());
        $this->assertSame($this->testUserId, $user->getUserId());
        $this->assertContains('ROLE_USER', $user->getRoles());
    }

    public function testUserProviderThrowsExceptionForNonExistentUser(): void
    {
        $this->expectException(UserNotFoundException::class);

        $this->userProvider->loadUserByIdentifier('nonexistent@example.com');
    }

    public function testTokenContainsUserInformation(): void
    {
        $token = $this->getAuthToken();

        $parts = explode('.', $token);

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        $this->assertSame($this->testUsername, $payload['username']);
        $this->assertContains('ROLE_USER', $payload['roles']);
    }

    public function testRegularUserCannotAccessAdminEndpoint(): void
    {
        $user = $this->userProvider->loadUserByIdentifier($this->testUsername);

        $response = $this->adminController->getSettings($user);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testAdminUserCanAccessAdminEndpoint(): void
    {
        $admin = $this->userProvider->loadUserByIdentifier($this->testAdminUsername);

        $response = $this->adminController->getSettings($admin);

        $this->assertSame(200, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertFalse($data['settings']['maintenance_mode']);
        $this->assertSame(1000, $data['settings']['api_rate_limit']);
        $this->assertSame($this->testAdminUsername, $data['admin_user']);
    }

    public function testPublicEndpointAccessibleWithoutAuthentication(): void
    {
        $response = $this->adminController->getPublicInfo();

        $this->assertSame(200, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertSame('1.0.0', $data['version']);
        $this->assertSame('operational', $data['status']);
    }

    private function getAuthToken(): string
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'username' => $this->testUsername,
                'password' => $this->testPassword,
            ])
        );

        $response = $this->loginController->login($request);
        $data = json_decode($response->getContent(), true);

        return $data['token'] ?? '';
    }

    private function getAuthTokenForAdmin(): string
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode([
                'username' => $this->testAdminUsername,
                'password' => $this->testAdminPassword,
            ])
        );

        $response = $this->loginController->login($request);
        $data = json_decode($response->getContent(), true);

        return $data['token'] ?? '';
    }

    private function createTestUser(): void
    {
        $this->testUserId = bin2hex(random_bytes(16));

        $passwordHash = hash('sha512', $this->testPassword);

        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->insert('oxuser')
            ->values([
                'OXID' => ':oxid',
                'OXUSERNAME' => ':username',
                'OXPASSWORD' => ':password',
                'OXACTIVE' => ':active',
                'OXRIGHTS' => ':rights',
                'OXSHOPID' => ':shopid',
            ])
            ->setParameters([
                'oxid' => $this->testUserId,
                'username' => $this->testUsername,
                'password' => $passwordHash,
                'active' => 1,
                'rights' => 'user',
                'shopid' => 1,
            ])
            ->execute();
    }

    private function deleteTestUser(): void
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->delete('oxuser')
            ->where('OXID = :oxid')
            ->setParameter('oxid', $this->testUserId)
            ->execute();
    }

    private function createTestAdmin(): void
    {
        $this->testAdminId = bin2hex(random_bytes(16));

        $passwordHash = hash('sha512', $this->testAdminPassword);

        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->insert('oxuser')
            ->values([
                'OXID' => ':oxid',
                'OXUSERNAME' => ':username',
                'OXPASSWORD' => ':password',
                'OXACTIVE' => ':active',
                'OXRIGHTS' => ':rights',
                'OXSHOPID' => ':shopid',
            ])
            ->setParameters([
                'oxid' => $this->testAdminId,
                'username' => $this->testAdminUsername,
                'password' => $passwordHash,
                'active' => 1,
                'rights' => 'malladmin',
                'shopid' => 1,
            ])
            ->execute();
    }

    private function deleteTestAdmin(): void
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->delete('oxuser')
            ->where('OXID = :oxid')
            ->setParameter('oxid', $this->testAdminId)
            ->execute();
    }
}
