<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Integration\Security;

use OxidEsales\AuthComponent\Security\AdminController;
use OxidEsales\AuthComponent\Security\Auth\AuthenticationSuccessHandler;
use OxidEsales\AuthComponent\Security\Auth\JwtAuthenticator;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use OxidEsales\AuthComponent\Security\User\OxidPasswordHasher;
use OxidEsales\AuthComponent\Security\User\OxidPasswordHasherFactory;
use OxidEsales\AuthComponent\Security\User\RoleResolver;
use Symfony\Component\Security\Http\AccessToken\HeaderAccessTokenExtractor;
use Symfony\Component\Security\Http\EventListener\CheckCredentialsListener;
use OxidEsales\EshopCommunity\Internal\Container\ContainerFactory;
use OxidEsales\EshopCommunity\Internal\Domain\Authentication\Bridge\PasswordServiceBridgeInterface;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\EshopCommunity\Internal\Transition\Utility\ContextInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Http\Authenticator\JsonLoginAuthenticator;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\HttpUtils;

final class ApiAuthenticationTest extends TestCase
{
    private string $testUserId;
    private string $testUsername = 'test-api-user@example.com';
    private string $testPassword = 'testpassword123';
    private TokenService $tokenService;
    private ApiUserProvider $userProvider;
    private JwtAuthenticator $jwtAuthenticator;
    private JsonLoginAuthenticator $jsonLoginAuthenticator;
    private AuthenticationSuccessHandler $successHandler;
    private EventDispatcher $eventDispatcher;
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

        $context = $container->get(ContextInterface::class);
        $roleResolver = new RoleResolver($context, [
            'malladmin' => ['ROLE_ADMIN', 'ROLE_ADMIN_MALL'],
        ]);
        $this->userProvider = new ApiUserProvider($this->queryBuilderFactory, $roleResolver, $context);

        $passwordHasher = new OxidPasswordHasher($container->get(PasswordServiceBridgeInterface::class));
        $passwordHasherFactory = new OxidPasswordHasherFactory($passwordHasher);

        $this->eventDispatcher = new EventDispatcher();
        $this->eventDispatcher->addSubscriber(new CheckCredentialsListener($passwordHasherFactory));

        $this->tokenService = new TokenService(
            'test-secret-key-for-integration-tests-must-be-at-least-256-bits-long',
            'oxid-api',
            'oxid-api',
            3600
        );
        $this->jwtAuthenticator = new JwtAuthenticator($this->tokenService, $this->userProvider, new HeaderAccessTokenExtractor());
        $this->successHandler = new AuthenticationSuccessHandler($this->tokenService);

        $httpUtils = new HttpUtils();
        $this->jsonLoginAuthenticator = new JsonLoginAuthenticator(
            $httpUtils,
            $this->userProvider,
            $this->successHandler,
            null,
            ['check_path' => '/api/login']
        );
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
        $request = $this->createLoginRequest($this->testUsername, $this->testPassword);

        $passport = $this->jsonLoginAuthenticator->authenticate($request);
        $this->eventDispatcher->dispatch(new CheckPassportEvent($this->jsonLoginAuthenticator, $passport));

        $user = $passport->getUser();
        $token = new UsernamePasswordToken($user, 'api', $user->getRoles());
        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

        $this->assertSame(200, $response->getStatusCode());

        $data = json_decode($response->getContent(), true);
        $this->assertContains('ROLE_USER', $data['user']['roles']);
    }

    public function testLoginWithInvalidCredentials(): void
    {
        $request = $this->createLoginRequest($this->testUsername, 'wrongpassword');

        $passport = $this->jsonLoginAuthenticator->authenticate($request);

        $this->expectException(\Symfony\Component\Security\Core\Exception\BadCredentialsException::class);

        $this->eventDispatcher->dispatch(new CheckPassportEvent($this->jsonLoginAuthenticator, $passport));
    }

    public function testLoginWithMissingPassword(): void
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'REQUEST_URI' => '/api/login', 'REQUEST_METHOD' => 'POST'],
            json_encode(['username' => $this->testUsername])
        );
        $request->server->set('REQUEST_URI', '/api/login');
        $request->server->set('REQUEST_METHOD', 'POST');
        $request->headers->set('Content-Type', 'application/json');

        $this->expectException(\Symfony\Component\HttpKernel\Exception\BadRequestHttpException::class);

        $this->jsonLoginAuthenticator->authenticate($request);
    }

    private function createLoginRequest(string $username, string $password): Request
    {
        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json', 'REQUEST_URI' => '/api/login', 'REQUEST_METHOD' => 'POST'],
            json_encode(['username' => $username, 'password' => $password])
        );
        $request->server->set('REQUEST_URI', '/api/login');
        $request->server->set('REQUEST_METHOD', 'POST');
        $request->headers->set('Content-Type', 'application/json');

        return $request;
    }

    public function testAdminUserCanAccessAdminEndpoint(): void
    {
        $admin = $this->userProvider->loadByOxid($this->testAdminId);
        $jwt = $this->tokenService->generateToken($admin);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $jwt);

        $passport = $this->jwtAuthenticator->authenticate($request);
        $user = $passport->getUser();

        $this->assertContains('ROLE_ADMIN', $user->getRoles());

        $response = $this->adminController->getSettings($user);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testTokenAuthenticatesCorrectUserById(): void
    {
        $user = $this->userProvider->loadByOxid($this->testUserId);
        $jwt = $this->tokenService->generateToken($user);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $jwt);

        $passport = $this->jwtAuthenticator->authenticate($request);
        $authenticatedUser = $passport->getUser();

        $this->assertSame($this->testUserId, $authenticatedUser->getOxid());
    }

    public function testDeactivatedUserJwtIsRejected(): void
    {
        $user = $this->userProvider->loadByOxid($this->testUserId);
        $jwt = $this->tokenService->generateToken($user);

        $this->queryBuilderFactory->create()->getConnection()
            ->update('oxuser', ['OXACTIVE' => 0], ['OXID' => $this->testUserId]);

        try {
            $request = new Request();
            $request->headers->set('Authorization', 'Bearer ' . $jwt);

            $this->expectException(\Symfony\Component\Security\Core\Exception\UserNotFoundException::class);

            $passport = $this->jwtAuthenticator->authenticate($request);
            $passport->getUser();
        } finally {
            $this->queryBuilderFactory->create()->getConnection()
                ->update('oxuser', ['OXACTIVE' => 1], ['OXID' => $this->testUserId]);
        }
    }

    public function testAdminRightsRevocationReflectedImmediately(): void
    {
        $admin = $this->userProvider->loadByOxid($this->testAdminId);
        $jwt = $this->tokenService->generateToken($admin);

        $this->queryBuilderFactory->create()->getConnection()
            ->update('oxuser', ['OXRIGHTS' => 'user'], ['OXID' => $this->testAdminId]);

        try {
            $request = new Request();
            $request->headers->set('Authorization', 'Bearer ' . $jwt);

            $passport = $this->jwtAuthenticator->authenticate($request);
            $reloadedUser = $passport->getUser();

            $this->assertNotContains('ROLE_ADMIN', $reloadedUser->getRoles());
            $this->assertContains('ROLE_USER', $reloadedUser->getRoles());
        } finally {
            $this->queryBuilderFactory->create()->getConnection()
                ->update('oxuser', ['OXRIGHTS' => 'malladmin'], ['OXID' => $this->testAdminId]);
        }
    }

    public function testSqlInjectionInJwtUserIdIsRejected(): void
    {
        $injectionUser = new \OxidEsales\AuthComponent\Security\User\ApiUser(
            "' OR '1'='1",
            'attacker@test.com',
            ['ROLE_USER']
        );
        $jwt = $this->tokenService->generateToken($injectionUser);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $jwt);

        $this->expectException(\Symfony\Component\Security\Core\Exception\UserNotFoundException::class);

        $passport = $this->jwtAuthenticator->authenticate($request);
        $passport->getUser();
    }

    public function testOtherShopUserJwtIsRejected(): void
    {
        $connection = $this->queryBuilderFactory->create()->getConnection();
        $otherShopId = uniqid('os_', true);

        $connection->insert('oxuser', [
            'OXID' => $otherShopId,
            'OXUSERNAME' => "attacker-{$otherShopId}@example.com",
            'OXPASSWORD' => password_hash('password', PASSWORD_DEFAULT),
            'OXRIGHTS' => 'user',
            'OXACTIVE' => 1,
            'OXSHOPID' => 999,
        ]);

        try {
            $otherShopUser = new \OxidEsales\AuthComponent\Security\User\ApiUser(
                $otherShopId,
                "attacker-{$otherShopId}@example.com",
                ['ROLE_USER']
            );
            $jwt = $this->tokenService->generateToken($otherShopUser);

            $request = new Request();
            $request->headers->set('Authorization', 'Bearer ' . $jwt);

            $this->expectException(\Symfony\Component\Security\Core\Exception\UserNotFoundException::class);

            $passport = $this->jwtAuthenticator->authenticate($request);
            $passport->getUser();
        } finally {
            $connection->delete('oxuser', ['OXID' => $otherShopId]);
        }
    }

    public function testRegularUserJwtHasNoAdminRole(): void
    {
        $user = $this->userProvider->loadByOxid($this->testUserId);
        $jwt = $this->tokenService->generateToken($user);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $jwt);

        $passport = $this->jwtAuthenticator->authenticate($request);
        $authenticatedUser = $passport->getUser();

        $this->assertContains('ROLE_USER', $authenticatedUser->getRoles());
        $this->assertNotContains('ROLE_ADMIN', $authenticatedUser->getRoles());
        $this->assertNotContains('ROLE_ADMIN_MALL', $authenticatedUser->getRoles());
    }

    public function testTokenWithNonExistentUserIdFailsAuthentication(): void
    {
        $fakeUser = new \OxidEsales\AuthComponent\Security\User\ApiUser(
            'nonexistent-user-id',
            'fake@test.com',
            ['ROLE_USER']
        );
        $jwt = $this->tokenService->generateToken($fakeUser);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $jwt);

        $this->expectException(\Symfony\Component\Security\Core\Exception\UserNotFoundException::class);

        $passport = $this->jwtAuthenticator->authenticate($request);
        $passport->getUser();
    }

    private function createTestUser(): void
    {
        $this->testUserId = bin2hex(random_bytes(16));

        $passwordHash = password_hash($this->testPassword, PASSWORD_DEFAULT);

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

        $passwordHash = password_hash($this->testAdminPassword, PASSWORD_DEFAULT);

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
