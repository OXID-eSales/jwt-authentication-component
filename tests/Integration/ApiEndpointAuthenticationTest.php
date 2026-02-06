<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Integration;

use OxidEsales\EshopCommunity\Core\Di\ContainerFacade;
use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\EshopCommunity\Internal\Framework\Module\Install\DataObject\OxidEshopPackage;
use OxidEsales\EshopCommunity\Internal\Framework\Module\Install\Service\ModuleInstallerInterface;
use OxidEsales\EshopCommunity\Internal\Framework\Module\Setup\Bridge\ModuleActivationBridgeInterface;
use OxidEsales\EshopCommunity\Internal\Transition\Utility\BasicContextInterface;
use PHPUnit\Framework\TestCase;

final class ApiEndpointAuthenticationTest extends TestCase
{
    private const BASE_URL = 'http://localhost.local';
    private const MODULE_ID = 'oxid_jwt_test_module';
    private const MODULE_SOURCE_PATH = __DIR__ . '/../Fixtures/TestModule';

    private string $regularUserId;
    private string $regularUsername = 'test-regular@example.com';
    private string $regularPassword = 'userpassword123';

    private string $adminUserId;
    private string $adminUsername = 'test-admin@example.com';
    private string $adminPassword = 'adminpassword123';

    private QueryBuilderFactoryInterface $queryBuilderFactory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->queryBuilderFactory = $this->get(QueryBuilderFactoryInterface::class);

        $this->installModuleFixture();
        $this->activateModuleFixture();
        $this->createTestUsers();
    }

    protected function tearDown(): void
    {
        $this->deleteTestUsers();
        $this->uninstallModuleFixture();
        parent::tearDown();
    }

    public function testPublicEndpointWithoutAuthentication(): void
    {
        $response = $this->curl('GET', '/api/test/public');

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('Public endpoint - no authentication required', $response['body']['message']);
        $this->assertArrayHasKey('timestamp', $response['body']);
    }

    public function testPublicEndpointWithAuthentication(): void
    {
        $token = $this->login($this->regularUsername, $this->regularPassword);
        $response = $this->curl('GET', '/api/test/public', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('Public endpoint - no authentication required', $response['body']['message']);
    }

    public function testUserEndpointWithoutAuthentication(): void
    {
        $response = $this->curl('GET', '/api/test/user');

        $this->assertSame(401, $response['http_code']);
        $this->assertSame('Authentication required', $response['body']['error']);
    }

    public function testUserEndpointWithRegularUserToken(): void
    {
        $token = $this->login($this->regularUsername, $this->regularPassword);
        $response = $this->curl('GET', '/api/test/user', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('User endpoint - ROLE_USER required', $response['body']['message']);
        $this->assertContains('ROLE_USER', $response['body']['user']['roles']);
    }

    public function testUserEndpointWithAdminToken(): void
    {
        $token = $this->login($this->adminUsername, $this->adminPassword);
        $response = $this->curl('GET', '/api/test/user', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('User endpoint - ROLE_USER required', $response['body']['message']);
        $this->assertContains('ROLE_USER', $response['body']['user']['roles']);
        $this->assertContains('ROLE_ADMIN', $response['body']['user']['roles']);
    }

    public function testAdminEndpointWithoutAuthentication(): void
    {
        $response = $this->curl('GET', '/api/test/admin');

        $this->assertSame(401, $response['http_code']);
        $this->assertSame('Authentication required', $response['body']['error']);
    }

    public function testAdminEndpointWithRegularUserToken(): void
    {
        $token = $this->login($this->regularUsername, $this->regularPassword);
        $response = $this->curl('GET', '/api/test/admin', [], $token);

        $this->assertSame(403, $response['http_code']);
        $this->assertSame('Access denied', $response['body']['error']);
        $this->assertSame('Insufficient permissions', $response['body']['message']);
    }

    public function testAdminEndpointWithAdminToken(): void
    {
        $token = $this->login($this->adminUsername, $this->adminPassword);
        $response = $this->curl('GET', '/api/test/admin', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('Admin endpoint - ROLE_ADMIN required', $response['body']['message']);
        $this->assertContains('ROLE_ADMIN', $response['body']['user']['roles']);
    }

    public function testInfoEndpointWithoutAuthentication(): void
    {
        $response = $this->curl('GET', '/api/test/info');

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('Info endpoint - optional authentication', $response['body']['message']);
        $this->assertFalse($response['body']['authenticated']);
        $this->assertNull($response['body']['user']);
    }

    public function testInfoEndpointWithAuthentication(): void
    {
        $token = $this->login($this->regularUsername, $this->regularPassword);
        $response = $this->curl('GET', '/api/test/info', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame('Info endpoint - optional authentication', $response['body']['message']);
        $this->assertTrue($response['body']['authenticated']);
        $this->assertSame($this->regularUsername, $response['body']['user']['username']);
    }

    public function testInvalidToken(): void
    {
        $response = $this->curl('GET', '/api/test/user', [], 'invalid.jwt.token');

        $this->assertSame(401, $response['http_code']);
        $this->assertSame('Authentication failed', $response['body']['error']);
    }

    public function testProfileEndpointWithValidToken(): void
    {
        $token = $this->login($this->regularUsername, $this->regularPassword);
        $response = $this->curl('GET', '/api/profile', [], $token);

        $this->assertSame(200, $response['http_code']);
        $this->assertSame($this->regularUsername, $response['body']['username']);
        $this->assertContains('ROLE_USER', $response['body']['roles']);
    }

    private function login(string $username, string $password): string
    {
        $response = $this->curl('POST', '/api/login', [
            'username' => $username,
            'password' => $password,
        ]);

        $this->assertSame(200, $response['http_code'], 'Login failed: ' . json_encode($response['body']));
        $this->assertArrayHasKey('token', $response['body']);

        return $response['body']['token'];
    }

    private function curl(string $method, string $path, array $body = [], ?string $token = null): array
    {
        $url = self::BASE_URL . $path;
        $ch = curl_init($url);

        $headers = ['Content-Type: application/json'];
        if ($token) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        if (!empty($body)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        }

        $responseBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        return [
            'http_code' => $httpCode,
            'body' => json_decode($responseBody, true) ?? [],
        ];
    }

    private function get(string $serviceId)
    {
        return ContainerFacade::get($serviceId);
    }

    private function installModuleFixture(): void
    {
        $this->get(ModuleInstallerInterface::class)
            ->install($this->getPackageFixture());
    }

    private function activateModuleFixture(): void
    {
        $this->get(ModuleActivationBridgeInterface::class)
            ->activate(self::MODULE_ID, $this->get(BasicContextInterface::class)->getDefaultShopId());
    }

    private function uninstallModuleFixture(): void
    {
        $this->get(ModuleInstallerInterface::class)
            ->uninstall($this->getPackageFixture());
    }

    private function getPackageFixture(): OxidEshopPackage
    {
        return new OxidEshopPackage(self::MODULE_SOURCE_PATH);
    }

    private function createTestUsers(): void
    {
        $this->regularUserId = bin2hex(random_bytes(16));

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
                'oxid' => $this->regularUserId,
                'username' => $this->regularUsername,
                'password' => password_hash($this->regularPassword, PASSWORD_DEFAULT),
                'active' => 1,
                'rights' => 'user',
                'shopid' => 1,
            ])
            ->execute();

        $this->adminUserId = bin2hex(random_bytes(16));

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
                'oxid' => $this->adminUserId,
                'username' => $this->adminUsername,
                'password' => password_hash($this->adminPassword, PASSWORD_DEFAULT),
                'active' => 1,
                'rights' => 'malladmin',
                'shopid' => 1,
            ])
            ->execute();
    }

    private function deleteTestUsers(): void
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->delete('oxuser')
            ->where('OXID IN (:ids)')
            ->setParameter('ids', [$this->regularUserId, $this->adminUserId], \Doctrine\DBAL\Connection::PARAM_STR_ARRAY)
            ->execute();
    }

}
