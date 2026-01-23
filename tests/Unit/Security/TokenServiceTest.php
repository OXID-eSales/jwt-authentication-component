<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\Auth\Exception\InvalidTokenException;
use PHPUnit\Framework\TestCase;

final class TokenServiceTest extends TestCase
{
    private TokenService $tokenService;
    private string $secretKey = 'test-secret-key-for-unit-tests-must-be-at-least-256-bits-long';
    private int $expirationSeconds = 3600;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tokenService = new TokenService($this->secretKey, $this->expirationSeconds);
    }

    public function testGenerateToken(): void
    {
        $userId = 'user123';
        $username = 'test@example.com';
        $roles = ['ROLE_USER'];

        $token = $this->tokenService->generateToken($userId, $username, $roles);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        $this->assertStringContainsString('.', $token); // JWT format check
    }

    public function testGenerateTokenWithAdminRole(): void
    {
        $userId = 'admin123';
        $username = 'admin@example.com';
        $roles = ['ROLE_USER', 'ROLE_ADMIN'];

        $token = $this->tokenService->generateToken($userId, $username, $roles);

        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame($userId, $parsedToken->claims()->get('uid'));
        $this->assertSame($username, $parsedToken->claims()->get('username'));
        $this->assertSame($roles, $parsedToken->claims()->get('roles'));
    }

    public function testParseValidToken(): void
    {
        $userId = 'user456';
        $username = 'user@example.com';
        $roles = ['ROLE_USER'];

        $token = $this->tokenService->generateToken($userId, $username, $roles);
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame($userId, $parsedToken->claims()->get('uid'));
        $this->assertSame($username, $parsedToken->claims()->get('username'));
        $this->assertSame($roles, $parsedToken->claims()->get('roles'));
    }

    public function testParseInvalidToken(): void
    {
        $invalidToken = 'invalid.token.here';

        $this->expectException(InvalidTokenException::class);

        $this->tokenService->parseToken($invalidToken);
    }

    public function testParseTokenWithInvalidSignature(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');

        $differentService = new TokenService('different-secret-key-for-testing-at-least-256-bits', 3600);

        $this->expectException(InvalidTokenException::class);

        $differentService->parseToken($token);
    }

    public function testValidateToken(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');

        $isValid = $this->tokenService->validateToken($token);

        $this->assertTrue($isValid);
    }

    public function testValidateInvalidToken(): void
    {
        $isValid = $this->tokenService->validateToken('invalid.token.here');

        $this->assertFalse($isValid);
    }

    public function testTokenContainsStandardClaims(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertTrue($parsedToken->claims()->has('iss'));
        $this->assertTrue($parsedToken->claims()->has('aud'));
        $this->assertTrue($parsedToken->claims()->has('jti'));
        $this->assertTrue($parsedToken->claims()->has('iat'));
        $this->assertTrue($parsedToken->claims()->has('exp'));
    }

    public function testTokenIssuerAndAudience(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame(['oxid-api'], $parsedToken->claims()->get('aud'));
        $this->assertTrue($parsedToken->hasBeenIssuedBy('oxid-api'));
    }

    public function testGenerateTokenWithDefaultRoles(): void
    {
        $token = $this->tokenService->generateToken('user123', 'test@example.com');
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame(['ROLE_USER'], $parsedToken->claims()->get('roles'));
    }

    public function testParseExpiredToken(): void
    {
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->secretKey)
        );

        $now = new \DateTimeImmutable();
        $expiredToken = $config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now->modify('-2 hours'))
            ->expiresAt($now->modify('-1 hour'))
            ->withClaim('uid', 'user123')
            ->withClaim('username', 'test@example.com')
            ->withClaim('roles', ['ROLE_USER'])
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $this->expectException(InvalidTokenException::class);

        $this->tokenService->parseToken($expiredToken);
    }

    public function testGenerateTokenWithCustomExpiration(): void
    {
        $customExpiration = 7200;
        $customTokenService = new TokenService($this->secretKey, $customExpiration);

        $token = $customTokenService->generateToken('user123', 'test@example.com');
        $parsedToken = $customTokenService->parseToken($token);

        $issuedAt = $parsedToken->claims()->get('iat');
        $expiresAt = $parsedToken->claims()->get('exp');

        $this->assertSame($customExpiration, $expiresAt->getTimestamp() - $issuedAt->getTimestamp());
    }
}
