<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class TokenServiceTest extends TestCase
{
    private TokenService $tokenService;
    private string $secretKey = 'test-secret-key-for-unit-tests-must-be-at-least-256-bits-long';
    private string $issuer = 'oxid-api';
    private string $audience = 'oxid-api';
    private int $expirationSeconds = 3600;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tokenService = new TokenService(
            $this->secretKey,
            $this->issuer,
            $this->audience,
            $this->expirationSeconds
        );
    }

    public function testGenerateToken(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);

        $token = $this->tokenService->generateToken($user);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        $this->assertStringContainsString('.', $token); // JWT format check
    }

    public function testGenerateTokenWithAdminRole(): void
    {
        $user = new ApiUser('admin123', 'admin@test.com', ['ROLE_USER', 'ROLE_ADMIN']);

        $token = $this->tokenService->generateToken($user);

        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame('admin123', $parsedToken->claims()->get('userId'));
        $this->assertFalse($parsedToken->claims()->has('username'));
        $this->assertFalse($parsedToken->claims()->has('roles'));
    }

    public function testParseValidToken(): void
    {
        $user = new ApiUser('user456', 'user456@test.com', ['ROLE_USER']);

        $token = $this->tokenService->generateToken($user);
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame('user456', $parsedToken->claims()->get('userId'));
    }

    public function testParseInvalidToken(): void
    {
        $invalidToken = 'invalid.token.here';

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken($invalidToken);
    }

    public function testParseTokenWithInvalidSignature(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $this->tokenService->generateToken($user);

        $differentService = new TokenService(
            'different-secret-key-for-testing-at-least-256-bits',
            $this->issuer,
            $this->audience,
            3600
        );

        $this->expectException(AuthenticationException::class);

        $differentService->parseToken($token);
    }

    public function testValidateToken(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $this->tokenService->generateToken($user);

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
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $this->tokenService->generateToken($user);
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertTrue($parsedToken->claims()->has('iss'));
        $this->assertTrue($parsedToken->claims()->has('aud'));
        $this->assertTrue($parsedToken->claims()->has('jti'));
        $this->assertTrue($parsedToken->claims()->has('iat'));
        $this->assertTrue($parsedToken->claims()->has('exp'));
    }

    public function testTokenIssuerAndAudience(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $this->tokenService->generateToken($user);
        $parsedToken = $this->tokenService->parseToken($token);

        $this->assertSame([$this->audience], $parsedToken->claims()->get('aud'));
        $this->assertTrue($parsedToken->hasBeenIssuedBy($this->issuer));
    }

    public function testTokenWithCustomIssuerAndAudience(): void
    {
        $customIssuer = 'custom-issuer';
        $customAudience = 'custom-audience';
        $customTokenService = new TokenService(
            $this->secretKey,
            $customIssuer,
            $customAudience,
            $this->expirationSeconds
        );

        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $customTokenService->generateToken($user);
        $parsedToken = $customTokenService->parseToken($token);

        $this->assertSame([$customAudience], $parsedToken->claims()->get('aud'));
        $this->assertTrue($parsedToken->hasBeenIssuedBy($customIssuer));
    }

    public function testParseTokenWithWrongIssuer(): void
    {
        $otherService = new TokenService(
            $this->secretKey,
            'other',
            $this->audience,
            $this->expirationSeconds
        );

        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $otherService->generateToken($user);

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken($token);
    }

    public function testParseTokenWithWrongAudience(): void
    {
        $otherService = new TokenService(
            $this->secretKey,
            $this->issuer,
            'other',
            $this->expirationSeconds
        );

        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $otherService->generateToken($user);

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken($token);
    }

    public function testParseExpiredToken(): void
    {
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->secretKey)
        );

        $now = new DateTimeImmutable();
        $expiredToken = $config->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($this->audience)
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now->modify('-2 hours'))
            ->expiresAt($now->modify('-1 hour'))
            ->withClaim('userId', 'user123')
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken($expiredToken);
    }

    public function testGenerateTokenWithCustomExpiration(): void
    {
        $customExpiration = 7200;
        $customTokenService = new TokenService(
            $this->secretKey,
            $this->issuer,
            $this->audience,
            $customExpiration
        );

        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $customTokenService->generateToken($user);
        $parsedToken = $customTokenService->parseToken($token);

        $issuedAt = $parsedToken->claims()->get('iat');
        $expiresAt = $parsedToken->claims()->get('exp');

        $this->assertSame($customExpiration, $expiresAt->getTimestamp() - $issuedAt->getTimestamp());
    }

    public function testEachTokenHasUniqueJti(): void
    {
        $user = new ApiUser('oxid123', 'user@test.com', ['ROLE_USER']);

        $jti1 = $this->tokenService->parseToken($this->tokenService->generateToken($user))->claims()->get('jti');
        $jti2 = $this->tokenService->parseToken($this->tokenService->generateToken($user))->claims()->get('jti');

        $this->assertNotSame($jti1, $jti2);
    }

    public function testTamperedPayloadIsRejected(): void
    {
        $user = new ApiUser('oxid123', 'user@test.com', ['ROLE_USER']);
        $token = $this->tokenService->generateToken($user);

        $parts = explode('.', $token);
        $payload = json_decode(base64_decode(str_pad(strtr($parts[1], '-_', '+/'), (int) (ceil(strlen($parts[1]) / 4) * 4), '=')), true);
        $payload['userId'] = 'hacked@test.com';
        $parts[1] = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken(implode('.', $parts));
    }

    public function testAlgNoneTokenIsRejected(): void
    {
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $header = rtrim(strtr(base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'none'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'iss' => $this->issuer,
            'aud' => [$this->audience],
            'jti' => bin2hex(random_bytes(16)),
            'iat' => $now->getTimestamp(),
            'exp' => $now->getTimestamp() + 3600,
            'userId' => 'admin@example.com',
        ])), '+/', '-_'), '=');

        $this->expectException(AuthenticationException::class);

        $this->tokenService->parseToken($header . '.' . $payload . '.');
    }

    public function testConstructorThrowsExceptionWhenSecretKeyIsNull(): void
    {
        $this->expectException(\RuntimeException::class);

        new TokenService(null);
    }

    public function testTokenServiceUsesInjectedClock(): void
    {
        $fixedTime = new DateTimeImmutable('2024-01-15 12:00:00', new DateTimeZone('UTC'));
        $clock = $this->createMock(ClockInterface::class);
        $clock->method('now')->willReturn($fixedTime);

        $tokenService = new TokenService(
            $this->secretKey,
            $this->issuer,
            $this->audience,
            $this->expirationSeconds,
            $clock
        );

        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $token = $tokenService->generateToken($user);
        $parsedToken = $tokenService->parseToken($token);

        $issuedAt = $parsedToken->claims()->get('iat');
        $this->assertSame($fixedTime->getTimestamp(), $issuedAt->getTimestamp());
    }
}
