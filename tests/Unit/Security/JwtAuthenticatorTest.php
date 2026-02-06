<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\Auth\JwtAuthenticator;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessToken\HeaderAccessTokenExtractor;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class JwtAuthenticatorTest extends TestCase
{
    private TokenService $tokenService;
    private ApiUserProvider $userProvider;
    private JwtAuthenticator $authenticator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tokenService = $this->createMock(TokenService::class);
        $this->userProvider = $this->createMock(ApiUserProvider::class);
        $this->authenticator = new JwtAuthenticator($this->tokenService, $this->userProvider, new HeaderAccessTokenExtractor());
    }

    public function testSupportsReturnsTrueWhenAuthorizationHeaderPresent(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer token');

        $this->assertTrue($this->authenticator->supports($request));
    }

    public function testSupportsReturnsFalseWhenAuthorizationHeaderMissing(): void
    {
        $request = new Request();

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testSupportsReturnsFalseForNonBearerAuthorization(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');

        $this->assertFalse($this->authenticator->supports($request));
    }

    public function testAuthenticateThrowsExceptionForInvalidHeaderFormat(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'InvalidFormat token');

        $this->expectException(AuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionForInvalidToken(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer invalid-token');

        $this->tokenService
            ->method('parseToken')
            ->with('invalid-token')
            ->willThrowException(new AuthenticationException('Invalid token'));

        $this->expectException(AuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateReturnsPassportForValidToken(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);

        $realTokenService = new TokenService(
            'test-secret-key-for-testing-must-be-at-least-256-bits-long',
            'oxid-api',
            'oxid-api',
            3600
        );
        $tokenString = $realTokenService->generateToken($user);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenString);

        $userProvider = $this->createMock(ApiUserProvider::class);
        $userProvider
            ->method('loadByOxid')
            ->with('user123')
            ->willReturn($user);

        $authenticator = new JwtAuthenticator($realTokenService, $userProvider, new HeaderAccessTokenExtractor());

        $passport = $authenticator->authenticate($request);

        $this->assertSame($user, $passport->getUser());
    }

    public function testAuthenticateThrowsExceptionForTokenWithoutUserIdClaim(): void
    {
        $realTokenService = new TokenService(
            'test-secret-key-for-testing-must-be-at-least-256-bits-long',
            'oxid-api',
            'oxid-api',
            3600
        );

        $config = \Lcobucci\JWT\Configuration::forSymmetricSigner(
            new \Lcobucci\JWT\Signer\Hmac\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText('test-secret-key-for-testing-must-be-at-least-256-bits-long')
        );
        $now = new \DateTimeImmutable();
        $tokenWithoutUserId = $config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+3600 seconds'))
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenWithoutUserId);

        $authenticator = new JwtAuthenticator($realTokenService, $this->userProvider, new HeaderAccessTokenExtractor());

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionForEmptyUserIdClaim(): void
    {
        $secret = 'test-secret-key-for-testing-must-be-at-least-256-bits-long';
        $config = \Lcobucci\JWT\Configuration::forSymmetricSigner(
            new \Lcobucci\JWT\Signer\Hmac\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($secret)
        );
        $now = new \DateTimeImmutable();
        $tokenWithEmptyUserId = $config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+3600 seconds'))
            ->withClaim('userId', '')
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $realTokenService = new TokenService($secret, 'oxid-api', 'oxid-api', 3600);
        $authenticator = new JwtAuthenticator($realTokenService, $this->userProvider, new HeaderAccessTokenExtractor());

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenWithEmptyUserId);

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionForArrayUserIdClaim(): void
    {
        $secret = 'test-secret-key-for-testing-must-be-at-least-256-bits-long';
        $config = \Lcobucci\JWT\Configuration::forSymmetricSigner(
            new \Lcobucci\JWT\Signer\Hmac\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($secret)
        );
        $now = new \DateTimeImmutable();
        $tokenWithArrayUserId = $config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+3600 seconds'))
            ->withClaim('userId', ['admin', 'hacker'])
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $realTokenService = new TokenService($secret, 'oxid-api', 'oxid-api', 3600);
        $authenticator = new JwtAuthenticator($realTokenService, $this->userProvider, new HeaderAccessTokenExtractor());

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenWithArrayUserId);

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request);
    }

    public function testAuthenticateThrowsExceptionForIntegerUserIdClaim(): void
    {
        $secret = 'test-secret-key-for-testing-must-be-at-least-256-bits-long';
        $config = \Lcobucci\JWT\Configuration::forSymmetricSigner(
            new \Lcobucci\JWT\Signer\Hmac\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::plainText($secret)
        );
        $now = new \DateTimeImmutable();
        $tokenWithIntUserId = $config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+3600 seconds'))
            ->withClaim('userId', 0)
            ->getToken($config->signer(), $config->signingKey())
            ->toString();

        $realTokenService = new TokenService($secret, 'oxid-api', 'oxid-api', 3600);
        $authenticator = new JwtAuthenticator($realTokenService, $this->userProvider, new HeaderAccessTokenExtractor());

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenWithIntUserId);

        $this->expectException(AuthenticationException::class);

        $authenticator->authenticate($request);
    }

    public function testOnAuthenticationSuccessReturnsNull(): void
    {
        $request = new Request();
        $token = $this->createMock(TokenInterface::class);

        $response = $this->authenticator->onAuthenticationSuccess($request, $token, 'api');

        $this->assertNull($response);
    }

    public function testOnAuthenticationFailureReturnsJsonResponse(): void
    {
        $request = new Request();
        $exception = new AuthenticationException('Test authentication failed');

        $response = $this->authenticator->onAuthenticationFailure($request, $exception);

        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Authentication failed', $content['error']);
    }
}
