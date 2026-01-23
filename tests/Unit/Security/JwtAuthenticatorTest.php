<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\DataSet;
use OxidEsales\AuthComponent\Security\Auth\JwtAuthenticator;
use OxidEsales\AuthComponent\Security\Auth\TokenService;
use OxidEsales\AuthComponent\Security\Auth\Exception\InvalidTokenException;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use OxidEsales\AuthComponent\Security\User\ApiUserProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

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
        $this->authenticator = new JwtAuthenticator($this->tokenService, $this->userProvider);
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
            ->willThrowException(new InvalidTokenException('Invalid token'));

        $this->expectException(AuthenticationException::class);

        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateReturnsPassportForValidToken(): void
    {
        $user = new ApiUser('user123', 'user@example.com', ['ROLE_USER']);

        $realTokenService = new TokenService('test-secret-key-for-testing-must-be-at-least-256-bits-long', 3600);
        $tokenString = $realTokenService->generateToken('user123', 'user@example.com', ['ROLE_USER']);

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $tokenString);

        $userProvider = $this->createMock(ApiUserProvider::class);
        $userProvider
            ->method('loadUserByIdentifier')
            ->with('user@example.com')
            ->willReturn($user);

        $authenticator = new JwtAuthenticator($realTokenService, $userProvider);

        $passport = $authenticator->authenticate($request);

        $this->assertSame($user, $passport->getUser());
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
        $this->assertSame('Test authentication failed', $content['message']);
    }
}
