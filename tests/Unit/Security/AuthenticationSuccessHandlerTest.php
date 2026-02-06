<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\Auth\AuthenticationSuccessHandler;
use OxidEsales\AuthComponent\Security\Auth\TokenServiceInterface;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class AuthenticationSuccessHandlerTest extends TestCase
{
    public function testOnAuthenticationSuccessWithApiUser(): void
    {
        $user = new ApiUser('user123', 'user@test.com', ['ROLE_USER']);
        $jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...';

        $tokenService = $this->createMock(TokenServiceInterface::class);
        $tokenService
            ->expects($this->once())
            ->method('generateToken')
            ->with($user)
            ->willReturn($jwtToken);

        $securityToken = $this->createMock(TokenInterface::class);
        $securityToken->method('getUser')->willReturn($user);

        $handler = new AuthenticationSuccessHandler($tokenService);
        $response = $handler->onAuthenticationSuccess(new Request(), $securityToken);

        $this->assertSame(200, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame($jwtToken, $content['token']);
        $this->assertSame('user@test.com', $content['user']['username']);
        $this->assertSame(['ROLE_USER'], $content['user']['roles']);
    }

    public function testOnAuthenticationSuccessWithNonApiUserReturnsError(): void
    {
        $nonApiUser = $this->createMock(UserInterface::class);

        $tokenService = $this->createMock(TokenServiceInterface::class);
        $tokenService->expects($this->never())->method('generateToken');

        $securityToken = $this->createMock(TokenInterface::class);
        $securityToken->method('getUser')->willReturn($nonApiUser);

        $handler = new AuthenticationSuccessHandler($tokenService);
        $response = $handler->onAuthenticationSuccess(new Request(), $securityToken);

        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Invalid user type', $content['error']);
    }
}
