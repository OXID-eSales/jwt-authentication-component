<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\Auth\AuthenticationListener;
use OxidEsales\AuthComponent\Security\User\ApiUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class AuthenticationListenerTest extends TestCase
{
    public function testGetSubscribedEvents(): void
    {
        $events = AuthenticationListener::getSubscribedEvents();

        $this->assertArrayHasKey('kernel.request', $events);
        $this->assertSame(['onKernelRequest', 8], $events['kernel.request']);
    }

    public function testSkipsLoginEndpoint(): void
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(false);
        $authenticator->expects($this->never())->method('authenticate');

        $listener = $this->createListener($authenticator);

        $request = new Request([], [], [], [], [], ['REQUEST_URI' => '/api/login']);
        $request->server->set('REQUEST_URI', '/api/login');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    private function createListener(AuthenticatorInterface $authenticator): AuthenticationListener
    {
        $tokenStorage = new TokenStorage();

        return new AuthenticationListener($authenticator, $tokenStorage);
    }

    public function testSkipsNonApiEndpoints(): void
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(false);
        $authenticator->expects($this->never())->method('authenticate');

        $listener = $this->createListener($authenticator);

        $request = new Request([], [], [], [], [], ['REQUEST_URI' => '/shop/product']);
        $request->server->set('REQUEST_URI', '/shop/product');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testPublicEndpointWithoutAuthentication(): void
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(false);
        $authenticator->expects($this->never())->method('authenticate');

        $listener = $this->createListener($authenticator);

        $request = new Request([], [], ['_controller' => 'TestController::publicMethod'], [], [], ['REQUEST_URI' => '/api/public']);
        $request->server->set('REQUEST_URI', '/api/public');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }


    public function testAuthenticatesValidRequest(): void
    {
        $user = new ApiUser('user123', 'user@example.com', ['ROLE_USER']);
        $passport = new SelfValidatingPassport(new UserBadge('user@example.com', fn() => $user));

        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(true);
        $authenticator->method('authenticate')->willReturn($passport);

        $listener = $this->createListener($authenticator);

        $controller = new class {
            #[IsGranted('ROLE_USER')]
            public function userMethod() {}
        };

        $request = new Request([], [], ['_controller' => [$controller, 'userMethod']], [], [], ['REQUEST_URI' => '/api/user', 'HTTP_AUTHORIZATION' => 'Bearer token']);
        $request->server->set('REQUEST_URI', '/api/user');
        $request->headers->set('Authorization', 'Bearer token');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertSame($user, $request->attributes->get('_api_user'));
    }

    public function testAuthenticationFailureThrowsException(): void
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(true);
        $authenticator->method('authenticate')->willThrowException(new AuthenticationException('Invalid token'));

        $listener = $this->createListener($authenticator);

        $request = new Request([], [], ['_controller' => 'TestController::method'], [], [], ['REQUEST_URI' => '/api/test', 'HTTP_AUTHORIZATION' => 'Bearer invalid']);
        $request->server->set('REQUEST_URI', '/api/test');
        $request->headers->set('Authorization', 'Bearer invalid');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid token');

        $listener->onKernelRequest($event);
    }

    public function testAllowsAccessWithValidTokenAndNoRequiredRoles(): void
    {
        $user = new ApiUser('user123', 'user@example.com', ['ROLE_USER']);
        $passport = new SelfValidatingPassport(new UserBadge('user@example.com', fn() => $user));

        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(true);
        $authenticator->method('authenticate')->willReturn($passport);

        $listener = $this->createListener($authenticator);

        $request = new Request([], [], ['_controller' => 'TestController::publicMethod'], [], [], ['REQUEST_URI' => '/api/test', 'HTTP_AUTHORIZATION' => 'Bearer token']);
        $request->server->set('REQUEST_URI', '/api/test');
        $request->headers->set('Authorization', 'Bearer token');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }

    public function testDoesNotAuthenticateWhenAuthenticatorDoesNotSupport(): void
    {
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $authenticator->method('supports')->willReturn(false);
        $authenticator->expects($this->never())->method('authenticate');

        $listener = $this->createListener($authenticator);

        $controller = new class {
            #[IsGranted('ROLE_USER')]
            public function method() {}
        };

        $request = new Request([], [], ['_controller' => [$controller, 'method']], [], [], ['REQUEST_URI' => '/api/test', 'HTTP_AUTHORIZATION' => 'Bearer token']);
        $request->server->set('REQUEST_URI', '/api/test');
        $request->headers->set('Authorization', 'Bearer token');
        $kernel = $this->createMock(HttpKernelInterface::class);
        $event = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);

        $listener->onKernelRequest($event);

        $this->assertNull($event->getResponse());
    }
}
