<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\Auth\ExceptionListener;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class ExceptionListenerTest extends TestCase
{
    public function testGetSubscribedEvents(): void
    {
        $events = ExceptionListener::getSubscribedEvents();

        $this->assertArrayHasKey(KernelEvents::EXCEPTION, $events);
        $this->assertSame(['onKernelException', 0], $events[KernelEvents::EXCEPTION]);
    }

    public function testAccessDeniedForUnauthenticatedUser(): void
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker
            ->expects($this->once())
            ->method('isGranted')
            ->with('IS_AUTHENTICATED_FULLY')
            ->willReturn(false);

        $event = $this->createExceptionEvent(new AccessDeniedException());

        (new ExceptionListener($authChecker))->onKernelException($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Authentication required', $content['error']);
    }

    public function testAccessDeniedForAuthenticatedUser(): void
    {
        $authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $authChecker
            ->expects($this->once())
            ->method('isGranted')
            ->with('IS_AUTHENTICATED_FULLY')
            ->willReturn(true);

        $event = $this->createExceptionEvent(new AccessDeniedException());

        (new ExceptionListener($authChecker))->onKernelException($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(403, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Access denied', $content['error']);
        $this->assertSame('Insufficient permissions', $content['message']);
    }

    public function testAuthenticationException(): void
    {
        $event = $this->createExceptionEvent(new AuthenticationException('Invalid token'));

        $this->createListener()->onKernelException($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Authentication failed', $content['error']);
    }

    public function testOtherExceptionNotHandled(): void
    {
        $event = $this->createExceptionEvent(new \RuntimeException('Some error'));

        $this->createListener()->onKernelException($event);

        $this->assertNull($event->getResponse());
    }

    private function createListener(): ExceptionListener
    {
        return new ExceptionListener($this->createStub(AuthorizationCheckerInterface::class));
    }

    private function createExceptionEvent(\Throwable $exception): ExceptionEvent
    {
        $kernel = $this->createStub(HttpKernelInterface::class);
        $request = new Request();

        return new ExceptionEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST, $exception);
    }
}
