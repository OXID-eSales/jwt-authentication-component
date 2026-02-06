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
    private AuthorizationCheckerInterface $authChecker;
    private ExceptionListener $listener;

    protected function setUp(): void
    {
        parent::setUp();
        $this->authChecker = $this->createMock(AuthorizationCheckerInterface::class);
        $this->listener = new ExceptionListener($this->authChecker);
    }

    public function testGetSubscribedEvents(): void
    {
        $events = ExceptionListener::getSubscribedEvents();

        $this->assertArrayHasKey(KernelEvents::EXCEPTION, $events);
        $this->assertSame(['onKernelException', 0], $events[KernelEvents::EXCEPTION]);
    }

    public function testAccessDeniedForUnauthenticatedUser(): void
    {
        $this->authChecker
            ->method('isGranted')
            ->with('IS_AUTHENTICATED_FULLY')
            ->willReturn(false);

        $event = $this->createExceptionEvent(new AccessDeniedException());

        $this->listener->onKernelException($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Authentication required', $content['error']);
    }

    public function testAccessDeniedForAuthenticatedUser(): void
    {
        $this->authChecker
            ->method('isGranted')
            ->with('IS_AUTHENTICATED_FULLY')
            ->willReturn(true);

        $event = $this->createExceptionEvent(new AccessDeniedException());

        $this->listener->onKernelException($event);

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

        $this->listener->onKernelException($event);

        $response = $event->getResponse();
        $this->assertNotNull($response);
        $this->assertSame(401, $response->getStatusCode());

        $content = json_decode($response->getContent(), true);
        $this->assertSame('Authentication failed', $content['error']);
    }

    public function testOtherExceptionNotHandled(): void
    {
        $event = $this->createExceptionEvent(new \RuntimeException('Some error'));

        $this->listener->onKernelException($event);

        $this->assertNull($event->getResponse());
    }

    private function createExceptionEvent(\Throwable $exception): ExceptionEvent
    {
        $kernel = $this->createMock(HttpKernelInterface::class);
        $request = new Request();

        return new ExceptionEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST, $exception);
    }
}
