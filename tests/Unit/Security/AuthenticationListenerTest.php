<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\Auth\AuthenticationListener;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Firewall\FirewallListenerInterface;

final class AuthenticationListenerTest extends TestCase
{
    public function testSubscribesToKernelRequest(): void
    {
        $this->assertSame(
            [KernelEvents::REQUEST => ['onKernelRequest', 8]],
            AuthenticationListener::getSubscribedEvents()
        );
    }

    public function testAuthenticatesWhenSupported(): void
    {
        $event = $this->createRequestEvent();

        $firewallListener = $this->createMock(FirewallListenerInterface::class);
        $firewallListener->method('supports')->willReturn(true);
        $firewallListener->expects($this->once())->method('authenticate')->with($event);

        (new AuthenticationListener($firewallListener))->onKernelRequest($event);
    }

    public function testAuthenticatesWhenSupportIsLazy(): void
    {
        $event = $this->createRequestEvent();

        $firewallListener = $this->createMock(FirewallListenerInterface::class);
        $firewallListener->method('supports')->willReturn(null);
        $firewallListener->expects($this->once())->method('authenticate')->with($event);

        (new AuthenticationListener($firewallListener))->onKernelRequest($event);
    }

    public function testSkipsWhenNotSupported(): void
    {
        $firewallListener = $this->createMock(FirewallListenerInterface::class);
        $firewallListener->method('supports')->willReturn(false);
        $firewallListener->expects($this->never())->method('authenticate');

        (new AuthenticationListener($firewallListener))->onKernelRequest($this->createRequestEvent());
    }

    private function createRequestEvent(): RequestEvent
    {
        return new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            new Request(),
            HttpKernelInterface::MAIN_REQUEST
        );
    }
}
