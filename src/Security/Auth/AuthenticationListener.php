<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

final class AuthenticationListener implements EventSubscriberInterface
{
    public function __construct(
        private readonly AuthenticatorInterface $authenticator,
        private readonly TokenStorage $tokenStorage
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 8],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();

        if ($this->authenticator->supports($request)) {
            $passport = $this->authenticator->authenticate($request);
            $user = $passport->getUser();

            $token = new UsernamePasswordToken($user, 'api', $user->getRoles());
            $this->tokenStorage->setToken($token);
            $request->attributes->set('_api_user', $user);
        }
    }
}
