<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

readonly class ExceptionListener implements EventSubscriberInterface
{
    public function __construct(
        private AuthorizationCheckerInterface $authorizationChecker
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::EXCEPTION => ['onKernelException', 0],
        ];
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();

        if ($exception instanceof AccessDeniedException) {
            $isAuthenticated = $this->authorizationChecker->isGranted('IS_AUTHENTICATED_FULLY');

            if (!$isAuthenticated) {
                $response = new JsonResponse(
                    ['error' => 'Authentication required'],
                    Response::HTTP_UNAUTHORIZED
                );
            } else {
                $response = new JsonResponse(
                    ['error' => 'Access denied', 'message' => 'Insufficient permissions'],
                    Response::HTTP_FORBIDDEN
                );
            }
            $event->setResponse($response);
        } elseif ($exception instanceof AuthenticationException) {
            $response = new JsonResponse(
                ['error' => 'Authentication failed'],
                Response::HTTP_UNAUTHORIZED
            );
            $event->setResponse($response);
        }
    }
}
