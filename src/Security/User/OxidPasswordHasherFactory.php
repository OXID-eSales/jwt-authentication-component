<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use Symfony\Component\PasswordHasher\Hasher\PasswordHasherAwareInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

final readonly class OxidPasswordHasherFactory implements PasswordHasherFactoryInterface
{
    public function __construct(
        private OxidPasswordHasher $passwordHasher
    ) {
    }

    public function getPasswordHasher(PasswordAuthenticatedUserInterface|PasswordHasherAwareInterface|string $user): PasswordHasherInterface
    {
        return $this->passwordHasher;
    }
}
