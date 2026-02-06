<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use OxidEsales\EshopCommunity\Internal\Domain\Authentication\Bridge\PasswordServiceBridgeInterface;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

final readonly class OxidPasswordHasher implements PasswordHasherInterface
{
    public function __construct(
        private PasswordServiceBridgeInterface $passwordService
    ) {
    }

    public function hash(#[\SensitiveParameter] string $plainPassword): string
    {
        return $this->passwordService->hash($plainPassword);
    }

    public function verify(string $hashedPassword, #[\SensitiveParameter] string $plainPassword): bool
    {
        if ($hashedPassword === '') {
            return false;
        }

        return $this->passwordService->verifyPassword($plainPassword, $hashedPassword);
    }

    public function needsRehash(string $hashedPassword): bool
    {
        return false;
    }
}
