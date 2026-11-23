<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Tests\Unit\Security;

use OxidEsales\AuthComponent\Security\User\OxidPasswordHasher;
use OxidEsales\EshopCommunity\Internal\Domain\Authentication\Bridge\PasswordServiceBridgeInterface;
use PHPUnit\Framework\TestCase;

final class OxidPasswordHasherTest extends TestCase
{
    public function testHash(): void
    {
        $plainPassword = 'secret123';
        $hashedPassword = '$2y$10$hashedvalue';

        $passwordService = $this->createMock(PasswordServiceBridgeInterface::class);
        $passwordService
            ->expects($this->once())
            ->method('hash')
            ->with($plainPassword)
            ->willReturn($hashedPassword);

        $result = (new OxidPasswordHasher($passwordService))->hash($plainPassword);

        $this->assertSame($hashedPassword, $result);
    }

    public function testVerifyWithValidPassword(): void
    {
        $plainPassword = 'secret123';
        $hashedPassword = '$2y$10$hashedvalue';

        $passwordService = $this->createMock(PasswordServiceBridgeInterface::class);
        $passwordService
            ->expects($this->once())
            ->method('verifyPassword')
            ->with($plainPassword, $hashedPassword)
            ->willReturn(true);

        $result = (new OxidPasswordHasher($passwordService))->verify($hashedPassword, $plainPassword);

        $this->assertTrue($result);
    }

    public function testVerifyWithInvalidPassword(): void
    {
        $plainPassword = 'wrongpassword';
        $hashedPassword = '$2y$10$hashedvalue';

        $passwordService = $this->createMock(PasswordServiceBridgeInterface::class);
        $passwordService
            ->expects($this->once())
            ->method('verifyPassword')
            ->with($plainPassword, $hashedPassword)
            ->willReturn(false);

        $result = (new OxidPasswordHasher($passwordService))->verify($hashedPassword, $plainPassword);

        $this->assertFalse($result);
    }

    public function testVerifyWithEmptyHashedPassword(): void
    {
        $passwordService = $this->createMock(PasswordServiceBridgeInterface::class);
        $passwordService
            ->expects($this->never())
            ->method('verifyPassword');

        $result = (new OxidPasswordHasher($passwordService))->verify('', 'anypassword');

        $this->assertFalse($result);
    }

    public function testNeedsRehash(): void
    {
        $hasher = new OxidPasswordHasher($this->createStub(PasswordServiceBridgeInterface::class));

        $this->assertFalse($hasher->needsRehash('$2y$10$anyhash'));
    }
}
