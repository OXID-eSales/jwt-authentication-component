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
    private PasswordServiceBridgeInterface $passwordService;
    private OxidPasswordHasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->passwordService = $this->createMock(PasswordServiceBridgeInterface::class);
        $this->hasher = new OxidPasswordHasher($this->passwordService);
    }

    public function testHash(): void
    {
        $plainPassword = 'secret123';
        $hashedPassword = '$2y$10$hashedvalue';

        $this->passwordService
            ->expects($this->once())
            ->method('hash')
            ->with($plainPassword)
            ->willReturn($hashedPassword);

        $result = $this->hasher->hash($plainPassword);

        $this->assertSame($hashedPassword, $result);
    }

    public function testVerifyWithValidPassword(): void
    {
        $plainPassword = 'secret123';
        $hashedPassword = '$2y$10$hashedvalue';

        $this->passwordService
            ->expects($this->once())
            ->method('verifyPassword')
            ->with($plainPassword, $hashedPassword)
            ->willReturn(true);

        $result = $this->hasher->verify($hashedPassword, $plainPassword);

        $this->assertTrue($result);
    }

    public function testVerifyWithInvalidPassword(): void
    {
        $plainPassword = 'wrongpassword';
        $hashedPassword = '$2y$10$hashedvalue';

        $this->passwordService
            ->expects($this->once())
            ->method('verifyPassword')
            ->with($plainPassword, $hashedPassword)
            ->willReturn(false);

        $result = $this->hasher->verify($hashedPassword, $plainPassword);

        $this->assertFalse($result);
    }

    public function testVerifyWithEmptyHashedPassword(): void
    {
        $this->passwordService
            ->expects($this->never())
            ->method('verifyPassword');

        $result = $this->hasher->verify('', 'anypassword');

        $this->assertFalse($result);
    }

    public function testNeedsRehash(): void
    {
        $result = $this->hasher->needsRehash('$2y$10$anyhash');

        $this->assertFalse($result);
    }
}
