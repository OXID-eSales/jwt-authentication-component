<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\User;

use OxidEsales\EshopCommunity\Internal\Framework\Database\QueryBuilderFactoryInterface;
use OxidEsales\AuthComponent\Security\User\Exception\InvalidCredentialsException;

final readonly class CredentialValidator implements CredentialValidatorInterface
{
    public function __construct(
        private QueryBuilderFactoryInterface $queryBuilderFactory
    ) {
    }

    public function validateCredentials(string $username, string $password): array
    {
        $queryBuilder = $this->queryBuilderFactory->create();
        $queryBuilder
            ->select('OXID', 'OXUSERNAME', 'OXPASSWORD', 'OXRIGHTS')
            ->from('oxuser')
            ->where('OXUSERNAME = :username')
            ->andWhere('OXACTIVE = 1')
            ->setParameter('username', $username);

        $userData = $queryBuilder->execute()->fetchAssociative();

        if (!$userData || !$this->verifyPassword($password, $userData['OXPASSWORD'])) {
            throw new InvalidCredentialsException('Invalid credentials');
        }

        // Remove password from result before returning
        unset($userData['OXPASSWORD']);

        return $userData;
    }

    private function verifyPassword(string $password, string $hash): bool
    {
        if ($this->isSaltedHash($hash)) {
            return $this->verifySaltedPassword($password, $hash);
        }

        return $this->verifyLegacyPassword($password, $hash);
    }

    private function isSaltedHash(string $hash): bool
    {
        return str_contains($hash, '$');
    }

    private function verifySaltedPassword(string $password, string $hash): bool
    {
        [$storedHash, $salt] = explode('$', $hash, 2);
        $computedHash = hash('sha512', $password . $salt);
        return hash_equals($storedHash, $computedHash);
    }

    private function verifyLegacyPassword(string $password, string $hash): bool
    {
        $computedHash = hash('sha512', $password);
        return hash_equals($hash, $computedHash);
    }
}
