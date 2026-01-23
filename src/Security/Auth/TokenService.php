<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use OxidEsales\AuthComponent\Security\Auth\Exception\InvalidTokenException;
use Psr\Clock\ClockInterface;

class TokenService implements TokenServiceInterface
{
    private Configuration $config;
    private ClockInterface $clock;
    private SignedWith $signatureConstraint;

    public function __construct(
        private readonly string $secretKey,
        private readonly int $expirationSeconds = 3600
    ) {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->secretKey)
        );

        $this->clock = new class implements ClockInterface {
            public function now(): \DateTimeImmutable
            {
                return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
            }
        };

        $this->signatureConstraint = new SignedWith($this->config->signer(), $this->config->signingKey());
    }

    public function generateToken(string $userId, string $username, array $roles = ['ROLE_USER']): string
    {
        $now = new DateTimeImmutable();

        $token = $this->config->builder()
            ->issuedBy('oxid-api')
            ->permittedFor('oxid-api')
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify(sprintf('+%d seconds', $this->expirationSeconds)))
            ->withClaim('uid', $userId)
            ->withClaim('username', $username)
            ->withClaim('roles', $roles)
            ->getToken($this->config->signer(), $this->config->signingKey());

        return $token->toString();
    }

    public function parseToken(string $token): Plain
    {
        try {
            $parsedToken = $this->config->parser()->parse($token);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Unable to parse token', 0, $e);
        }

        if (!$this->hasValidSignature($parsedToken)) {
            throw new InvalidTokenException('Invalid token signature');
        }

        if ($this->isExpired($parsedToken)) {
            throw new InvalidTokenException('Token expired');
        }

        return $parsedToken;
    }

    public function validateToken(string $token): bool
    {
        try {
            $this->parseToken($token);
            return true;
        } catch (InvalidTokenException) {
            return false;
        }
    }

    private function hasValidSignature(Plain $token): bool
    {
        return $this->config->validator()->validate($token, $this->signatureConstraint);
    }

    private function isExpired(Plain $token): bool
    {
        return $token->isExpired($this->clock->now());
    }
}
