<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

declare(strict_types=1);

namespace OxidEsales\AuthComponent\Security\Auth;

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use OxidEsales\AuthComponent\Security\User\OxidAwareUserInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class TokenService implements TokenServiceInterface
{
    private ?Configuration $config = null;
    private ClockInterface $clock;
    private ?array $validationConstraints = null;

    public function __construct(
        private ?string $secretKey = null,
        private string $issuer = 'oxid-api',
        private string $audience = 'oxid-api',
        private int $expirationSeconds = 3600,
        ?ClockInterface $clock = null
    ) {

        $this->clock = $clock ?? new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('now', new DateTimeZone('UTC'));
            }
        };
    }

    public function getConfiguration(): Configuration
    {
        if ($this->secretKey === null || $this->secretKey === '') {
            throw new \RuntimeException(
                'JWT authentication is not configured. Set the API_JWT_SECRET environment variable.'
            );
        }

        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($this->secretKey)
        );

        return $this->config;
    }

    public function getValidatorConstrains(): array
    {

        if ($this->validationConstraints === null) {
            $config = $this->getConfiguration();

            $this->validationConstraints = [
                new SignedWith($config->signer(), $config->signingKey()),
                new IssuedBy($this->issuer),
                new PermittedFor($this->audience),
            ];
        }

        return $this->validationConstraints;
    }


    public function generateToken(OxidAwareUserInterface $user): string
    {
        $now = $this->clock->now();

        $token = $this->getConfiguration()->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($this->audience)
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify(sprintf('+%d seconds', $this->expirationSeconds)))
            ->withClaim('userId', $user->getOxid())
            ->getToken($this->getConfiguration()->signer(), $this->getConfiguration()->signingKey());

        return $token->toString();
    }

    public function parseToken(string $token): Plain
    {
        try {
            $parsedToken = $this->getConfiguration()->parser()->parse($token);
        } catch (\Throwable $e) {
            throw new AuthenticationException('Unable to parse token', 0, $e);
        }

        if (!$this->isValid($parsedToken)) {
            throw new AuthenticationException('Invalid token');
        }

        if ($this->isExpired($parsedToken)) {
            throw new AuthenticationException('Token expired');
        }

        return $parsedToken;
    }

    public function validateToken(string $token): bool
    {
        try {
            $this->parseToken($token);
            return true;
        } catch (AuthenticationException) {
            return false;
        }
    }

    private function isValid(Plain $token): bool
    {
        return $this->getConfiguration()->validator()->validate($token, ...$this->getValidatorConstrains());
    }

    private function isExpired(Plain $token): bool
    {
        return $token->isExpired($this->clock->now());
    }
}
