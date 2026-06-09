<?php

/**
 * Copyright © OXID eSales AG. All rights reserved.
 * See LICENSE file for license details.
 */

namespace OxidEsales\AuthComponent\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

interface OxidAwareUserInterface extends UserInterface
{
    public function getOxid(): string;
}
