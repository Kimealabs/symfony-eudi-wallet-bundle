<?php

declare(strict_types=1);

namespace Kimealabs\EudiWalletBundle\Trust;

interface JwksProviderInterface
{
    public function getJwks(string $issuer): array;
}
