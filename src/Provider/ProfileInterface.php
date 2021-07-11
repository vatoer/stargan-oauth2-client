<?php

/**
 * this file is part of Stargan oauth2 client
 * Interface untuk profile
 * 
 * @author fathur rohman <fathur.rohman@Stargan.go.id>
 * 
 */

namespace Stargan\OAuth2\Client\Provider;

interface ProfileInterface
{
    /**
     * fungsi untuk security 
     *
     * @return SecurityInterface|null
     */
    public function getSecurity(): ?SecurityInterface;
}
