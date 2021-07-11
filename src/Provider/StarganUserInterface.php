<?php

/**
 * this file is part of Stargan oauth2 client
 * Stargan user profile
 * 
 * @author fathur rohman <fathur.rohman@Stargan.go.id>
 * 
 */

namespace Stargan\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

Interface StarganUserInterface extends ResourceOwnerInterface
{
    
    public function setAccout(array $account):self;

    public function getAccount();

    public function isValid(): bool;

    /**
     * get profile
     * batasan : 
     * ! TIDAK BOLEH ADA NAMA PROFIL YANG SAMA UNTUK SATU ORANG
     * ! HANYA ADA SATU REALM UNTUK SETIAP PROFILE YANG DITARIK DARI DB
     * @param string|null $name
     * @return Profile|array|bool
     */
    public function getProfiles(?string $name = null);

    public function getId();

    public function toArray();

    public function countProfiles();

    /**
     * extract profile
     *
     * @param array $account
     * @return array|null Profile
     */
    public function extractProfile($account): ?array;

    public function getSecurity(): ?Security;

    public function getRoles(): ?array;

    public function  getPassword(): ?string;

    public function getSalt(): ?string;

    public function eraseCredentials();

    public function getUsername(): ?string;

    public function getUserIdentifier(): ?string;

}
