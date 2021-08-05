<?php

/**
 * this file is part of Stargan oauth2 client
 * Stargan user profile
 *
 * @author fathur rohman <fathur.rohman@Stargan.go.id>
 *
 */

namespace Stargan\OAuth2\Client\Provider;

class StarganUser implements StarganUserInterface
{
    private $username;
    protected $profiles = [];
    protected $roles;
    public Security $security;
    protected $account;

    public function setAccout(array $account): self
    {
        $this->account = $account;
        $this->roles = ['ROLE_USER'];
        $this->username = $this->account['username'];
        if(isset($account['roles'])){
            $this->security = new Security($account['roles']);
        }else{
            //dump($account);exit;
        }
        $this->extractProfile($account);
        return $this;
    }

    public function getAccount()
    {
        return $this->account;
    }

    public function isValid(): bool
    {
        return isset($this->account['user']);
    }

    /**
     * get profile
     * batasan :
     * ! TIDAK BOLEH ADA NAMA PROFIL YANG SAMA UNTUK SATU ORANG
     * ! HANYA ADA SATU REALM UNTUK SETIAP PROFILE YANG DITARIK DARI DB
     * @param string|null $name
     * @return Profile|array
     */
    public function getProfiles(?string $name = null)
    {
        if (!$name) return $this->profiles;

        return isset($this->profiles[$name]) ? $this->profiles[$name] : false;
    }

    public function getId()
    {
        return $this->account['id'];
    }

    public function toArray()
    {
        return $this->account;
    }

    public function countProfiles()
    {
        return count($this->profiles);
    }

    public function extractProfile($account): ?array
    {
        foreach ($account['profiles'] as $key => $profile) {
            if (isset($profile["name"])) {
                $name = $profile["name"];
                $profile['user'] = (object)['username' => $account['username'] ];
                $this->profiles[$name] = new Profile($profile);
            }
        }
        return $this->profiles;
    }

    public function getSecurity(): ?Security
    {
        return $this->security;
    }

    public function getRoles(): ?array
    {
        $roles = $this->security->getRoles();
        foreach ($roles as $key => $value) {
            $this->roles[] = $value['name'];
        }
        return array_unique($this->roles);
    }

    public function  getPassword(): ?string
    {
        return null;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials()
    {
        //do nothing
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getUserIdentifier(): ?string
    {
        return $this->username;
    }

}
