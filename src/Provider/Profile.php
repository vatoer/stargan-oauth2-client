<?php

/**
 * this file is part of Stargan oauth2 client
 * profile implementation
 * 
 * @author fathur rohman <fathur.rohman@Stargan.go.id>
 * 
 */

namespace Stargan\OAuth2\Client\Provider;

use App\Entity\Permissions;
use Exception;
use Stargan\OAuth2\Client\Exception\UserException;

class Profile implements ProfileInterface
{
    protected $permissions;
    protected $targets;
    //protected $profileRoles;
    protected $roles;
    protected $realm;
    protected $user;
    protected Security $security;

    public function __construct(
        protected array $options
    ) {
        $this->_extractOptions($options);
    }

    private function _extractOptions(array $options)
    {
        $this->_extractUser($options);
        $this->realm = isset($options['realm']) ? $options['realm'] : null; 
        if(isset($options['roles'])){
            $this->security = new Security($options['roles']);
        }
    }

    /**
     * make sure that every profile have user
     *
     * @return void
     */
    private function _extractUser($options)
    {
        if( !isset($options['user']) )
        {
            throw new UserException('profile doesnt have user key ExPu01',401);
        }
        return $this->user = $options['user'];
    }

    public function getUser()
    {
        return $this->user;
    }

    public function getRealm()
    {
        return $this->realm;
    }

    public function getOptions()
    {
        return $this->options;
    }

    public function getSecurity(): ?Security
    {
        return $this->security;
    }

}
