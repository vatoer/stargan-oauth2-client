<?php 

namespace Stargan\OAuth2\Client\Provider;

interface SecurityInterface
{
    /**
     * get All roles
     *
     * @return array
     */
    public function getRoles():?array;

    /**
     * get permissions
     *
     * @return array|null
     */
    public function getPermissions():?array;

    
    /**
     * Check if profile has Role
     *
     * @param string $roleName
     * @return boolean
     */
    public function hasRole(string $roleName);

    /**
     * Check if profile has Role
     * @param string $permissionName
     * @return boolean
     */
    public function hasPermission(string $permissionName);
}