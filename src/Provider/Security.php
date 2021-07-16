<?php
namespace Stargan\OAuth2\Client\Provider;

use Exception;

class Security implements SecurityInterface
{
    private $targets;
    private array $options;

    public function __construct( array $options )
    {
        $this->options = $options;
    }

    /**
     * roles should not overlap over other realm
     * @return array
     */
    public function getRoles(): ?array
    {
        if (isset($this->roles)) return $this->roles;
        $this->roles = [];
        foreach ($this->options as $key => $profileRole)
        {
            if(isset($profileRole['role'])){
                $role = $profileRole['role'];
                $this->roles[$role['name']] = $role;
            }
        }
        return $this->roles;
    }

    /**
     * get permission
     *
     * @return array|null
     */
    public function getPermissions(): ?array
    {
        if (isset($this->permissions)) return $this->permissions;
        $this->permissions = [];
        $roles = $this->getRoles(); // ! TODO CHEK ULANG
        foreach ($roles as $key => $role)
        {
            $permissions = $role["permissions"];
            foreach ( $permissions as $key => $rolePermissions) {
                $permission = $rolePermissions['permission'];
                $this->permissions[$permission['name']] =  $permission;
            }
        }
        return $this->permissions;
    }

    public function getTargets()
    {
        if(isset($this->targets)) return $this->targets;
        $this->targets = [];
        foreach ($this->getPermissions() as $key => $permission) {
            $object  = $permission['object'];
            $otName = $object['name'];
            if(!isset($this->targets[$otName])){
                $object['allowCreate'] = $permission['allowCreate'];
                $object['allowRead'] = $permission['allowRead'];
                $object['allowUpdate'] = $permission['allowUpdate'];
                $object['allowDelete'] = $permission['allowDelete'];
                $this->targets[$otName] = $object;
            }else{
                // ! PENTING BERLAKU OPERASI AND
                //
                $this->target[$otName]['allowCreate'] = $permission['allowCreate'] && $this->target[$otName]['allowCreate'];
                $this->target[$otName]['allowRead'] = $permission['allowRead'] && $this->target[$otName]['allowRead'];
                $this->target[$otName]['allowUpdate'] = $permission['allowUpdate'] && $this->target[$otName]['allowUpdate'];
                $this->target[$otName]['allowDelete'] = $permission['allowDelete'] && $this->target[$otName]['allowDelete'];
            }

        }
        return $this->targets;
        //return array_unique($targets);
    }

    public function hasTarget(string $name)
    {
        if (array_key_exists($name, $this->getTargets() )) {
            return $this->targets[$name];
        }
        return false;
    }

    /**
     * fungsi untuk cek permission pada target
     *
     * @param string $target
     * @return boolean|null
     */
    public function isAllowCreate(string $target)
    {
        return $this->_isAllow('create',$target);
    }

    /**
     * fungsi untuk cek permission pada target
     *
     * @param string $target
     * @return boolean|null
     */
    public function isAllowRead(string $target)
    {
        return $this->_isAllow('read',$target);
    }

    /**
     * fungsi untuk cek permission pada target
     *
     * @param string $target
     * @return boolean|null
     */
    public function isAllowUpdate(string $target)
    {
        return $this->_isAllow('update',$target);
    }

    /**
     * fungsi untuk cek permission pada target
     *
     * @param string $target
     * @return boolean|null
     */
    public function isAllowDelete(string $target)
    {
        return $this->_isAllow('delete',$target);
    }

    /**
     * Check is $action is allowed on $taget
     *
     * @param string $action
     * @param string $target
     * @return bool
     */
    private function _isAllow($action='create', $targetName=null )
    {
        switch ($action) {
            case 'create':
            case 'read':
            case 'update':
            case 'delete':
                $allow = 'allow'.ucfirst($action);
                break;
            default:
                throw new Exception("parameter out of scope e98x11CD, ", 500);
                return false;
                break;
        }

        if (array_key_exists($targetName, $this->getTargets())) {
            return $this->targets[$targetName][$allow];
        }
        return false;
    }

    public function hasRole(string $name)
    {
        if (array_key_exists($name, $this->getRoles())) {
            return $this->roles[$name];
        }
        return false;
        //return $this->_recursive_array_search($name, $this->getRoles());
    }


    public function hasPermission(string $permissionName)
    {
        if (array_key_exists($permissionName, $this->getPermissions())) {
            return $this->permissions[$permissionName];
        }
        return false;
    }


}
