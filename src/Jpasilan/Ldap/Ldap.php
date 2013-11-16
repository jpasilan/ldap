<?php namespace Jpasilan\Ldap;

class Ldap
{
    /**
     * Stores the LDAP configuration values.
     *
     * @var config
     */
    protected $config;

    /**
     * Stores the LDAP connection resource.
     *
     * @var $conn
     */
    protected $conn;

    /**
     * Stores the LDAP entries from Ldap::search()
     *
     * @var $ldapEntries
     */
    protected $ldapEntries = array();


    /**
     * Class constructor and initializes an LDAP connection.
     *
     * @param array $config
     * @throws \Exception
     */
    public function __construct($config)
    {
        $this->config = $config;

        // Checks first whether the PHP LDAP extension is installed in the server.
        if (!function_exists('ldap_connect')) {
            throw new \Exception('Requires the php-ldap extension to be installed.');
        }

        $this->conn = ldap_connect($config['host'], $config['port']);
        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    }

    /**
     * Unset the class variables on object destruction.
     */
    public function __destruct()
    {
        $this->config = null;
        $this->ldapEntries = array();

        ldap_close($this->conn);
    }

    /**
     * Abstracts the ldap_bind() function. Returns a boolean value that determines whether bind is successful.
     *
     * @param string $dn
     * @param string $password
     * @param boolean $is_user
     * @return bool
     */
    public function bind($dn, $password, $is_user = true)
    {
        $dn = $is_user ? $this->setUserDn($dn) : $dn;

        $bind = (!empty($dn) && !empty($password))
            ? ldap_bind($this->conn, $dn, $password)
            : ldap_bind($this->conn); // Bind anonymously to the LDAP server

        return $bind ? true : false;
    }

    /**
     * Bind using the admin credentials from configuration.
     */
    public function bindWithAdmin()
    {
        return $this->bind($this->config['admin_dn'], $this->config['admin_pw'], false);
    }

    /**
     * Abstracts the ldap_search() function. Returns the array retrieved from ldap_get_entries().
     *
     * @param $filter
     * @return array
     */
    public function search($filter)
    {
        $entries = array();

        if (!empty($filter)) {
            $filter = "($filter)";
            $result = @ldap_search($this->conn, $this->setUserDn(), $filter, $this->config['read_attributes']);
            $entries = @ldap_get_entries($this->conn, $result);
        }

        $this->ldapEntries = $entries;
    }

    /**
     * Get an attribute from an LDAP entry.
     *
     * @param $attribute
     * @return string
     */
    public function getAttribute($attribute)
    {
        $value = null;

        if (!empty($attribute) && isset($this->ldapEntries[0][$attribute][0])) {
            $value = $this->ldapEntries[0][$attribute][0];
        }

        return $value;
    }

    /**
     * Abstracts the ldap_mod_replace function.
     *
     * @param string $dn
     * @param array $attribute
     * @return bool
     */
    public function replace($dn, $attribute)
    {
        return ldap_mod_replace($this->conn, $this->setUserDn($dn), $attribute);
    }

    /**
     * Change the LDAP password.
     *
     * @param string $dn
     * @param string $password
     * @return bool
     */
    public function changePassword($dn, $password)
    {
        // Encode the password according to LDAP specs.
        $newPassword = "{SHA}" . base64_encode(pack("H*", sha1($password)));

        return $this->replace($dn, array('userPassword' => $newPassword));
    }

    /**
     * Set the User DN.
     *
     * @param string $dn
     * @return string
     */
    private function setUserDn($dn = '')
    {
        return !empty($dn)
            ? $dn . ',' . $this->config['user_dn']
            : $this->config['user_dn'];
    }
}