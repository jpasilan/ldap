<?php namespace Jpasilan\Ldap;

use Illuminate\Support\Facades\Config;

class Ldap
{
    /**
     * Stores the LDAP configuration values.
     *
     * @var $config
     */
    protected $config;

    /**
     * Stores the LDAP connection resource.
     *
     * @var $conn
     */
    protected $conn;

    /**
     * Stores the LDAP entries from ldap_get_entries().
     *
     * @var $ldap_entries
     */
    protected $ldap_entries = array();


    /**
     * Class constructor and initiates an LDAP connection.
     *
     * @throws \Exception
     */
    public function __construct()
    {
        // Get the package configuration
        $this->config = \Config::get('ldap::default');

        if (empty($this->config['host'])) {
            // Otherwise, retrieve it from the app configuration.
            $this->config = \Config::get('ldap');
        }

        // Check if at least the host and port values are set. Otherwise, throw an exception.
        if (empty($this->config['host']) || empty($this->config['port'])) {
            throw new \Exception('Host and port values are not set. Check either the application or package config file.');
        }

        // Checks first whether the PHP LDAP extension is installed in the server.
        if (!function_exists('ldap_connect')) {
            throw new \Exception('Requires the php-ldap extension to be installed.');
        }

        // Initiate an LDAP connection and set the necessary option.
        $this->conn = ldap_connect($this->config['host'], $this->config['port']);
        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
    }

    /**
     * Unset the class variables and close connection on object destruction.
     */
    public function __destruct()
    {
        // Unset the class properties.
        $this->config = null;
        $this->ldap_entries = array();

        // Close LDAP connection.
        if ($this->conn) {
            ldap_close($this->conn);
        }
    }

    /**
     * Wrapper function of the ldap_bind(). Returns a boolean value that determines whether bind is successful.
     *
     * @param string $dn
     * @param string $password
     * @param boolean $is_user
     * @return bool
     */
    public function bind($dn = '', $password = '', $is_user = true)
    {
        $dn = $is_user && !empty($dn) ? $this->setUserDn($dn) : $dn;

        $bind = (!empty($dn) && !empty($password))
            ? ldap_bind($this->conn, $dn, $password)
            : ldap_bind($this->conn); // Bind anonymously to the LDAP server

        return $bind ? true : false;
    }

    /**
     * Bind using the admin credentials from configuration.
     *
     * @return bool
     */
    public function bindWithAdmin()
    {
        return $this->bind($this->config['admin_dn'], $this->config['admin_pw'], false);
    }

    /**
     * Wrapper function of ldap_search(). Returns the array retrieved from ldap_get_entries().
     *
     * @param $filter
     * @return void
     */
    public function search($filter)
    {
        $entries = array();

        if (!empty($filter)) {
            $filter = "($filter)";
            $result = ldap_search($this->conn, $this->setUserDn(), $filter, $this->config['read_attributes']);
            $entries = ldap_get_entries($this->conn, $result);
        }

        $this->ldap_entries = $entries;
    }

    /**
     * Get an attribute from an LDAP entry.
     *
     * @param $attribute
     * @return mixed
     */
    public function getAttribute($attribute)
    {
        $value = null;

        if (!empty($attribute) && isset($this->ldap_entries[0][$attribute][0])) {
            $value = $this->ldap_entries[0][$attribute][0];
        }

        return $value;
    }

    /**
     * Wrapper function of ldap_mod_replace().
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
        $new_password = "{SHA}" . base64_encode(pack("H*", sha1($password)));

        return $this->replace($dn, array('userPassword' => $new_password));
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