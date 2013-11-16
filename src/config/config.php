<?php

return array(
    'default' => array(
        /*
        |--------------------------------------------------------------------------
        | LDAP Host
        |
        | Example: 'name.domain'
        |--------------------------------------------------------------------------
        */

        'host' => '',

        /*
        |--------------------------------------------------------------------------
        | LDAP Port
        |
        | Example: 389
        |--------------------------------------------------------------------------
        */

        'port' => 389,

        /*
        |--------------------------------------------------------------------------
        | LDAP Base DN
        |
        | Example: 'ou=People,dc=name,dc=domain'
        |--------------------------------------------------------------------------
        */

        'user_dn' => '',

        /*
        |--------------------------------------------------------------------------
        | LDAP Admin DN
        |
        | The Admin DN that will be used for administrative functions.
        |
        | Example: 'cn=admin,dc=name,dc=domain'
        |--------------------------------------------------------------------------
        */

        'admin_dn' => '',

        /*
        |--------------------------------------------------------------------------
        | LDAP Admin Password
        |--------------------------------------------------------------------------
        */

        'admin_pw' => '',

        /*
        |--------------------------------------------------------------------------
        | LDAP Attributes
        |
        | List of the readable LDAP attributes.
        |
        | Example: array('sn', 'uid', 'mail')
        |--------------------------------------------------------------------------
        */

        'read_attributes' => array(),
    )
);