<?php namespace Jpasilan\Ldap;

use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\AliasLoader;

class LdapServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('jpasilan/ldap');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
        $this->app['ldap'] = $this->app->share(function($app){
            return new Ldap($app['config']->get('ldap'));
        });

        $this->app->booting(function(){
            $loader = AliasLoader::getInstance();
            $loader->alias('Ldap', 'Jpasilan\Ldap\Facades\Ldap');
        });
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('ldap');
	}

}