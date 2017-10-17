<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
	public function register()
	{
		$this->app->alias('bugsnag.logger', \Illuminate\Contracts\Logging\Log::class);
		$this->app->alias('bugsnag.logger', \Psr\Log\LoggerInterface::class);
	  $this->app->singleton('mailer', function ($app) {
	        return $app->loadComponent('mail', 'Illuminate\Mail\MailServiceProvider', 'mailer');
	    });
		if ($this->app->environment() == 'local') {
        $this->app->register('Wn\Generators\CommandsServiceProvider');
    }
	}
}
