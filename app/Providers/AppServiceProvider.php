<?php

namespace App\Providers;

use Illuminate\Cache\CacheManager;
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
        $this->app->singleton([CacheManager::class => 'cache'], function ($app) {
            $app->configure('cache');

            return new CacheManager($app);
        });
    }
}
