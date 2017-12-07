<?php

namespace jmrieger\OneSignal;

use Illuminate\Support\ServiceProvider;

class OneSignalServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {

    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        /** @noinspection PhpUndefinedFieldInspection */
        $this->app->singleton('onesignal', function () {
            /** @noinspection PhpUndefinedFunctionInspection */
            /** @noinspection PhpUndefinedFunctionInspection */
            /** @noinspection PhpUndefinedFunctionInspection */
            $config = [
                "app_id"        => "74881da6-0051-4a63-a008-39bf018375e5",
                "rest_api_key"  => "ZjQxNGNjMTktOWUzOC00NDY0LWFkODMtYzU0Yjg0YTY0YjVj",
                "user_auth_key" => "NjNkZTMyNjUtNmMzMy00NDZkLThiNmMtNzgzZjJkNjkyMWMx",
            ];

            $client = new OneSignalClient($config[ 'app_id' ], $config[ 'rest_api_key' ], $config[ 'user_auth_key' ]);

            return $client;
        });
    }

    public function provides()
    {
        return ['onesignal'];
    }


}
