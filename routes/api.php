<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$app->post('/auth/login', ['uses' => 'Auth\AuthController@postLogin', 'as' => 'api.auth.login']);

$app->group([
    'middleware' => 'jwt.auth',
    'namespace' => 'App\Http\Controllers'
], function ($app) {
    $app->get('/', ['uses' => 'APIController@getIndex', 'as' => 'api.index']);
    $app->get('/auth/user', ['uses' => 'Auth\AuthController@getUser', 'as' => 'api.auth.user']);
    $app->patch('/auth/refresh', ['uses' => 'Auth\AuthController@patchRefresh', 'as' => 'api.auth.refresh']);
    $app->delete('/auth/invalidate', ['uses' => 'Auth\AuthController@deleteInvalidate', 'as' => 'api.auth.invalidate']);
});
