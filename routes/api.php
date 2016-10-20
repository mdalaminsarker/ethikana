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

$app->post('/auth/login', 'Auth\AuthController@postLogin');

$app->group([
    'middleware' => 'jwt.auth',
    'namespace' => 'App\Http\Controllers'
], function ($app) {
    $app->get('/', 'APIController@getIndex');
    $app->get('/auth/user', 'Auth\AuthController@getUser');
    $app->patch('/auth/refresh', 'Auth\AuthController@patchRefresh');
    $app->delete('/auth/invalidate', 'Auth\AuthController@deleteInvalidate');
});
