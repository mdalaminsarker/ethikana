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

$api = $app->make(Dingo\Api\Routing\Router::class);

$api->version('v1', function ($api) {

/// Get place type and subtype
  $api->get('/place/get/sub/type/{type}/',[
      'as' => 'place.get.sub.type',
      'uses' => 'App\Http\Controllers\PlaceController@getPlaceSubType',
   ]);

   $api->get('/place/get/type/{type}/',[
     'as' => 'place.type.get',
     'uses' => 'App\Http\Controllers\PlaceController@getPlaceType',
   ]);
  /// Post place type and subtype
   $api->post('/place/type',[
     'as' => 'place.type',
     'uses' => 'App\Http\Controllers\PlaceController@placeType',
   ]);
   $api->post('/place/sub/type',[
     'as' => 'place.sub.type',
     'uses' => 'App\Http\Controllers\PlaceController@placeSubType',
   ]);
   // Auth/ login/ register
    $api->post('/auth/login', [
        'as' => 'api.auth.login',
        'uses' => 'App\Http\Controllers\Auth\AuthController@postLogin',
    ]);
    $api->post('/auth/register', [
        'as' => 'api.auth.register',
        'uses' => 'App\Http\Controllers\Auth\AuthController@Register',
    ]);
  // Post place addresss lon lat
    $api->post('/place/post',[
      'as' => 'place.post',
      'uses' => 'App\Http\Controllers\PlaceController@StorePlace',
    ]);
  // Post custom code
    $api->post('/place/custom/post',[
      'as' => 'place.post.custom',
      'uses' => 'App\Http\Controllers\PlaceController@StoreCustomPlace',
    ]);
    //get place by barikoicode
    $api->get('/place/get/{id}/',[
      'as' => 'place.get',
      'uses' => 'App\Http\Controllers\PlaceController@KhujTheSearch',
    ]);
    //get all codes by device id
    $api->get('/place/get/app/{id}/',[
      'as' => 'place.get.app',
      'uses' => 'App\Http\Controllers\PlaceController@KhujTheSearchApp',
    ]);
    //get all the codes admin panel
    $api->get('/place/get/',[
      'as' => 'places.get',
      'uses' => 'App\Http\Controllers\PlaceController@shobai',
    ]);
    //delete place by ucode
    $api->get('/place/delete/{id}',[
      'as' => 'places.delete',
      'uses' => 'App\Http\Controllers\PlaceController@mucheFeli',
    ]);
    //update place by ucode
    $api->post('/place/update/{id}',[
      'as' => 'places.update',
      'uses' => 'App\Http\Controllers\PlaceController@halnagad',
    ]);

    //search
    $api->get('/place/search/{name}/',[
      'as' => 'places.search',
      'uses' => 'App\Http\Controllers\PlaceController@search',
    ]);
    //Get near by public places
    $api->get('/public/place/{ucode}',[
      'as' => 'place.public',
      'uses' => 'App\Http\Controllers\PlaceController@ashpash',
    ]);

    $api->get('/public/find/nearby/place/',[
      'as' => 'place.public',
      'uses' => 'App\Http\Controllers\PlaceController@amarashpash',
    ]);
    $api->get('/analytics',[
      'as' => 'place.analytics',
      'uses' => 'App\Http\Controllers\PlaceController@analytics',
    ]);
    $api->post('/save/place',[
      'as' => 'place.save',
      'uses' => 'App\Http\Controllers\PlaceController@savedPlaces',
    ]);
    $api->get('/saved/place/get/{id}',[
      'as' => 'places.saved.get',
      'uses' => 'App\Http\Controllers\PlaceController@getSavedPlace',
    ]);

    $api->get('/saved/place/delete/{id}',[
      'as' => 'places.saved.delete',
      'uses' => 'App\Http\Controllers\PlaceController@DeleteSavedPlace',
    ]);
    $api->get('/get/count',[
      'as' => 'place.count',
      'uses' => 'App\Http\Controllers\PlaceController@count',
    ]);

    $api->post('/connect/us/',[
      'as' => 'place.contact',
      'uses' => 'App\Http\Controllers\PlaceController@contactUS',
    ]);

    $api->post('/update/custom/code/{id}',[
      'as' => 'place.update.code',
      'uses' => 'App\Http\Controllers\PlaceController@updateCustomCode',
    ]);




  /*
   */



///Auth api starts
    $api->group([
        'middleware' => 'api.auth',
    ], function ($api) {
        $api->get('/', [
            'uses' => 'App\Http\Controllers\APIController@getIndex',
            'as' => 'api.index'
        ]);


        $api->get('/auth/user', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@getUser',
            'as' => 'api.auth.user'
        ]);
        $api->patch('/auth/refresh', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@patchRefresh',
            'as' => 'api.auth.refresh'
        ]);
        $api->delete('/auth/invalidate', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@deleteInvalidate',
            'as' => 'api.auth.invalidate'
        ]);

    });
});
