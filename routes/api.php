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
  // Auth/ login/ register
  $api->post('/auth/register', [
    'as' => 'api.auth.register',
    'uses' => 'App\Http\Controllers\Auth\AuthController@Register',
  ]);

  $api->post('/auth/login', [
    'as' => 'api.auth.login',
    'uses' => 'App\Http\Controllers\Auth\AuthController@postLogin',
  ]);

//get all codes by device id
  $api->get('/place/get/app/{id}/',[
    'as' => 'place.get.app',
    'uses' => 'App\Http\Controllers\PlaceController@KhujTheSearchApp',
  ]);
/// Get place type and subtype
  $api->get('/place/get/sub/type/{type}/',[
      'as' => 'place.get.sub.type',
      'uses' => 'App\Http\Controllers\PlaceController@getPlaceSubType',
   ]);
  
   $api->get('/place/get/type/',[
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

    //get all the codes admin panel
    $api->get('/place/get/',[
      'as' => 'places.get',
      'uses' => 'App\Http\Controllers\PlaceController@shobai',
    ]);

    //delete place by place id()
    $api->get('/place/delete/{barikoicode}',[
      'as' => 'places.delete',
      'uses' => 'App\Http\Controllers\PlaceController@mucheFeli',
    ]);

    //update place by place code
    $api->post('/place/update/{barikoicode}',[
      'as' => 'places.update',
      'uses' => 'App\Http\Controllers\PlaceController@halnagad',
    ]);
//Get near by public places
    $api->get('/public/place/{ucode}',[
      'as' => 'place.public',
      'uses' => 'App\Http\Controllers\PlaceController@ashpash',
    ]);

//Get near by public places by  lon lat
$api->get('/public/find/nearby/place/',[
      'as' => 'place.lon.public',
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
   $api->post('/saved/place/delete/{id}',[
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

  //---------------------Business User Routes-----------------------//
    //Register a Business user: from "Admin panel" or "SignUp as a Business feature"
    $api->post('/business/register', [
        'as' => 'api.business.register',
        'uses' => 'App\Http\Controllers\BusinessApiController@RegisterBusinessUser',
    ]);

    //get all the codes admin panel
    $api->post('/business/keygen/',[
      'as' => 'business.keygen.email',
      'uses' => 'App\Http\Controllers\BusinessApiController@generateApiKey',
    ]);

    //pass the encoded API-KEY alog with post request
    $api->post('/business/StorePlace/{apikey}',[
      'as' => 'business.store.place',
      'uses' => 'App\Http\Controllers\BusinessApiController@addPlaceByBusinessUser',
    ]);
//search using BariKoi Code fofr business
    $api->get('/business/SearchPlace/{apikey}/{code}',[
      'as' => 'business.search.place',
      'uses' => 'App\Http\Controllers\BusinessApiController@searchPlaceByBusinessUser',
    ]);

    //places added by a business user
    $api->get('/business/PlacesAdded/{apikey}',[
      'as' => 'business.added.place',
      'uses' => 'App\Http\Controllers\BusinessApiController@PlacesAddedByBusinessUser',
    ]);

    //places added by a business user
    $api->get('/business/UpdatePlace/{apikey}',[
      'as' => 'business.update.place',
      'uses' => 'App\Http\Controllers\BusinessApiController@UpdatePlaceByBusinessUser',
    ]);
        //places added by a business user
    $api->get('/business/CurrentActiveKey/',[
      'as' => 'business.current.active.key',
      'uses' => 'App\Http\Controllers\BusinessApiController@getCurrentActiveKey',
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
               //Refresh Token 
        $api->patch('/auth/refresh', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@patchRefresh',
            'as' => 'api.auth.refresh'
        ]);

        $api->get('/auth/user', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@getUser',
            'as' => 'api.auth.user'
        ]);
	     
        //Delete Token
        $api->delete('/auth/invalidate', [
            'uses' => 'App\Http\Controllers\Auth\AuthController@deleteInvalidate',
            'as' => 'api.auth.invalidate'
        ]);

              //ADN: Show all codes for a specific Authenticated user by user_id (My Places)
      $api->get('/auth/placebyuid/{deviceid}', [
        'uses' => 'App\Http\Controllers\Auth\AuthController@getPlacesByUserId',
        'as' => 'api.auth.userid'
      ]);
  
      //ADN: add a new place
      $api->post('/auth/place/newplace',[
        'as' => 'api.auth.place.new',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authAddNewPlace',
      ]);

      $api->post('/auth/place/newplacecustom',[
        'as' => 'api.auth.place.new',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authAddCustomPlace',
      ]);
      
      //ADN: Update Place by Place Code
      $api->post('/auth/place/update/{barikoicode}',[
        'as' => 'api.auth.places.update',
        'uses' => 'App\Http\Controllers\Auth\AuthController@halnagadMyPlace',
      ]);
      
      //ADN:Delete place by BariKoi code
      $api->get('/auth/place/delete/{barikoicode}',[
        'as' => 'auth.places.delete',
        'uses' => 'App\Http\Controllers\Auth\AuthController@mucheFeliMyPlace',
      ]);

      //ADN: Get All List of Favorite Places for Authenticated User by user_id
      $api->get('/auth/savedplacebyuid',[
        'uses' => 'App\Http\Controllers\Auth\AuthController@getSavedPlacesByUserId',
        'as' => 'api.auth.savedplaces'  
      ]);
      //ADN: Add place to favorite 
      $api->post('/auth/save/place',[
        'as' => 'api.auth.places.favorite.add',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authAddFavoritePlace',
      ]);
      //ADN:remove place from favorite 
      $api->get('/auth/saved/place/delete/{barikoicode}',[
        'as' => 'api.auth.places.favorite.delete',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authDeleteFavoritePlace',
      ]);

    });
});

