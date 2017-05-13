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

  $api->post('/imageTestUp', [
    'as' => 'image.file',
    'uses' => 'App\Http\Controllers\PlaceController@TestImageUp',
  ]);
  // Auth/ login/ register
  $api->post('/auth/register', [
    'as' => 'api.auth.register',
    'uses' => 'App\Http\Controllers\Auth\AuthController@Register',
  ]);

  $api->post('/auth/login', [
    'as' => 'api.auth.login',
    'uses' => 'App\Http\Controllers\Auth\AuthController@postLogin',
  ]);

  $api->post('admin/login', [
    'as' => 'api.admin.login',
    'uses' => 'App\Http\Controllers\Auth\AuthController@postLoginAdmin',
  ]);

   //ADN: Password Reset/email
   $api->post('/auth/password/reset',[
     'as' => 'auth.password.reset',
     'uses' => 'App\Http\Controllers\Auth\AuthController@resetPassword',
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
    $api->get('/place/get/{ucode}/',[
      'as' => 'place.get',
      'uses' => 'App\Http\Controllers\PlaceController@KhujTheSearch',
    ]);
    //search by place id
    $api->get('/place/pid/{pid}/',[
      'as' => 'place.get.pid',
      'uses' => 'App\Http\Controllers\PlaceController@KhujTheSearchPid',
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

    //Get near by public places by  Name
    $api->get('/public/find/{name}',[
      'as' => 'place.searchby.name',
      'uses' => 'App\Http\Controllers\PlaceController@search',
    ]);
    
    $api->get('/web/search/{nameorcode}',[
      'as' => 'web.searchby.nameorcode',
      'uses' => 'App\Http\Controllers\PlaceController@searchNameAndCodeWeb',
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

    //review-rating
    //all reviews for an address (which is a business)
      $api->get('/reviews/{pid}',[
        'as' => 'all.reviews.',
        'uses' => 'App\Http\Controllers\ReviewController@index',
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

      $api->post('/auth/UpdatePass',[
        'as' => 'user.updatePass',
        'uses' => 'App\Http\Controllers\Auth\AuthController@UpdatePass',
      ]);

            //mail test route : dont use in prod
      $api->post('/auth/UpdatePass12',[
        'as' => 'user.updatePass',
        'uses' => 'App\Http\Controllers\Auth\AuthController@UpdatePass12',
      ]);
      
      //ADN: Show all codes for a specific Authenticated user by user_id (My Places)
      $api->get('/auth/placebyuid/{deviceid}', [
        'uses' => 'App\Http\Controllers\Auth\AuthController@getPlacesByUserDeviceId',
        'as' => 'api.auth.deviceid'
      ]);
      //Show all places by User ID: for web mainly
      $api->get('/auth/placeby/userid/', [
        'uses' => 'App\Http\Controllers\Auth\AuthController@getPlacesByUserId',
        'as' => 'api.auth.userid'
      ]);
            //ADN:Change My Password
       $api->post('/auth/password/change',[
         'uses' => 'App\Http\Controllers\Auth\AuthController@changePasswordByUser',
         'as' => 'auth.password.change',
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
      //search for client:app
      $api->get('/auth/search/{bcode}',[
        'as' => 'auth.app.search',
        'uses' => 'App\Http\Controllers\Auth\AuthController@AppKhujTheSearch',
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

      //Generate Ref_Code for Early Users;(22thpril Onward,Ref_Code auto generated on Registration)
      $api->get('/auth/generate/refcode/',[
        'as' => 'api.auth.generate.refcode',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authRefCodeGen',
      ]);

      //Redeem A Ref_Code
      $api->post('/auth/redeem/referrals',[
        'as' => 'api.auth.redeem.refcode',
        'uses' => 'App\Http\Controllers\Auth\AuthController@authRedeemRefCode',
      ]);
      //ADN: busines_key generate
      $api->post('/auth/business/keygen/',[
        'as' => 'auth.business.keygen.email',
        'uses' => 'App\Http\Controllers\BusinessApiController@generateApiKey',
      ]);
      //ADN: current active key
      $api->get('/auth/business/CurrentActiveKey/',[
        'as' => 'business.current.active.keys',
        'uses' => 'App\Http\Controllers\BusinessApiController@getCurrentActiveKey',
      ]);

      //Add Business Details by Business User
      $api->post('/auth/business/AddDescription/{pid}',[
        'as' => 'business.add.description',
        'uses' => 'App\Http\Controllers\BusinessApiController@AddBusinessDescription',
      ]);

      //Add Business Details by Business User
      $api->get('/auth/business/ShowDescription/{pid}',[
        'as' => 'business.show.description',
        'uses' => 'App\Http\Controllers\BusinessApiController@ShowBusinessDescription',
      ]);
      //Get Users List
      $api->get('/auth/admin/userlist',[
        'as' => 'admin.listusers',
        'uses' => 'App\Http\Controllers\Auth\AuthController@getUserList',
      ]);

      //review-rating
      //save a review+rating for a place id

      $api->post('/reviews/{pid}',[
        'as' => 'all.reviews.',
        'uses' => 'App\Http\Controllers\ReviewController@store',
      ]);

      $api->post('/reviews/update/{id}',[
        'as' => 'upddate.reviews.',
        'uses' => 'App\Http\Controllers\ReviewController@update',
      ]);
      //analytics

      $api->get('/analytics',[
        'as' => 'place.analytics',
        'uses' => 'App\Http\Controllers\Auth\AuthController@analytics',
      ]);

      $api->get('/offers/{pid}',[
        'as' => 'get.business.offers',
        'uses' => 'App\Http\Controllers\OfferController@show',
      ]);

      $api->post('/offers/{pid}',[
        'as' => 'post.business.offers',
        'uses' => 'App\Http\Controllers\OfferController@store',
      ]);

      $api->post('/offers/update/{id}',[
        'as' => 'update.business.offers',
        'uses' => 'App\Http\Controllers\OfferController@update',
      ]);

      $api->get('/offers/delete/{id}',[
        'as' => 'delete.business.offers',
        'uses' => 'App\Http\Controllers\OfferController@destroy',
      ]);

      $api->get('/app/search/{nameorcode}',[
        'as' => 'app.searchby.nameorcode',
        'uses' => 'App\Http\Controllers\PlaceController@searchNameAndCodeApp',
      ]);
      
      $api->post('/image', [
        'as' => 'image.upload',
        'uses' => 'App\Http\Controllers\PlaceController@store',
      ]);


  });
});

