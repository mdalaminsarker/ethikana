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

//bot search
  $api->post('/search0', [
    'as' => 'test.googlebot1',
    'uses' => 'App\Http\Controllers\BotSearchController@test1',
  ]);
  $api->post('/search1', [
    'as' => 'test.bot1',
    'uses' => 'App\Http\Controllers\BotSearchController@index',
  ]);

  $api->post('/up', [
    'as' => 'test.mtb.atm',
    'uses' => 'App\Http\Controllers\testController@mtb',
  ]);
//bot,ride search
  $api->get('/bot/pool/ride/search', [
    'as' => 'ride.search.bot',
    'uses' => 'App\Http\Controllers\PoolRideController@indexBot'
  ]);
  // $api->post('/atm', [
  //   'as' => 'test.mtb.atm',
  //   'uses' => 'App\Http\Controllers\testController@mtb',
  // ]);
  $api->post('/exc', [
    'as' => 'test.excel',
    'uses' => 'App\Http\Controllers\testController@excel',
  ]);
    $api->post('/search/nearby',[
      'as' => 'bot.search.nearby',
      'uses' => 'App\Http\Controllers\SearchController@findNearby',
    ]);
    $api->post('/search/all',[
      'as' => 'bot.search.all',
      'uses' => 'App\Http\Controllers\SearchController@findAll',
    ]);

    $api->post('/search/travel',[
      'as' => 'bot.search.travel',
      'uses' => 'App\Http\Controllers\SearchController@travel',
    ]);
    $api->post('/search/food',[
      'as' => 'bot.search.food',
      'uses' => 'App\Http\Controllers\SearchController@food',
    ]);
  $api->get('/searchlog', [
    'as' => 'search.log',
    'uses' => 'App\Http\Controllers\SearchController@searchLog',
  ]);

  $api->post('/landmarks', [
    'as' => 'nearest.landmarks',
    'uses' => 'App\Http\Controllers\LandmarkNavController@nearestLandmark',
  ]);

  $api->get('/elastic', [
    'as' => 'test.elastic.index',
    'uses' => 'App\Http\Controllers\testElasticController@index',
  ]);

#Test Routes Starts#
  //TEST: save log into a file
  $api->post('/filesave', [
    'as' => 'save.to.file',
    'uses' => 'App\Http\Controllers\testController@index',
  ]);
#Test Routes End#
  $api->get('/ip', [
    'as' => 'ip',
    'uses' => 'App\Http\Controllers\PlaceController@get_client_ip',
  ]);

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
    $api->post('/public/find/nearby/place/',[
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


      
    //full text
    
    $api->post('/search',[
      'as' => 'search.fulltext',
      'uses' => 'App\Http\Controllers\SearchController@index',
    ]);

    $api->post('/search/code',[
      'as' => 'search.code',
      'uses' => 'App\Http\Controllers\SearchController@indexCode',
    ]);
      
    //Leaderboard Till Date
    $api->get('/all/leaderboard',[
      'as' => 'public.leaderboard.tilldate',
      'uses' => 'App\Http\Controllers\LeaderBoardController@indexTillDate',
    ]);

    //Leaderboard Weekly
    $api->get('/weekly/leaderboard',[
      'as' => 'public.leaderboard.weekly',
      'uses' => 'App\Http\Controllers\LeaderBoardController@indexWeekly',
    ]);

    //Leaderboard Monthly
    $api->get('/monthly/leaderboard',[
      'as' => 'public.leaderboard.monthly',
      'uses' => 'App\Http\Controllers\LeaderBoardController@indexMonthly',
    ]);


    $api->get('/word',[
      'as' => 'random.words',
      'uses' => 'App\Http\Controllers\Auth\AuthTest0Controller@word',
    ]);

  /*
   */
 


///Auth api starts
    $api->group([
        'middleware' => 'api.auth',
    ], function ($api) {

      //Test Routes: with images
      $api->post('/test/auth/place/newplace',[
        'as' => 'test.api.auth.place.new',
        'uses' => 'App\Http\Controllers\Auth\AuthTest0Controller@authAddNewPlace',
      ]);

      $api->post('/test/auth/place/newplacecustom',[
        'as' => 'test.api.auth.place.newcustom',
        'uses' => 'App\Http\Controllers\Auth\AuthTest0Controller@authAddCustomPlace',
      ]);
      //Test Routes


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
      //analytics
      $api->get('/analytics',[
        'as' => 'place.analytics',
        'uses' => 'App\Http\Controllers\Auth\AuthController@analytics',
      ]);

      //ADN: Show all codes for a specific Authenticated user by user_id (My Places)
      $api->get('/auth/placebyuid/{deviceid}',[
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
//user info for Admin
      $api->get('/user/{id}',[
        'as' => 'user.individual',
        'uses' => 'App\Http\Controllers\UserManagementController@index',
      ]);
      //user profile details:Client
      $api->get('/user/profile/details',[
        'as' => 'user.profile.details',
        'uses' => 'App\Http\Controllers\UserProfileController@index'
      ]);

      $api->post('/user/profile/photo',[
        'as' => 'upolad.profile.pic',
        'uses' => 'App\Http\Controllers\UserProfileController@storeProPic',
      ]);

      $api->get('/user/profile/photo',[
        'as' => 'show.profile.pic',
        'uses' => 'App\Http\Controllers\UserProfileController@showProPic',
      ]);
      
      $api->delete('/user/profile/photo',[
        'as' => 'remove.profile.pic',
        'uses' => 'App\Http\Controllers\UserProfileController@destroyProPic',
      ]);

      $api->get('/user/{id}/places',[
        'as' => 'places.by.user',
        'uses' => 'App\Http\Controllers\UserManagementController@show',
      ]);

      $api->delete('/user/{id}/place',[
        'as' => 'delete.place',
        'uses' => 'App\Http\Controllers\UserManagementController@destroy',
      ]);

      $api->post('/user/{id}/place',[
        'as' => 'update.place',
        'uses' => 'App\Http\Controllers\UserManagementController@update',
      ]);

      $api->get('/app/search/{nameorcode}',[
        'as' => 'app.searchby.nameorcode',
        'uses' => 'App\Http\Controllers\PlaceController@searchNameAndCodeApp',
      ]);


    // //Start:Image Controller
      $api->post('/image', [
        'as' => 'image.store',
        'uses' => 'App\Http\Controllers\ImageController@store',
      ]);

      $api->get('/image/{pid}', [
        'as' => 'image.show',
        'uses' => 'App\Http\Controllers\ImageController@show',
      ]);

      // $api->delete('/image/{imageGetHash}', [
      //   'as' => 'image.delete',
      //   'uses' => 'App\Http\Controllers\ImageController@destroy',
      // ]);
    //#End: Image Controller

      //rewards controller starts
      /// rewards list for users
      $api->get('/rewards', [
        'as' => 'rewards.list',
        'uses' => 'App\Http\Controllers\RewardsController@index',
      ]);
      // request to redeem reward points
      $api->post('/reward', [
        'as' => 'rewards.redeem.request',
        'uses' => 'App\Http\Controllers\RewardsController@store',
      ]);
      //get the list of reward request/queue
      $api->get('/rewardhistory', [
        'as' => 'rewards.redeem.request',
        'uses' => 'App\Http\Controllers\RewardsController@show',
      ]);
      #User Part Ends#

      //Admin Part Starts
      //reward management controller(admin) starts
      //show the requested queue , for Admin
      $api->get('/admin/requests', [
        'as' => 'rewards.request.queue',
        'uses' => 'App\Http\Controllers\RewardRequestQueueController@index',
      ]);
      //show a specific request
      $api->get('/admin/requests/{id}', [
        'as' => 'rewards.request.queue.item',
        'uses' => 'App\Http\Controllers\RewardRequestQueueController@show',
      ]);
      // update a request
      $api->post('/admin/requests/update/{id}', [
        'as' => 'rewards.request.queue',
        'uses' => 'App\Http\Controllers\RewardRequestQueueController@update',
      ]);

      // reward management
      //show reward list
      $api->get('/admin/rewards', [
        'as' => 'all.rewards',
        'uses' => 'App\Http\Controllers\RewardsManagementController@index',
      ]);
      //show a reward item
      $api->get('/admin/reward/{id}', [
        'as' => 'reward.details',
        'uses' => 'App\Http\Controllers\RewardsManagementController@show',
      ]);
      //store new reward from admin
      $api->post('/admin/reward', [
        'as' => 'add.reward',
        'uses' => 'App\Http\Controllers\RewardsManagementController@store',
      ]);
      //update a reward item
      $api->post('/admin/reward/{id}', [
        'as' => 'update.reward',
        'uses' => 'App\Http\Controllers\RewardsManagementController@update',
      ]);
      //delete a reward item
      $api->delete('/admin/reward/{id}', [
        'as' => 'reward.delete',
        'uses' => 'App\Http\Controllers\RewardsManagementController@destroy',
      ]);

      //Enterprise Routes
      $api->get('/enterprise/places', [
        'as' => 'enterprise.total.places',
        'uses' => 'App\Http\Controllers\EnterpriseAnalyticsController@index'
      ]);
      $api->post('/enterprise/random/place', [
        'as' => 'enterprise.random.place',
        'uses' => 'App\Http\Controllers\EnterprisePlacesController@storeRandom'
      ]);
      $api->post('/enterprise/custom/place', [
        'as' => 'enterprise.custom.place',
        'uses' => 'App\Http\Controllers\EnterprisePlacesController@storeCustom'
      ]);
      //update 
      $api->post('/enterprise/place/{id}', [
        'as' => 'enterprise.update.place',
        'uses' => 'App\Http\Controllers\EnterprisePlacesController@update'
      ]);
      $api->get('/enterprise/place/{id}', [
        'as' => 'enterprise.single.place',
        'uses' => 'App\Http\Controllers\EnterprisePlacesController@show'
      ]);
      $api->delete('/enterprise/place/{id}', [
        'as' => 'enterprise.delete.place',
        'uses' => 'App\Http\Controllers\EnterprisePlacesController@destroy'
      ]);

      //End- Enterprie Routes
      $api->delete('/image/{imagedeletehash}', [
        'as' => 'image.delete',
        'uses' => 'App\Http\Controllers\ImageController@destroyImage'
      ]);
      $api->delete('/images/{placeId}', [
        'as' => 'images.delete',
        'uses' => 'App\Http\Controllers\ImageController@destroyImages'
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

      //CheckIns
      $api->post('/checkin/{pid}', [
        'as' => 'chekin.place',
        'uses' => 'App\Http\Controllers\CheckInsController@store'
      ]);  

      //End CheckIns

      //Pool//
      //show all rides for a ride sharer
      $api->get('/pool/user/rides/', [
        'as' => 'users.ride.offer',
        'uses' => 'App\Http\Controllers\PoolOfferRideController@showAllRides'
      ]);
      //show single ride details
      $api->get('/pool/user/ride/', [
        'as' => 'users.ride.offer.single',
        'uses' => 'App\Http\Controllers\PoolOfferRideController@showRideDetails'
      ]);
      $api->get('/pool/vehicles/', [
        'as' => 'get.user.vehicles',
        'uses' => 'App\Http\Controllers\PoolVehiclesController@index'
      ]);

      $api->post('/pool/vehicle/info', [
        'as' => 'save.pool.driver.information',
        'uses' => 'App\Http\Controllers\PoolVehiclesController@store'
      ]);
      // $api->get('/pool/vehicle/info', [
      //   'as' => 'show.pool.driver.information',
      //   'uses' => 'App\Http\Controllers\PoolVehiclesController@show'
      // ]);  


      // $api->get('/pool/user/info', [
      //   'as' => 'show.pool.user.additional.information',
      //   'uses' => 'App\Http\Controllers\AdditionalUserInfoController@store'
      // ]);
      //end-Additional user info
      //Offer Ride
      $api->get('/pool/can', [
        'as' => 'ride.share.eligibility',
        'uses' => 'App\Http\Controllers\PoolOfferRideController@eligibility'
      ]);
      //Additoonal user Info-Pool
      $api->post('/pool/user/info', [
        'as' => 'save.pool.user.additional.information',
        'uses' => 'App\Http\Controllers\AdditionalUserInfoController@store'
      ]);
      $api->post('/pool/ride/', [
        'as' => 'ride.share.post',
        'uses' => 'App\Http\Controllers\PoolOfferRideController@store'
      ]);
      $api->post('/pool/ride/status', [
        'as' => 'ride.share.status',
        'uses' => 'App\Http\Controllers\PoolOfferRideController@updateActivation'
      ]);
      //PoolRide- Ride Finder
      $api->get('/pool/ride/search', [
        'as' => 'ride.search',
        'uses' => 'App\Http\Controllers\PoolRideController@index'
      ]);
          //show a particular ride details from Ride Seekers "Nearest Rides Menu"
      $api->get('/pool/ride/', [
        'as' => 'ride.details',
        'uses' => 'App\Http\Controllers\PoolRideController@show'
      ]);
      //book ride
      $api->post('/book/ride/', [
        'as' => 'ride.details',
        'uses' => 'App\Http\Controllers\PoolRideController@store'
      ]);
      //Admin- Manage Pool Related Activity
      $api->get('/pool/providers/', [
        'as' => 'pool.providers',
        'uses' => 'App\Http\Controllers\UserManagementController@poolProvider'
      ]);

      $api->get('/vehicles/all/', [
        'as' => 'vehicles.all',
        'uses' => 'App\Http\Controllers\PoolManagementController@showAllVehicles'
      ]);

      $api->post('/vehicle/stat/', [
        'as' => 'vehicle.stats.update',
        'uses' => 'App\Http\Controllers\PoolManagementController@updateVehicleStats'
      ]);
      $api->get('/rides', [
        'as' => 'all.rides',
        'uses' => 'App\Http\Controllers\PoolManagementController@index'
      ]);

  });
});

