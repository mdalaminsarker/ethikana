<?php

namespace App\Http\Controllers\Auth;
use DB;
use Auth;
use App\User;
use App\Place;
use App\SavedPlace;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;

class AuthController extends Controller
{
  /**
  * Handle a login request to the application.
  *
  * @param \Illuminate\Http\Request $request
  *
  * @return \Illuminate\Http\Response
  */

  public function Register(Request $request){

    $this->validate($request, [
      'name' => 'required',
      'email' => 'required|email|max:255',
      'password' => 'required',
      'userType'=>'required',
      'phone' => 'numeric|min:11',
    ]);

    $user = new User;
    $user->name = $request->name;
    $user->email = $request->email;
    $user->password = app('hash')->make($request->password);
    $user->userType=$request->userType;


    if ($request->has('device_ID')) {
      $user->device_ID = $request->device_ID;
    }
    if ($request->has('phone')) {
      $user->phone=$request->phone;
    }
    $user->save();

    return response()->json('Welcome');

  }
  public function postLogin(Request $request)
  {
    try {
      $this->validatePostLoginRequest($request);
    } catch (HttpResponseException $e) {
      return $this->onBadRequest();
    }

    try {
      // Attempt to verify the credentials and create a token for the user
      if (!$token = JWTAuth::attempt(
        $this->getCredentials($request)
      )) {
        return $this->onUnauthorized();
      }
    } catch (JWTException $e) {
      // Something went wrong whilst attempting to encode the token
      return $this->onJwtGenerationError();
    }

    // All good so return the token
    return $this->onAuthorized($token);
  }

  /**
  * Validate authentication request.
  *
  * @param  Request $request
  * @return void
  * @throws HttpResponseException
  */
  protected function validatePostLoginRequest(Request $request)
  {
    $this->validate($request, [
      'email' => 'required|email|max:255',
      'password' => 'required',
    ]);
  }

  /**
  * What response should be returned on bad request.
  *
  * @return JsonResponse
  */
  protected function onBadRequest()
  {
    return new JsonResponse([
      'message' => 'invalid_credentials'
    ], Response::HTTP_BAD_REQUEST);
  }

  /**
  * What response should be returned on invalid credentials.
  *
  * @return JsonResponse
  */
  protected function onUnauthorized()
  {
    return new JsonResponse([
      'message' => 'invalid_credentials'
    ], Response::HTTP_UNAUTHORIZED);
  }

  /**
  * What response should be returned on error while generate JWT.
  *
  * @return JsonResponse
  */
  protected function onJwtGenerationError()
  {
    return new JsonResponse([
      'message' => 'could_not_create_token'
    ], Response::HTTP_INTERNAL_SERVER_ERROR);
  }

  /**
  * What response should be returned on authorized.
  *
  * @return JsonResponse
  */
  protected function onAuthorized($token)
  {
    return new JsonResponse([
      'message' => 'token_generated',
      'data' => [
        'token' => $token,
      ]
    ]);
  }

  /**
  * Get the needed authorization credentials from the request.
  *
  * @param \Illuminate\Http\Request $request
  *
  * @return array
  */
  protected function getCredentials(Request $request)
  {
    return $request->only('email', 'password');
  }

  /**
  * Invalidate a token.
  *
  * @return \Illuminate\Http\Response
  */
  public function deleteInvalidate()
  {
    $token = JWTAuth::parseToken();

    $token->invalidate();

    return new JsonResponse(['message' => 'token_invalidated']);
  }

  /**
  * Refresh a token.
  *
  * @return \Illuminate\Http\Response
  */
  public function patchRefresh()
  {
    $token = JWTAuth::parseToken();

    $newToken = $token->refresh();

    return new JsonResponse([
      'message' => 'token_refreshed',
      'data' => [
        'token' => $newToken
      ]
    ]);
  }

  /**
  * Get authenticated user.
  *
  * @return \Illuminate\Http\Response
  */
  public function getUser()
  {
    return new JsonResponse([
      'message' => 'authenticated_user',
      'data' => JWTAuth::parseToken()->authenticate()
    ]);
  }
  public function getPlacesByUserId($deviceId)
  {
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
   //update all places with this 'deviceId' ,where user_id is null -> update the user id to $userId;  
    $placesWithDvid=Place::where('device_ID','=',$deviceId)->where('user_id', null)->update(['user_id' => $userId]);
    //get the places with user id only
    $place = Place::where('user_id','=',$userId)->get();

    return $place->toJson();
    //return $deviceId;
  }

    //Add New Place
          /*
      $lat = $request->latitude;
      $lon = $request->longitude;
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->having('distance','<',0.02) //20 meter
           ->where('flag','=',1)
           ->get();
      */    
    public function authAddNewPlace(Request $request){

      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      //char part
      $charactersChar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersCharLength = strlen($charactersChar);
      $randomStringChar = '';
      for ($i = 0; $i < 4; $i++) {
          $randomStringChar .= $charactersChar[rand(0, $charactersCharLength - 1)];
      }
      //number part
      $charactersNum = '0123456789';
      $charactersNumLength = strlen($charactersNum);
      $randomStringNum = '';
      for ($i = 0; $i < 4; $i++) {
          $randomStringNum .= $charactersNum[rand(0, $charactersNumLength - 1)];
      }

      $ucode =  ''.$randomStringChar.''.$randomStringNum.'';
      
      $lat = $request->latitude;
      $lon = $request->longitude;
      //check if it is private and less then 20 meter
      if($request->flag==0){
      
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('user_id','=',$userId) // same user can not add
           ->having('distance','<',0.05) //another private place in 50 meter
           ->get();
       $message='Can not Add Another Private Place in 50 meter';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){
        
        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.02) //no one 20 meter for public
           ->get();
        $message='A Public Place is Available in 20 meter.';
      }
      /*return response()->json([
          'Count' => $result->count()
          ]);*/
      if(count($result) === 0)
      {
        $input = new Place;
        $input->longitude = $lon;
        $input->latitude = $lat;
        $input->Address = $request->Address;
        $input->city = $request->city;
        $input->area = $request->area;
        $input->postCode = $request->postCode;
        $input->pType = $request->pType;
        $input->subType = $request->subType;  
        //longitude,latitude,Address,city,area,postCode,pType,subType,flag,device_ID,user_id,email
        if($request->has('flag')) 
        {
          $input->flag = $request->flag;
          if ($request->flag==1) {
            DB::table('analytics')->increment('public_count');
          }else{
            DB::table('analytics')->increment('private_count');
          }
        }
          if ($request->has('device_ID')) {
              $input->device_ID = $request->device_ID;
          }

        //ADN:when authenticated , user_id from client will be passed on this var. 
        $input->user_id =$userId;

        if ($request->has('email')){
          $input->email = $request->email;
        }

        $input->uCode = $ucode;      
        $input->save();
        User::where('id','=',$userId)->increment('total_points',5);

        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);

        //everything went weel, user gets add place points, return code and the point he recived
        return response()->json([
          'uCode' => $ucode,
          'points' => 5
          ]);
      }
      else{
        //can't add places in 20/50 mter, return a message
        return response()->json([
          'message' => $message
          ]);
      }

    }

    //Add new place with custom code
    public function authAddCustomPlace(Request $request)
    {
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      
      $lat = $request->latitude;
      $lon = $request->longitude;
      //check if it is private and less then 20 meter
      if($request->flag==0){
      
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('user_id','=',$userId)
           ->having('distance','<',0.05) //50 meter for private
           ->get();
       $message='Can not Add Another Private Place in 50 meter';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){
        
        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.02) //20 meter for public
           ->get();
        $message='A Public Place is Available in 20 meter';
   
      }
      /*return response()->json([
          'Count' => $result->count()
          ]);*/
      if(count($result) === 0)
      {
        $input = new Place;
        $input->longitude = $lon;
        $input->latitude = $lat;
        $input->Address = $request->Address;
        $input->city = $request->city;
        $input->area = $request->area;
        $input->postCode = $request->postCode;
        $input->pType = $request->pType;
        $input->subType = $request->subType;  
        //longitude,latitude,Address,city,area,postCode,pType,subType,flag,device_ID,user_id,email
        if($request->has('flag')) 
        {
          $input->flag = $request->flag;
          if ($request->flag==1) {
            DB::table('analytics')->increment('public_count');
          }else{
            DB::table('analytics')->increment('private_count');
          }
        }
          if ($request->has('device_ID')) {
              $input->device_ID = $request->device_ID;
          }

        //ADN:when authenticated , user_id from client will be passed on this var. 
        $input->user_id =$userId;

        if ($request->has('email')){
          $input->email = $request->email;
        }

        $input->uCode = $request->uCode;      
        $input->save();
        User::where('id','=',$userId)->increment('total_points',5);

        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);
        return response()->json([
          'uCode' => $request->uCode,
          'points' => 5
          ]);
      }
      else{
        return response()->json([
          'message' => $message
          ]);
      }

    }

        //Update My Place
    public function halnagadMyPlace(Request $request,$id){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $places = Place::where('id','=',$id)->first();
        if ($request->has('longitude')) {
            $places->longitude = $request->longitude;
        }
        if ($request->has('latitude')) {
            $places->latitude = $request->latitude;
        }
        $places->Address = $request->Address;
        $places->city = $request->city;
        $places->area = $request->area;
        $places->user_id = $userId; 
        $places->postCode = $request->postCode;
        $places->flag = $request->flag;
        $places->save();
    //  $splaces = SavedPlace::where('pid','=',$id)->update(['Address'=> $request->Address]);
    
        return response()->json('updated');
    }
    //Delete place from MyPlaces/"Places" table
    public function mucheFeliMyPlace(Request $request,$bariCode){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $toBeRemoved=$bariCode;
       // $getPid=Place::where('uCode','=',$toBeRemoved)->first();    
      //  $pid=$getPid->id;
       // $toDeleteSavedPlacesTable =SavedPlace::where('pid','=',$pid)->where('user_id','=',$userId)->delete();
        $toDelete =Place::where('uCode','=',$toBeRemoved)->where('user_id','=',$userId)->delete();

        return response()->json('Done');
    }
    // get all saved places for a userId
    public function getSavedPlacesByUserId()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $savedPlaces=DB::table('places')
        ->join('saved_places', function ($join) {
            $join->on('places.id', '=', 'saved_places.pid');
        })
        ->where('saved_places.user_id','=',$userId)
        ->get();
         return $savedPlaces->toJson();
    }
    //Add Favorite Place
    public function authAddFavoritePlace(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $saved = new SavedPlace;
        $saved->user_id = $userId; //user who is adding a place to his/her favorite
        $code = $request->barikoicode; // place is
        $getPid=Place::where('uCode','=',$code)->first();    
        $pid=$getPid->id;
        $saved->pid=$pid;
        //return $pid;
        $saved->save();
        DB::table('analytics')->increment('saved_count');
        return response()->json('saved');
    }
    // Delete a place from favorite
    public function authDeleteFavoritePlace(Request $request,$bariCode)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $toBeDeleted=$bariCode;
        $findThePid=Place::where('uCode','=',$toBeDeleted)->first();
        $toDelete = SavedPlace::where('pid','=',$findThePid->id)->where('user_id','=',$userId)->delete();
        return response()->json('Done');
        //return $toDelete;
    }


}
