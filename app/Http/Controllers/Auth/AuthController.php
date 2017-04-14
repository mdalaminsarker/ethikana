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
           'password' => 'required|min:6',
           'userType'=>'required',
       ]);

       $user = new User;
       $user->name = $request->name;
       $user->email = $request->email;
       $user->password = app('hash')->make($request->password);
       $user->user_type=$request->userType;
       if ($request->has('device_ID')) {
         $user->device_ID = $request->device_ID;
       }
       $user->save();

     //  return response()->json('Welcome');
       return new JsonResponse([
            'message' => 'Welcome'
        ]);
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
    
    //Add New Place    
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
      
      $input = new Place;
      
      $input->longitude = $request->longitude;
      $input->latitude = $request->latitude;
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
      

      if ($request->has('email')) {
        $input->email = $request->email;
      }
      
      $input->uCode = $ucode;      
      $input->save();
      
      DB::table('analytics')->increment('code_count');
      return response()->json($ucode);
    }
    
    //Add new place with custom code
        //Store Custom Place
    public function authAddCustomPlace(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        
        $input = new Place;
        $input->longitude = $request->longitude;
        $input->latitude = $request->latitude;
        $input->Address = $request->Address;
        $input->city = $request->city;
        $input->area = $request->area;
        $input->postCode = $request->postCode;
        $input->pType = $request->pType;
        $input->subType = $request->subType; 
        if ($request->has('flag')) {
            $input->flag = $request->flag;
            if ($request->flag===1) {
                DB::table('analytics')->increment('public_count');
            }else {
                DB::table('analytics')->increment('private_count');
            }
        }
        if($request->has('device_ID')) {
            $input->device_ID = $request->device_ID;
        }
        //ADN:when authenticated , user 
        $input->user_id = $userId;
        if($request->has('email')) {
            $input->email = $request->email;
        }
        $input->uCode = $request->uCode;
        $input->save();
        DB::table('analytics')->increment('code_count');
        return response()->json($request->uCode);
    }


    // get all places for  a Device by userId/(userId+deviceId)
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

    //Update My Place
    public function halnagadMyPlace(Request $request,$barikoicode){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $places = Place::where('uCode','=',$barikoicode)->first();
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
