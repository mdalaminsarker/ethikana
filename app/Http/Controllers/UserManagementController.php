<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use DB;
use Auth;
use App\User;
use App\Place;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;

class UserManagementController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index($id)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
          $userDetails=User::where('id','=',$id)->get();
          return new JsonResponse([
            'message' => 'User Details Provided',
            'data' => $userDetails
          ]);
        }else{
          return new JsonResponse([
            'message' => 'User Not Permitted To See This Resource;',
          ]);
        }
    }
    
    public function poolProvider()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
          $poolProvider=User::where('isPoolProvider','=',1)->get();
          return new JsonResponse([
            'message' => 'Pool Providers List',
            'data' => $poolProvider
          ]);
        }else{
          return new JsonResponse([
            'message' => 'User Not Permitted To See This Resource;',
          ]);
        }
    }
    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
          $PlacesByUser=Place::where('user_id','=',$id)->get();
          return new JsonResponse([
            'message' => 'List of Places Added by This User ID is Provided.',
            'data' => $PlacesByUser
          ]);
        }else{
          return new JsonResponse([
            'message' => 'User Not Permitted To See This Resource.'
          ]);
        }
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType; 
        $toBeEdited=$id;
        if($userType==1)
        {
            $places = Place::where('id','=',$toBeEdited)->first();
            if ($request->has('longitude')) {
                $places->longitude = $request->longitude;
            }
            if ($request->has('latitude')) {
                $places->latitude = $request->latitude;
            }
            if($request->has('Address')){
                $places->Address = $request->Address;
            }
            if($request->has('city')){
                $places->city = $request->city;                
            }
            if($request->has('area')){
                $places->area = $request->area;                
            }
            if($request->has('pType')){
                $places->pType = $request->pType;               
            }
            if($request->has('subType')){
                $places->subType = $request->subType;
            }
            if($request->has('postCode')){
                $places->postCode = $request->postCode;
            }
            if($request->has('flag')){
                $places->flag = $request->flag;
            }
            //$places->user_id = $request->user_id; 

            $places->save();

            return new JsonResponse([
                    'message'=>'Place Updated'
                ]);
        }
        else{
            return new JsonResponse([
                'message' => 'User Not Permitted To See This Resource.'
            ]);
        }
    }


    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType; 
        $toBeRemoved=$id;
        if($userType==1)
        {
            $isThisPlaceRewarded=Place::where('id','=',$toBeRemoved)->where('isRewarded','=',1)->first();
            if(count($isThisPlaceRewarded)!=0){
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
              $randomStringChar1=''.$randomStringChar.''.$randomStringNum.'';
              //we are not going to delete it from DB but void the reference user_id/device_id
              Place::where('id','=',$toBeRemoved)->update(['device_ID' => null,'uCode' => $randomStringChar1,'user_id' => null,'flag' => 0]);
              //deduct points
              User::where('id','=',$userId)->decrement('total_points',5);
              return response()->json('Place Deleted! 5 Points deducted!!');
            }else{
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
              $randomStringChar2=''.$randomStringChar.''.$randomStringNum.'';
              //we are not going to delete it from DB but void the reference user_id/device_id
              Place::where('id','=',$toBeRemoved)->update(['device_ID' => null,'uCode' => $randomStringChar2,'user_id' => null,'flag' => 0]);
              return response()->json('Place Deleted!');
            }
        }else{
            return new JsonResponse([
                'message' => 'User Not Permitted To See This Resource.'
            ]);
        }
    }
}
