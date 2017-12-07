<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Auth;
use App\Place;
use App\User;
use App\Token;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use App\BusinessDetails;
use App\ReviewRating;
use App\Reward;
use App\OneTimeReward;
use Illuminate\Support\Str;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class RewardsManagementController extends Controller
{
  //Manageing Rewards from Admin Panel
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
            $allRewards=Reward::get();
            if(!empty($allRewards))
            {
              return new JsonResponse([
                'success' => true,
                'message' => 'Reward List Found',
                'data' => $allRewards,
                //'userUsedBonus'=> $is20mbRedeemed,
                'status' => 200
                ],200);
            }
            else
            {
              return new JsonResponse([
                'success' => false,
                'message' => 'Reward List Not Found',
                'data' =>'N/A',
                'status' => 404
                ],404);
            }
        }else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                //'data' => $rewardsWithID,
                'status' => 403
                ],403);
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
      //add new reward
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
          $reward = new Reward;
          $reward->rewards_name=$request->rewards_name;
          $reward->required_points=$request->required_points;
          $reward->typeOfRewards=$request->typeOfRewards;
          $reward->isOneTime=$request->isOneTime;
          $reward->save();

          return new JsonResponse([
            'success' => true,
            'message' => 'Reward Item Created',
            'status' => 201
          ],201);
        }else{
          return new JsonResponse([
            'success' => false,
            'message' => 'User not authorised to Perform this Action',
            //'data' => $rewardsWithID,
            'status' => 403
          ],403);
        }
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
      //see details for a reward item
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
          $rewardsWithID=Reward::where('id',$id)->get();
          return new JsonResponse([
            'success' => true,
            'message' => 'Reward Item Found',
            'data' => $rewardsWithID,
            'status' => 200
          ],200);
        }else{
          return new JsonResponse([
            'success' => false,
            'message' => 'User not authorised to Access this Resource',
            //'data' => $rewardsWithID,
            'status' => 403
          ],403);
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
        //return $userType;

        if($userType==1){
          $reward = Reward::where('id',$id)->first();
          if($request->has('rewards_name')){
            $reward->rewards_name=$request->rewards_name;
          }
          if($request->has('required_points')) {
            $reward->required_points=$request->required_points;
          }
          if($request->has('isActive')){
            $reward->isActive=$request->isActive;
          }
          if($request->has('typeOfRewards')){
            $reward->typeOfRewards=$request->typeOfRewards;
          }
          if($request->has('isOneTime')){
            $reward->isOneTime=$request->isOneTime;
          }
          $reward->save();

          return new JsonResponse([
            'success' => true,
            'message' => 'Reward Updated',
            'status' => 201
          ],201);
        }else{
          return new JsonResponse([
            'success' => false,
            'message' => 'User not authorised to Perform this Action',
            //'data' => $rewardsWithID,
            'status' => 403
          ],403);
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
        //return $userType;
        if($userType==1){
          $reward = Reward::where('id',$id)->first();
          $reward->delete();
          return new JsonResponse([
            'success' => true,
            'message' => 'Reward Deleted',
            'status' => 201
          ],201);
        }else{
          return new JsonResponse([
            'success' => false,
            'message' => 'User not authorised to Perform this Action',
            //'data' => $rewardsWithID,
            'status' => 403
          ],403);
        }
    }
}
