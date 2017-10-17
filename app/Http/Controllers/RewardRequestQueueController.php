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
use App\RewardRedeemRequest;
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

class RewardRequestQueueController extends Controller
{

  //ADMIN panel reward request management

  
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
          $rewardRequestList=RewardRedeemRequest::with('user')->with('reward')->orderBy('id','DESC')->get();
            return new JsonResponse([
                'success' => true,
                'message' => 'Reward Request List Found',
                'data' => $rewardRequestList,
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
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {


    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //show a specific request
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
            $rewardRequestItem=RewardRedeemRequest::where('id',$id)->with('reward')->with('user')->first();
            return new JsonResponse([
                'success' => true,
                'message' => 'Reward Request Found',
                'data' => $rewardRequestItem,
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
        //update a speific request or grant a request
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        //return $userType;

        if($userType==1){
            //get request info from request queue table
            $getTheUserData=RewardRedeemRequest::where('id',$id)->select('user_id','requested_reward','isGranted')->first();
            $theUser=$getTheUserData->user_id;
            $isAllreadyGranted=$getTheUserData->isGranted;
            //get The Total Points
            $userInfo=User::where('id','=',$theUser)->select('name','total_points','redeemed_points','email')->first();
            $totalPoints=$userInfo->total_points;
            $old_redeemed_points=$userInfo->redeemed_points;
            $name=$userInfo->name;
            $mail=$userInfo->email;
            
            $theRewared=$getTheUserData->requested_reward;
            $getTheRewardInfo=Reward::where('id',$theRewared)->select('rewards_name','required_points','isOneTime')->first();
            $getTheRewaredPoints=$getTheRewardInfo->required_points;
            $ifThisRewardOneTime=$getTheRewardInfo->isOneTime;

            //get the request  from request queue table
            $getTheRequest=RewardRedeemRequest::where('id',$id)->first();
            if($isAllreadyGranted==0 or $isAllreadyGranted==2)
            {
              if($request->has('isGranted')){
                //0=requested, 1=granted, 2=denied
                $getTheRequest->isGranted=$request->isGranted;
                //if 1, increase the redeemed points
                if($request->isGranted==1){
                    User::where('id', $theUser)->increment('redeemed_points',$getTheRewaredPoints);
                    //create a record in one_time_reward table
                    if($ifThisRewardOneTime==1){
                      $newOneTimeReward=new OneTimeReward;
                      $newOneTimeReward->OneTimeRewardId=$theRewared;
                      $newOneTimeReward->user_id=$theUser;
                      $newOneTimeReward->save();
                    }  
                }else{
                    User::where('id', $theUser)->update(['redeemed_points' => $old_redeemed_points]);
                }
            }
            //$updateUserRedemmePoints=User::where('id',$theUser)->increment('redeemed_points',$getTheRewaredPoints);
            //change hasPendingRewardRequest , 1 to 0
            User::where('id', $theUser)->update(array('hasPendingRewardRequest' => 0));
            $getTheRequest->save();
            $data = array( 'to' => $mail,'name' => $name,'reward_name'=> $getTheRewardInfo['rewards_name']);
            Mail::send('Email.rewardAccepted',$data, function($message) use ($data){
              $message->to($data['to'])->subject('Reward Redeem Request Has Been Approved!');
            });

            return new JsonResponse([
                'success' => true,
                'message' => 'Reward Granted,points given to User',
                'status' => 200
              ],200);
          }else{
            return new JsonResponse([
                'success' => false,
                'message' => 'Reward granted allready',
                'status' => 406
                ],406);
          }
        }else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
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
    }
}
