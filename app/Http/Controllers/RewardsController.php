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

class RewardsController extends Controller
{
            //For Client side reward pages
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    { 
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        // $getTheUser=User::where('id','=',$userId)->select('total_points','redeemed_points')->first();
        // $usersTotalPoints=$getTheUser->total_points;
        // $usersRedeemedPoints=$getTheUser->redeemed_points;

        //$is20mbRedeemed=RewardRedeemRequest::where;
        $hasPendingRequest=User::where('id',$userId)->select('hasPendingRewardRequest')->first();
        $hasPendingRequestValue=$hasPendingRequest->hasPendingRewardRequest;
        $one_time = OneTimeReward::where('user_id',$userId)->pluck('oneTimeRewardId');
        $allRewards=Reward::whereNotIn('id',$one_time)->where('isActive',1)->get();
        //return $hasPendingRequestValue;
        if(!empty($allRewards)){
            return new JsonResponse([
            'success' => true,
            'message' => 'Reward List Found',
            'data' => $allRewards,
            'hasPendingRequest'=> $hasPendingRequestValue,
            'status' => 200
            ],200);
        }else{
            return new JsonResponse([
            'success' => false,
            'message' => 'Reward List Not Found',
            'data' =>'N/A',
            'hasPendingRequest'=> 'N/A',
            'status' => 404
            ],404);
        }
        // return response()->json(['status' => 'success']);
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
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $requiredPoints=$request->required_points;

        $pointsCurrent=User::where('id','=',$userId)->select('total_points','redeemed_points','hasPendingRewardRequest')->first();
        $total_points=$pointsCurrent->total_points;
        $total_redeemed=$pointsCurrent->redeemed_points;
        $hasPendingRqst=$pointsCurrent->hasPendingRewardRequest;

        //return $total_points.'---'.$total_redeemed;
        if($hasPendingRqst==0){
            if($requiredPoints<=($total_points-$total_redeemed)){
                $newRequest = new RewardRedeemRequest;
                $newRequest->user_id=$userId;
                $newRequest->requested_reward=$request->requested_reward;
                $newRequest->isGranted=0;
                // 0=requested, 1= granted
                $newRequest->save();

                //$total_redeemed_new=User::where('id',$userId)->increment('redeemed_points',$requiredPoints);
                //change hasPendingRewardRequest , 0 to 1
                User::where('id', $userId)->update(array('hasPendingRewardRequest' => 1));

                return new JsonResponse([
                    'success' => true,
                    'message' => 'Reward Request Submitted Successfully,Please give us some time to Confirm it.',          
                    'status' => 200
                    ],200);
            }else{
                return new JsonResponse([
                    'success' => false,
                    'message' => 'Sorry! Not enough Reward Points.',          
                    'status' => 406
                    ],406);
            }
        }else{
           return new JsonResponse([
            'success' => false,
            'message' => 'Sorry! You have a Redeem Request Pending.',          
            'status' => 406
            ],406);
        }
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show()
    {
        //show the reward request history/queue for User/CLient Side
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

        $pendingForGrant=RewardRedeemRequest::with('reward')->where('user_id',$userId)->get();

        if(!empty($pendingForGrant)){
            return new JsonResponse([
                'success' => true,
                'message' => 'Reward Request History List Found',
                'data' => $pendingForGrant,
                'status' => 200
            ],200);
        }else{
            return new JsonResponse([
                'success' => true,
                'message' => 'No Reward Request List Found',
                'data' => 'N/A',
                'status' => 404
            ],404);
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
