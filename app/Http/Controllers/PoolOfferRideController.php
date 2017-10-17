<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;
use Auth;
use Validator;
use App\User;
use App\Place;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use App\Image;
use App\AdditionalUserInfo;
use App\PoolVehicle;
use App\PoolPhoto;
use App\OfferRide;
use App\ProfilePhoto;
use App\BookARide;
use Bugsnag\BugsnagLaravel\Facades\Bugsnag;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Carbon\Carbon;

class PoolOfferRideController extends Controller
{

  //if a user can provide rides
    public function eligibility()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
 /*
    1. Condition => "usrer_id" has at least 1 "pool_vehicles" -- "isApproved"=1 && "isAllowedToServe"=1
    2. Condition=>"user_id" has "additional_info" 
    3. Condition => "user_id" has "profile_photo"
    *he will be able to share his ride
*/  
        $checkCondition1=PoolVehicle::where('user_id','=',$userId)->where('isApproved','=',1)->where('isAllowedToServe','=',1)->count();
        $checkCondition2=AdditionalUserInfo::where('user_id','=',$userId)->count();
        $checkCondition3=ProfilePhoto::where('user_id','=',$userId)->count();
        $msg=array();
        //return $checkCondition;
        //return $checkCondition1.'--'.$checkCondition2.'--'.$checkCondition3;
        if($checkCondition1>0){
            $setCon1=1;//emni 
        }else{
            $setCon1=0;//emni
            array_push($msg, "Vehicle Information Incomplete or Not Verified");
        }        
        if($checkCondition2>0){
            $setCon2=1;
        }else{
            $setCon2=0;
            array_push($msg, "Additional User Information Incomplete");
        }        
        if($checkCondition3>0){
            $setCon3=1;
        }else{
            $setCon3=0;
            array_push($msg, "User Profile Photo Not Found");
        }
        return $msg;
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

        $canShare=$this->eligibility();
        //echo count($canShare);
        //print_r($canShare);

        if (count($canShare)>0) {
            return new JsonResponse([
                'success'=>false,
                'messages' => $canShare,
              ],200);
        }
        else{
            if(PoolVehicle::where('user_id','=',$userId)->where('id','=',$request->vehicleId)->exists())
            {
                $ride=new OfferRide;
                $ride->user_id=$userId;
                $ride->vehicle_id=$request->vehicleId;
                $ride->startTime=$request->startTime;
                $ride->startLat=$request->startLat;
                $ride->startLon=$request->startLon;
                $ride->startAddress=$request->startAddress;
                $ride->endLat=$request->endLat;
                $ride->endLon=$request->endLon;
                $ride->endAddress=$request->endAddress;
                $ride->shared_seat_number=$request->sharable_seat;
                $ride->isActive=$request->isActive;
                $ride->save();
                User::where('id','=',$userId)->update(['isPoolProvider' => 1]);
                return new JsonResponse([
                    'success'=>true,
                    'messages' =>"Ride Offer Created Successfully.",
                  ],200);
            }else{
                return new JsonResponse([
                    'success'=>true,
                    'messages' =>"Could not verify vehicle ownership",
                  ],200); 
            }
        }

    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function showAllRides()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

       // $userDetails=OfferRide::with('rideRequestBy')->where('user_id','=',$userId)->get();
        $userRideOffers=OfferRide::with('vehicle')->where('user_id','=',$userId)->get();
        return new JsonResponse([
            'result'=>$userRideOffers,
          ]);
    }
    public function showRideDetails(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $userRideDetails=BookARide::with('passenger')->where('offer_rides_id','=',$request->rideId)->where('rideStat','=',0)->get();
        return new JsonResponse([
            'result'=>$userRideDetails
          ]);
    }


    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function updateActivation(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        if(OfferRide::where('user_id','=',$userId)->where('id','=',$request->id)->exists()) {
            # code...
            OfferRide::where('id','=',$request->id)->where('user_id','=',$userId)->update(['isActive'=>$request->isActive]);
            return new JsonResponse([
                'success'=>true,
                'messages' =>"Ride Offer Status Changed.",
              ],200);
        }else{
            return new JsonResponse([
                'success'=>false,
                'messages' =>"Something went wrong in the process",
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
