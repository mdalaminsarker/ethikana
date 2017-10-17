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
use Bugsnag\BugsnagLaravel\Facades\Bugsnag;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;

class PoolManagementController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType; 
        if($userType==1){
            $allRides=OfferRide::with('user')->with('vehicle')->orderBy('id', 'desc')->get();
            return new JsonResponse([
                    "allRideOffers"=>$allRides
                ],200);
        }
        else{
            return new JsonResponse([
                    "allRideOffers"=>"User Not Permitted to Access this Resource"
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
        //
    }

    public function showAllVehicles()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType; 
        if($userType==1){
            $allRides=PoolVehicle::with('rideOwner')->orderBy('id', 'desc')->get();
            return new JsonResponse([
                    "allRideOffers"=>$allRides
                ],200);
        }
        else{
            return new JsonResponse([
                    "allRideOffers"=>"User Not Permitted to Access this Resource"
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
    public function updateVehicleStats(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType; 

        if($request->has('isApproved')){
            $vehcileApproval=$request->isApproved;
        }else{
            $vehcileApproval=0;
        }

        if ($request->has('isAllowedToServe')) {
            $permit=$request->isAllowedToServe;
        }else{
           $permit=0; 
        }

        if($userType==1){
          PoolVehicle::where('id','=',$request->id)
                        ->update([
                            'isApproved' => $vehcileApproval,
                            'isAllowedToServe'=> $permit
                        ]);

          return new JsonResponse([
            'message' => 'Resource Updated.',
          ],200);
        }else{
          return new JsonResponse([
            'message' => 'User Not Permitted to Perform This Action'
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
