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
use Illuminate\Support\Str;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class EnterpriseAnalyticsController extends Controller
{
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

        if($userType==3){
            $allAddedByThisEnt=Place::where('user_id','=',$userId)->get();
            if(count($allAddedByThisEnt)!=0)
            {
              return new JsonResponse([
                'success' => true,
               // 'message' => 'Address List Found',
                'data' => $allAddedByThisEnt,
                //'userUsedBonus'=> $is20mbRedeemed,
                'places_count'=>count($allAddedByThisEnt),
                'status' => 200
                ],200);
            }
            else
            {
              return new JsonResponse([
                'success' => false,
                'message' => 'No Address List Found',
                'data' =>$allAddedByThisEnt,
                'places_count'=>count($allAddedByThisEnt),
                'status' => 200
                ],200);
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
