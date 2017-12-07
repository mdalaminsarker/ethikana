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
use Illuminate\Support\Str;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class ReviewController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index($pid)
    {
        //show all review for a Business Place
        //$allReviews=Place::where('pid','=',$pid)->get();
        //$post = DB::select('select p.place from places AS p,confirm AS c where p.id=c.post_id AND                                                     c.reply_user_id='.Auth::user()->id.'');
        $allReviews=Place::with('reviews.reviewByUser')->where('id','=',$pid)->get();
       	return new JsonResponse([
       		'allReviews'=> $allReviews,
        	],Response::HTTP_OK);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request,$pid)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
    	$userId = $user->id;

    	$saveRating=new ReviewRating;

    	$saveRating->pid=$pid;
    	$saveRating->user_id=$userId;
    	$saveRating->review=$request->reviewText;
    	$saveRating->rating=$request->reviewRating;
    	//isAllowedToShow is by default 1;
    	//that means it will be visible
    	$saveRating->save();
    	return new JsonResponse([
    		'confirm'=> 'Review Added Successfully'
    		],Response::HTTP_OK);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($pid)
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
        $placeRate=ReviewRating::where('id','=',$id)->first();
        if($request->has('reviewText')){
            $placeRate->review=$request->reviewText;
        }
        if($request->has('reviewRating')){
            $placeRate->rating=$request->reviewRating;
        }
        $placeRate->save();
        
        return new JsonResponse([
            'confirm'=> 'Review Updated Successfully',
        ],Response::HTTP_OK);
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
