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
use App\Offer;
use Illuminate\Support\Str;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class OfferController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
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

        $saveOffer=new Offer;

        $saveOffer->pid=$pid;
        $saveOffer->offer_title=$request->offerTitle;
        $saveOffer->offer_description=$request->offerDescription;
        $saveOffer->isActive=1;

        $saveOffer->save();
        return new JsonResponse([
            'confirm'=> 'Offer Saved Successfully',
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
        $getOfferForPID=Offer::where('pid','=',$pid)->first();

        return new JsonResponse([
            'confirm'=> $getOfferForPID,
        ],Response::HTTP_OK);
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
        $placeOffer=Offer::where('id','=',$id)->first();
        if($request->has('offerTitle')){
            $placeOffer->offer_title=$request->offerTitle;
        }
        if($request->has('offerDescription')){
            $placeOffer->offer_description=$request->offerDescription;
        }
        if($request->has('isActive')){
            $placeOffer->isActive=$request->isActive;
        }
        $placeOffer->save();
        
        return new JsonResponse([
            'confirm'=> 'Offer Updated Successfully',
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
      $offer= Offer::where('id','=',$id)->first();
      $offer->delete();
      
      return new JsonResponse([
        'confirm'=> 'Offer Deleted!',
      ],Response::HTTP_OK);
    }
}
