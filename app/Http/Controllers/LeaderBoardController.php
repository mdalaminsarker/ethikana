<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
//use Request;
use App\Place;
use App\User;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use App\Image;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use DB;
use Illuminate\Http\Response;
use Carbon\Carbon;

class LeaderBoardController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */

    public function ContributorLeaderBoard()
    {
      $today = Carbon::today()->toDateTimeString();
      $lastsevenday = Carbon::today()->subDays(6);
      $lastWeek = DB::table('places')
      ->join('users','places.user_id','=','users.id')
      ->select('places.*','users.*')
      ->where('isAllowed',0)
      ->whereBetween('places.created_at',[$lastsevenday,$today])->count();
      return response()->json($lastWeek);
    }
    public function indexTillDate()
    {
        //
        $leaders=User::where('userType','=',2)->orderBy('total_points','desc')->take(10)->get();
        return new JsonResponse([
            'list'=>$leaders,
            'status'=>http_response_code()
            ]);
    }

    public function indexWeekly(Request $request)
    {
        $today=Carbon::now();
        $yesterday = Carbon::now()->subDays(1);
        $one_week_ago= Carbon::now()->subWeeks(1);
        //
       // $date = new Carbon($request->start);
     //   $date2 = new Carbon($request->end);
        //$q->whereDate('created_at', '=', Carbon::today()->toDateString());
        //$leaders = User::whereBetween('created_at', [$one_week_ago->startOfDay(), $today->endOfDay()])->orderBy('total_points','desc')->take(10)->get();
         $leaders = User::where('userType','=',2)->whereBetween('created_at', [$one_week_ago,$today])->orderBy('total_points','desc')->take(10)->get();
        //$leaders=User::where('userType','=',2)->orderBy('total_points','desc')->paginate(10);


        return new JsonResponse([
            'time'=>$today."-------------".$one_week_ago,
            'list'=>$leaders,
            'status'=>http_response_code()
            ]);
    }

    public function indexMonthly(Request $request)
    {
        $today=Carbon::now();
        $yesterday = Carbon::now()->subDays(1);
        $one_week_ago= Carbon::now()->subWeeks(1);
        $one_month_ago= Carbon::now()->subMonths(1);
        //
       // $date = new Carbon($request->start);
     //   $date2 = new Carbon($request->end);
        //$q->whereDate('created_at', '=', Carbon::today()->toDateString());
        //$leaders = User::whereBetween('created_at', [$one_week_ago->startOfDay(), $today->endOfDay()])->orderBy('total_points','desc')->take(10)->get();
         $leaders = User::where('userType','=',2)->whereBetween('created_at', [$one_month_ago,$today])->orderBy('total_points','desc')->take(10)->get();
        //$leaders=User::where('userType','=',2)->orderBy('total_points','desc')->paginate(10);


        return new JsonResponse([
            'time'=>$today."-------------".$one_month_ago,
            'list'=>$leaders,
            'status'=>http_response_code()
            ]);
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
