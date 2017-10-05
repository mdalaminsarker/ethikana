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


class PoolRideController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $lat = $request->latitude;
        $lon = $request->longitude;
        //->with(array('vehicle'=>function($query){
          //  $query->select('id');}))
        $result = OfferRide::with(array('user'=>function($query){
            $query->select('id','name','phone');}))
                ->with(array('vehicle'=>function($query){
            $query->select('id','vehicle_type','vehicle_regnum');}))
                ->where('isActive','=',1)->where('isAvailable','=',1)
                ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(startLat * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(startLat * PI() / 180) * COS(('.$lon.' - startLon) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
                //->where('pType', '=','Food')
                ->having('distance','<',100)
                ->orderBy('distance','asc')
                ->limit(2)
                ->get();
        // $result1 = OfferRide::with(array('byUser' => function($query)
        //   {$query->select('id','phone');}))->where('isActive','=',1)
        //         ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(startLat * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(startLat * PI() / 180) * COS(('.$lon.' - startLon) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
        //         ->having('distance','<=',2)
        //         ->orderBy('distance')
        //         ->limit(2)
        //         ->get();

        // $res=array($result);
        // $vId=$res[0][0]->vehcile_id;

        // $vehicle_info=PoolVehicle::where('id','=',$vId)->get();

        return new JsonResponse([
            'rides' =>$result,
        ]);
    }

    public function indexBot(Request $request)
    {
        //
       // $user = JWTAuth::parseToken()->authenticate();
       // $userId = $user->id;
        $lat = $request->latitude;
        $lon = $request->longitude;
        // $result = DB::table('offer_rides')->where('isActive','=',1)
        //    ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(startLat * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(startLat * PI() / 180) * COS(('.$lon.' - startLon) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
        //   //->where('pType', '=','Food')
        //    ->having('distance','<',0.5)
        //    ->orderBy('distance')
        //    ->limit(5)
        //    ->get();
        $result = OfferRide::with(array('user'=>function($query){
        $query->select('id','name','phone');
    }))->where('isActive','=',1)
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(startLat * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(startLat * PI() / 180) * COS(('.$lon.' - startLon) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->having('distance','<',0.5)
           ->orderBy('distance')
           ->limit(5)
           ->get();

        //return $result;
        if(count($result)==0){
            $ar[]=array("text"=>"my apologies,could not find any ride nearby");
              return new JsonResponse([
                  'messages'=>$ar
              ]);
          }
          else{
            foreach ($result as $post) {
                $user='Rider: '.$post->user->name.'; Phone:'.$post->user->phone;
                $aLat=$post->startLat;
                $aLon=$post->startLon;
                $time=$post->startTime;
                $weblink="https://www.google.com.bd/maps/@".$aLat.",".$aLon.",17z";

                // echo count($post->by_user);

                // if(count($post->by_user)==0){
                //   $user='';
                //   // $posts1[]=array('title'=>$ad,'image_url'=>NULL,'subtitle'=>$sub,'buttons'=>array([
                //   //     'type'=>'web_url','url'=>$weblink,'title'=>$code]));
                // }else{
                //   foreach ($post->by_user as $p) {
                //       $user='Rider: '.$p->name.'; Phone:'.$p->phone;
                //   }
                // }
                $posts1[]=array('title'=>$user,'subtitle'=>'Time: '.$time,'buttons'=>array([
                    'type'=>'web_url','url'=>$weblink,'title'=>'TakeOff Location']));
             }

              $messages[]=array('attachment'=>[
                        'type'=>'template','payload'=>
                                [
                                    'template_type'=>'generic',
                                    'elements' =>$posts1
                                ]
                            ]
                        );
        // $ar[]=array("text"=>"Searched for:".$terms." Lon:".$longitude." Lat:".$latitude);
            //   define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
            //         $message = array('payload' => json_encode(array('text' => "Someone searched nearby for: '".$terms. "' ,from BOT")));
            // // Use curl to send your message
            //   $c = curl_init(SLACK_WEBHOOK);
            //   curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            //   curl_setopt($c, CURLOPT_POST, true);
            //   curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            //   curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            //   $res = curl_exec($c);
            //   curl_close($c);
                     return new JsonResponse([
                          'messages'=>$messages,
                      ]);
                }
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    //check if a user can book a ride
    public function check()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
 /*

    1. Condition2=>"user_id" has "additional_info" 
    2. Condition3=> "user_id" has "profile_photo"
    *he will be able to book a ride
*/  
        $checkCondition2=AdditionalUserInfo::where('user_id','=',$userId)->count();
        $checkCondition3=ProfilePhoto::where('user_id','=',$userId)->count();
        $msg=array();
        //return $checkCondition;
        //return $checkCondition1.'--'.$checkCondition2.'--'.$checkCondition3;
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
    public function store(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        //$canBook=$this->eligibility();
        // if (count($canBook)>0) {
        //     return new JsonResponse([
        //         'success'=>false,
        //         'messages' => $canShare,
        //       ],200);
        // }
        // else{
            if(OfferRide::where('id','=',$request->rideId)->where('user_id','!=',$userId)->where('isActive','=',1)->exists())
            {
                $ride=new BookARide;
                $ride->user_id=$userId;//rider
                $ride->offer_rides_id=$request->rideId;
                $ride->save();
                return new JsonResponse([
                    'success'=>true,
                    'messages' =>"Ride Requested.",
                  ],200);
            }else{
                return new JsonResponse([
                    'success'=>true,
                    'messages' =>"This ride is not available.",
                  ],200); 
            }
      //  }
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    //show a particular ride details from Ride Seekers "Nearest Rides Menu"
    public function show(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $showTheRide=OfferRide::with('vehicle')->with('user')->where('id','=',$request->id)->where('isActive','=',1)->where('isAvailable','=',1)->get();
        return new JsonResponse([
            'result'=>$showTheRide
        ]);
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
