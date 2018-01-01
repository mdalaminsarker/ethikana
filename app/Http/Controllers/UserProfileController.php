<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use DB;
use App\Place;
use App\User;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use App\PoolVehicle;
use App\PoolPhoto;
use App\AdditionalUserInfo;
use App\Image;
use App\ProfilePhoto;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Carbon\Carbon;
class UserProfileController extends Controller
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

        $userDetails=User::with('proPic')->with('moreInfo')->with('vehicles')->with('poolPhoto')->where('id','=',$userId)->get();

        return $userDetails;
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function storeProPic(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

        $client_id = '55c393c2e121b9f';
        $url = 'https://api.imgur.com/3/image';
        $headers = array("Authorization: Client-ID $client_id");
        //source:
        //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
        $recivedFiles = $request->get('images');
        //$file_count = count($reciveFile);
      // start count how many uploaded
        $uploadcount = count($recivedFiles);
        //return $uploadcount;
        if($uploadcount>1){
            $message="Can not Upload more then 1 files";
        }
        else{
            foreach($recivedFiles as $file)
            {
                //$img = file_get_contents($file);
                //$imgarray  = array('image' => base64_encode($file),'title'=> $title);
                $imgarray  = array('image' => $file);

                $curl = curl_init();

                curl_setopt_array($curl, array(
                   CURLOPT_URL=> $url,
                   CURLOPT_TIMEOUT => 30,
                   CURLOPT_POST => 1,
                   CURLOPT_RETURNTRANSFER => 1,
                   CURLOPT_HTTPHEADER => $headers,
                   CURLOPT_POSTFIELDS => $imgarray
                ));
                $json_returned = curl_exec($curl); // blank response
                $json_a=json_decode($json_returned ,true);
                $theImageHash=$json_a['data']['id'];
               // $theImageTitle=$json_a['data']['title'];
                $theImageRemove=$json_a['data']['deletehash'];
                $theImageLink=$json_a['data']['link'];
                curl_close ($curl);

                //save image info in images table;
                $saveImage=new ProfilePhoto;
                $saveImage->user_id=$userId;

                $saveImage->imageGetHash=$theImageHash;
                //$saveImage->imageTitle=$theImageTitle;
                $saveImage->imageRemoveHash=$theImageRemove;
                $saveImage->imageLink=$theImageLink;
                //$saveImage->isShowable=1;
                $saveImage->save();

                $uploadcount--;
            }
            $message="Images Saved Successfully";
        }

        //return $json_a;
        return new JsonResponse([
            //'message'=>'image added successfully!',
            'result'=> $message,
            'status' => http_response_code()
          ]);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function showProPic()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $userProfilePhoto=ProfilePhoto::where("user_id",'=',$userId)->first();
        //DB::table('analytics')->increment('search_count');
        //return $userProfilePhoto;
        if (is_null($userProfilePhoto)) {
            return new JsonResponse([
                'image'=>'not found',
                'result'=>$userProfilePhoto
              ]);
        }else{

            return new JsonResponse([
                'image'=>'found',
                'result'=>$userProfilePhoto
              ]);
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
    public function destroyProPic()
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        if(User::where('id','=',$userId)->exists()){
           ProfilePhoto::where('user_id','=',$userId)->delete();
            return new JsonResponse([
                'success'=>true,
                'message'=>'Profile Image Deleted',
                //'result'=>$json_a
              ],200);
        }else{
            return new JsonResponse([
                'success'=> false,
                'message'=>'Delete Unsuccessful',
            ],200);
        }
    }

    //============================================= contributor management =============================================
    public function Contributors()
    {
      $Contributors = User::where('isAllowed',0)->get();
      return $Contributors->toJson();
    }
    public function ContributorAddedPlacesX(Request $request,$id)
    {
      /*if ($request->has('dateFrom')) {
        $dateFrom = $request->dateFrom;
        $dateTo = $request->dateTo;
      }*/
      $today = Carbon::today()->toDateTimeString();
      $lastsevenday = Carbon::today()->subDays(6);
      if ($request->has('date')) {
        $date = $request->date;

        $newDate  = new Carbon($date);
        $today = Carbon::today();
        /*$Places = Place::with('images')->where('user_id',$id)
        ->whereDate('created_at',$date)
        ->get(['id','Address','area','pType','subType','longitude','latitude','uCode','created_at']);*/
        $count = Place::where('user_id',$id)
        ->whereDate('created_at',$date)
        ->count();
        $total = Place::where('user_id',$id)
      //  ->whereDate('created_at',$today)
        ->count();
        $results = DB::select(
                  "SELECT
                  Address,area,pType,user_id,created_at, COUNT(*)
                  FROM
                  places
                  WHERE
                  user_id = $id
                  GROUP BY
                  Address,area,pType,user_id
                  HAVING
                  COUNT(*) >1
                  ORDER BY
                  created_at");

                  $lastWeek = Place::where('user_id',$id)->whereBetween('created_at',[$lastsevenday,$today])->count();

      }else {
        $today = Carbon::today();
      /*  $Places = Place::with('images')->where('user_id',$id)
        ->whereDate('created_at',$today)
        ->get(['id','Address','area','pType','subType','longitude','latitude','uCode','created_at']);*/
        $count = Place::where('user_id',$id)
        ->whereDate('created_at',$today)
        ->count();
        $results = DB::select(
                  "SELECT
                  Address,area,pType,user_id,created_at, COUNT(*)
                  FROM
                  places
                  WHERE
                  user_id = $id
                  GROUP BY
                  Address,area,pType,user_id
                  HAVING
                  COUNT(*) >1
                  ORDER BY
                  created_at");
        $total = Place::where('user_id',$id)->count();
        $lastWeek = Place::where('user_id',$id)->whereBetween('created_at',[$lastsevenday,$today])->count();
      //  ->whereDate('created_at',$today)

      }
      if ($id === '1' || $id === '12'|| $id === '665' || $id === '676' || $id === '739' || $id === '779') {
        return new JsonResponse([
           'Duplicate' => count($results),
            'Count Todays' => $count,
            'Todays Income' => $count*0.80,
            'Total Income' =>  $total*0.80-(count($results)),
            'Total Added' => $total,
            'last Week' => $lastWeek,
          ],200);
      }
      else{
      return new JsonResponse([
         'Duplicate' => count($results),
          'Count Todays' => $count,
          'Todays Income' => $count*1,
          'Total Income' =>  $total*1-(count($results)),
          'Total Added' => $total,
          'last Week' => $lastWeek,


        ],200);
     }

    }
    public function ContributorAddedPlaces(Request $request,$id)
    {
      /*if ($request->has('dateFrom')) {
        $dateFrom = $request->dateFrom;
        $dateTo = $request->dateTo;
      }*/
      $today = Carbon::today()->toDateTimeString();
      $lastsevenday = Carbon::today()->subDays(6);

      if ($request->has('date')) {
        $date = $request->date;

        $newDate  = new Carbon($date);
        $today = Carbon::today();
        $Places = Place::with('images')->where('user_id',$id)
        ->whereDate('created_at',$date)
        ->get(['id','Address','area','pType','subType','longitude','latitude','uCode','created_at']);
        $count = Place::where('user_id',$id)
        ->whereDate('created_at',$date)
        ->count();
        $total = Place::where('user_id',$id)
      //  ->whereDate('created_at',$today)
        ->count();
        $lastWeek = Place::whereBetween('created_at',[$lastsevenday,$today])->count();

      }else {
        $today = Carbon::today();
        $Places = Place::with('images')->where('user_id',$id)
        ->whereDate('created_at',$today)
        ->get(['id','Address','area','pType','subType','longitude','latitude','uCode','created_at']);
        $count = Place::where('user_id',$id)
        ->whereDate('created_at',$today)
        ->count();
        $total = Place::where('user_id',$id)
      //  ->whereDate('created_at',$today)
        ->count();
        $lastWeek = Place::whereBetween('created_at',[$lastsevenday,$today])->count();

      }
      return new JsonResponse([
          'Message' => $Places,
          'Count Todays' => $count,
          'Todays Income' => $count*1,
          'Total Income' =>  $total,
          'Total Added' => $total,
          'last Week' => $lastWeek,

        ],200);


    }

    public function latest(Request $request)
    {
      $latest = Place::where('user_id',$request->user()->id)->limit(100)->orderBy('id','desc')->get();

      return $latest->toJson();
    }

}
