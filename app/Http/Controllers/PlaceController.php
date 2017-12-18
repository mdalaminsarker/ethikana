<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use DB;
use Auth;
use App\User;
use App\Place;
use App\PlaceType;
use App\PlaceSubType;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;
use Carbon\Carbon;
class PlaceController extends Controller
{
    //

    public function Register(Request $request){

      $user = new User;
      $user->name = $request->name;
      $user->email = $request->email;
      $user->password = bcrypt($request->password);
      $user->save();

      return response()->json('Welcome');

    }
    // generate strings
    public function generateRandomString($length = 10) {
      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersLength = strlen($characters);
      $randomString = '';
      for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
      }
      return $randomString;
    }
    //generate numbers
    public function generateRandomNumber($length = 10) {
      $characters = '0123456789';
      $charactersLength = strlen($characters);
      $randomString = '';
      for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
      }
      return $randomString;
    }
    // Store and generate random code
    public function StorePlace(Request $request)
    {
      $string = $this->generateRandomString(4);
      $number = $this->generateRandomNumber(4);
      $ucode =  ''.$string.''.$number.'';
      $lat = $request->latitude;
      $lon = $request->longitude;
      //check if it is private and less then 20 meter
      if($request->flag==0){
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('device_ID','=',$request->device_ID) // same user can not add
           ->having('distance','<',0.01) //another private place in 50 meter
           ->get();
       $message='Can not add Multiple Private Address in 10 meter radius from Same Device';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){

        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.005) //no one 20 meter for public
           ->get();
        $message='A Public Place is Available in 5 meter.';
      }
      /*return response()->json([
          'Count' => $result->count()
          ]);*/
      if(count($result) === 0)
      {
        $input = new Place;
        $input->longitude = $lon;
        $input->latitude = $lat;
        $input->Address = $request->Address;
        $input->city = $request->city;
        $input->area = $request->area;
        $input->postCode = $request->postCode;
        $input->pType = $request->pType;
        $input->subType = $request->subType;
        //longitude,latitude,Address,city,area,postCode,pType,subType,flag,device_ID,user_id,email
        if($request->has('flag'))
        {
          $input->flag = $request->flag;
          if ($request->flag==1) {
            DB::table('analytics')->increment('public_count');
          }else{
            DB::table('analytics')->increment('private_count');
          }
        }
        if ($request->has('device_ID')) {
          $input->device_ID = $request->device_ID;
        }
        if ($request->has('user_id')) {
          $input->user_id = $request->user_id;
        }
        if ($request->has('email')){
          $input->email = $request->email;
        }
        if ($request->has('route_description')){
          $input->route_description = $request->route_description;
        }
        $input->uCode = $ucode;
        $input->isRewarded = 0;
        $input->save();

        //Slack Webhook : notify
        define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      // Make your message
        $message = array('payload' => json_encode(array('text' => "Someone Added a Place with Code:".$ucode. "")));
        //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
      // Use curl to send your message
        $c = curl_init(SLACK_WEBHOOK);
        curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
        $res = curl_exec($c);
        curl_close($c);

        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);

        //everything went well, return code and the point he recived
        return response()->json([
          'uCode' => $ucode
          ]);
      }
      else{
        //can't add places in 20/50 mter, return a message
        return response()->json([
          'message' => $message
          ]);
      }
    }
    //Store Custom Place
    public function StoreCustomPlace(Request $request)
    {
      $lat = $request->latitude;
      $lon = $request->longitude;
      //check if it is private and less then 20 meter
      if($request->flag==0){
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('device_ID','=',$request->device_ID)
           ->having('distance','<',0.01) //50 meter for private
           ->get();
       $message='Can not add Multiple Private Address in 10 meter radius from Same Device';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){

        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.005) //20 meter for public
           ->get();
        $message='A Public Place is Available in 5 meter';
      }
      if(count($result) === 0)
      {
        $input = new Place;
        $input->longitude = $lon;
        $input->latitude = $lat;
        $input->Address = $request->Address;
        $input->city = $request->city;
        $input->area = $request->area;
        $input->postCode = $request->postCode;
        $input->pType = $request->pType;
        $input->subType = $request->subType;
        //longitude,latitude,Address,city,area,postCode,pType,subType,flag,device_ID,user_id,email
        if($request->has('flag'))
        {
          $input->flag = $request->flag;
          if ($request->flag==1) {
            DB::table('analytics')->increment('public_count');
          }else{
            DB::table('analytics')->increment('private_count');
          }
        }
          if ($request->has('device_ID')) {
              $input->device_ID = $request->device_ID;
          }

        //ADN:when authenticated , user_id from client will be passed on this var.
        if ($request->has('user_id')) {
          $input->user_id = $request->user_id;
        }

        if ($request->has('email')){
          $input->email = $request->email;
        }

        $input->uCode = $request->uCode;
        $input->isRewarded = 0;
        $input->save();

        //Slack Webhook : notify
        define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      // Make your message
        $message = array('payload' => json_encode(array('text' => "Someone Added a Place with Code:".$request->uCode. "")));
        //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
      // Use curl to send your message
        $c = curl_init(SLACK_WEBHOOK);
        curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
        $res = curl_exec($c);
        curl_close($c);

        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);
        return response()->json([
          'uCode' => $request->uCode,
          ]);
      }
      else{
        return response()->json([
          'message' => $message
          ]);
      }
    }
 /*   public function Slacker($code){
      echo 'Ho';
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $message = array('payload' => json_encode(array('text' => "Someone searched for: ".$code. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_exec($c);
      curl_close($c);

      return [];
    } */

    //search address using code
    public function KhujTheSearchTest($code)
    {
      if($token = JWTAuth::getToken()){

        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $getuserData=User::where('id','=',$userId)->select('name')->first();
        $name="'".$getuserData->name."'";
      }
      else{
        $name='Someone';
      }

      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      //webhook adnan: https://hooks.slack.com/services/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
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');

    // Make your message
      $message = array('payload' => json_encode(array('text' => "".$name." searched for: ".$code. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
      return $place->toJson();
    }
    public function autocomplete()
    {
      $today = Carbon::today()->toDateTimeString();
      $yesterday = Carbon::yesterday()->toDateTimeString();
      $data = Place::whereDate('created_at','=',$today)->count();
      $yesterdayData = Place::whereDate('created_at','=',$yesterday)->count();
      $lastsevenday = Carbon::today()->subDays(6);
      $lastWeek = Place::whereBetween('created_at',[$lastsevenday,$today])->count();

      $results = DB::select(
                "SELECT
                COUNT(*)
                FROM
                places
                GROUP BY
                Address
                HAVING
                COUNT(Address) > 1");
      $count  =  count($results);
      $total  = DB::table('places')->count();
    //  $users = DB::table('places')->distinct()->get(['Address','area','longitude','latitude','pType','subType'])->count();
    //  $data = $data->Address;
      return response()->json([
        'Total' => $data,
        'Yesterday'=>$yesterdayData,
        'Duplicate' => $count,
        'all' => $total-$count,
        'lastWeek' => $lastWeek,
      //  'distinct' => $users

      ],200);
    }

    //
    public function KhujTheSearch($code)
    {
      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');

    // Make your message
      $message = array('payload' => json_encode(array('text' => "Someone searched for: ".$code. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);

      return $place->toJson();
    }

    public function getListViewItem($code)
    {
      $place = Place::with('images')->where('uCode','=',$code)->first();
      return $place->toJson();
    }


    //search with device ID
    public function KhujTheSearchApp($id)
    {

      $place = Place::where('device_ID','=',$id)->where('user_id', null)->get();
    //  $lon = $place->longitude;
    //  $lat = $place->latitude;
    //  $Address = $place->Address;
  //  return $place->toJson();
      /*response()->json([
        'lon' => $lon,
        'lat' => $lat,
        'address' => $Address
      ]);*/
    }

    // Search places by name
    public function search(Request $request)
    {
      //$result = Place::where('area','like',$name)->first();
      $result = DB::select("SELECT id,longitude,latitude,Address,area,city,postCode,uCode, pType, subType FROM
                places
                WHERE
                MATCH (Address, area)
                AGAINST ('.$request->search*' IN BOOLEAN MODE)
                LIMIT 10");

      return response()->json($result);
    }

    // Search places by name
    public function searchNameAndCodeApp(Request $request,$name)
    {
     // $result = Place::where('Address','like','%'.$name.'%')->orWhere('uCode','=',$name)->get();
      $terms=$name;
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      $getuserData=User::where('id','=',$userId)->select('name')->first();
      $name1="'".$getuserData->name."'";

      $result = Place::where('uCode', '=', $name)
            ->orWhere(function($query) use ($name)
            {
                $query->where('Address','like',$name.'%')
                      ->where('flag', '=', 1);
            })
            ->get();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      //webhook adnan: https://hooks.slack.com/services/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
      // https://hooks.slack.com/services/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

      if (isset($_SERVER['HTTP_CLIENT_IP']))
          $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
      else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
          $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
      else if(isset($_SERVER['HTTP_X_FORWARDED']))
          $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
      else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
          $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
      else if(isset($_SERVER['HTTP_FORWARDED']))
          $ipaddress = $_SERVER['HTTP_FORWARDED'];
      else if(isset($_SERVER['REMOTE_ADDR']))
          $ipaddress = $_SERVER['REMOTE_ADDR'];
      else
          $ipaddress = 'UNKNOWN';
      $clientDevice = gethostbyaddr($ipaddress);

      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');


    // Make your message
      $message = array('payload' => json_encode(array('text' => "".$name1." searched for: '".$name. "' from App, ip:".$clientDevice)));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);

            //Save the log to a .json file
      /*
      $file = file_get_contents('search_log.json', true);
      $data = json_decode($file,true);
      unset($file);
      */
      $file=Storage::disk('search')->get('search_log.json');
      $data = json_decode($file,true);
      unset($file);
      //you need to add new data as next index of data.
      $data[] =array(
          'dateTime'=> date('Y-m-d H:i:s'),
          'terms' => $terms,
          'url' => $request->url(),
          'from_IP' =>$clientDevice
          );
      $result1=json_encode($data,JSON_PRETTY_PRINT);
      //file_put_contents('search_log.json', $result);
      Storage::disk('search')->put('search_log.json', $result1);
      unset($result1);
      $log_save="ok";
      /*
      return new JsonResponse([
          'search_result'=>$posts,
          'array'=>$terms,
          'log_saved'=>$log_save
          ]); */
      return $result->toJson();
    }

    public function get_client_ip(Request $request) {
      //$ipaddress = '';
      //$_SERVER['HTTP_USER_AGENT'];

      // if (isset($_SERVER['HTTP_USER_AGENT']))
      // $ipaddress = $_SERVER['HTTP_USER_AGENT'];
      // dd($request);
      //return $request->server('HTTP_USER_AGENT');
     // $hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);
     // $isp = geoip_isp_by_name($_SERVER['REMOTE_ADDR']);
      $ip=$_SERVER['REMOTE_ADDR'];

      $url=file_get_contents("http://whatismyipaddress.com/ip/$ip");

      preg_match_all('/<th>(.*?)<\/th><td>(.*?)<\/td>/s',$url,$output,PREG_SET_ORDER);

      $isp=$output[1][2];

      $city=$output[9][2];

      $state=$output[8][2];

      $zipcode=$output[12][2];

      $country=$output[7][2];
      // if (isset($_SERVER['HTTP_CLIENT_IP']))
      //     $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
      // else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
      //     $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
      // else if(isset($_SERVER['HTTP_X_FORWARDED']))
      //     $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
      // else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
      //     $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
      // else if(isset($_SERVER['HTTP_FORWARDED']))
      //     $ipaddress = $_SERVER['HTTP_FORWARDED'];
      // else if(isset($_SERVER['REMOTE_ADDR']))
      //     $ipaddress = $_SERVER['REMOTE_ADDR'];
      // else
      //     $ipaddress = 'UNKNOWN';
      // return gethostbyaddr($ipaddress);
      echo $isp;
    }

        // Search places by name
    public function searchNameAndCodeWeb($name)
    {
     // $result = Place::where('Address','like','%'.$name.'%')->orWhere('uCode','=',$name)->get();
      $result = Place::where('uCode', '=', $name)
            ->orWhere(function($query) use ($name)
            {
                $query->where('Address','like',$name.'%')
                      ->where('flag', '=', 1);
            })
            ->get();

      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      //webhook adnan: https://hooks.slack.com/services/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
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');

      if (isset($_SERVER['HTTP_CLIENT_IP']))
          $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
      else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
          $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
      else if(isset($_SERVER['HTTP_X_FORWARDED']))
          $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
      else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
          $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
      else if(isset($_SERVER['HTTP_FORWARDED']))
          $ipaddress = $_SERVER['HTTP_FORWARDED'];
      else if(isset($_SERVER['REMOTE_ADDR']))
          $ipaddress = $_SERVER['REMOTE_ADDR'];
      else
          $ipaddress = 'UNKNOWN';
      $clientDevice = gethostbyaddr($ipaddress);

    // Make your message
      $message = array('payload' => json_encode(array('text' => "Someone searched for: '".$name. "' from Website, ip:".$clientDevice)));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
      return $result->toJson();
    }

    // fetch all data
    public function shobaix()
    {
      //$places = Place::all();
      $places = Place::orderBy('id','desc')->limit(2000)->get(['id','Address','area','longitude','latitude','pType','subType','uCode']);
      $chunks =$places->chunk(200);
      return $places->toJson();
    }
    //Test paginate
    public function shobaiTest()
    {
      $places = Place::with('images')->with('user')->orderBy('id', 'DESC')->paginate(50);
      return $places->toJson();
    }
    //delete
    public function mucheFeli($barikoicode)
    {
      $places = Place::where('uCode','=',$barikoicode)->first();
      $places->delete();

      return response()->json('Done');
    }
    //update
    public function halnagad(Request $request,$barikoicode){
      $places = Place::where('uCode','=',$barikoicode)->first();
      if ($request->has('longitude')) {
        $places->longitude = $request->longitude;
      }
      if ($request->has('latitude')) {
        $places->latitude = $request->latitude;
      }
      $places->Address = $request->Address;
      $places->city = $request->city;
      $places->area = $request->area;
      if($request->has('user_id')){
        $places->user_id = $request->user_id;
      }
      $places->postCode = $request->postCode;
      $places->flag = $request->flag;
      $places->save();
      //$splaces = SavedPlace::where('pid','=',$id)->update(['Address'=> $request->Address]);

      return response()->json('updated');
    }

    public function placeType(Request $request)
    {
      $type = new PlaceType;
      $type->type = $request->type;
      $type->save();

      return response()->json('Done');
    }
    public function placeSubType(Request $request)
    {
      $type = new PlaceSubType;
      $type->type = $request->type;
      $type->subtype = $request->subtype;
      $type->save();
        return response()->json('Done');
    }
    public function getPlaceType()
    {
      $type = PlaceType::all();

      return $type->toJson();
    }
    public function getPlaceType1()
    {
      $type = PlaceType::all();
      $answer="hello";
      $list[] = array('text' => 'welcome to our store!', 'text' => 'How can I help you');
      return response()->json($list);
    }
    public function getPlaceSubType($type)
    {
      $subtype = placeSubType::where('type','=',$type)->get();
  //    $subtype = $subtype->subtype;
//      return response()->json($subtype);

	return $subtype->toJson();
 }
    public function ashpash($ucode)
    {
      $places = Place::with('images')->where('uCode','=',$ucode)->first();
      $lat = $places->latitude;
      $lon = $places->longitude;
	    $result = Place::with('images')
          ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
        //  ->select(DB::raw('uCode, ( 6371 * acos(cos( radians(23) ) * cos( radians( '.$lat.' ) ) * cos( radians( '.$lon.' ) - radians(90) ) + sin( radians(23) ) * sin( radians( '.$lat.' ) ) ) ) AS distance'))
          ->where('flag','=',1)
          ->having('distance','<',0.5)
          ->orderBy('distance')
          ->limit(10)
          ->get();
      DB::table('analytics')->increment('search_count',1);
      return $result->toJson();
}
public function amarashpash(Request $request)
    {
      $lat = $request->latitude;
      $lon = $request->longitude;

      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->having('distance','<',0.5)
           ->where('flag','=',1)
           ->whereNotIn('pType', ['Residential'])
           ->orderBy('distance')
           ->limit(10)
           ->get();
      DB::table('analytics')->increment('search_count',1);
      return $result->toJson();

    }

  public function analytics()
    {
      $numbers=analytics::all();
      return $numbers->toJson();
    }

    public function savedPlaces(Request $request)
    {
      $saved = new SavedPlace;
      $saved->uCode = $request->uCode;
      $saved->Address = $request->Address;
      $saved->device_ID = $request->device_ID;
      $saved->email = $request->email;
      $saved->save();
      DB::table('analytics')->increment('saved_count');

      return response()->json('saved');

    }

  public function getSavedPlace($deviceID)
    {
	    $place= DB::table('saved_places')
          ->where('device_ID','=',$deviceID)
          ->get();

      return $place->toJson();

    }

  public function DeleteSavedPlace(Request $request,$code)
  {
	//$places = SavedPlace::where('uCode','=',$code)->where('device_ID','=',$request->device_ID)->get();
      $places = DB::table('saved_places')->where('uCode','=',$code)->where('device_ID','=', $request->device_ID)->delete();
//	$places->delete();
      return response()->json('Done');
  }

  public function count()
  {
    $place = DB::table('places')->count();
    $placePub = DB::table('places')->where('flag',1)->count();
    $placePri = DB::table('places')->where('flag',0)->count();
    return response()->json([
      'place_total'=>$place,
      'place_public'=>$placePub,
      'place_private'=>$placePri]);
  }
 /*  public function devices()
{
	$users = DB:table('places')->distinct('device_ID')->count();
    return response()->json($users);
}*/
  public function contactUs(Request $request)
    {
      $name = $request->name;
      $email = $request->email;
      $Messsage = $request->message;

      $message = ''.$name.', '.$email.' wants to get connected';
      $channel = 'random';
      $data = array(
           'channel'     => $channel,
           'username'    => 'tayef',
           'text'        => $message

       );
      //Slack Webhook : notify
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $message_string = array('payload' => json_encode($data));
      //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message_string);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);

        return response()->json('Thank you, We will get back to you soon.');
    }

    public function tourism()
    {
      $ghurbokoi = Place::with('images')->where('pType','=','Tourism')->get();

      return $ghurbokoi->toJson();
    }

    public function duplicate($id)
    {
      $today = Carbon::today()->toDateTimeString();
      $yesterday = Carbon::yesterday()->toDateTimeString();
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

      $count = count($results);
       return response()->json([
         'count' => $count,
         'date' =>$today,
         'duplicates' => $results,


       ]);
    }
    public function fakeCatcher(Request $request)
    {
      $place = Place::where('user_id',$request->id)->where('Address','like','%'.$request->Address.'%')->where('pType','Residential')->get();
      $count = count($place);
      return response()->json([
        'count'=> $count,
        'Places' => $place,
    ]);
    }


        public function duplicateforMapper(Request $request)
        {
          $id = $request->user()->id;
          $today = Carbon::today()->toDateTimeString();
          $yesterday = Carbon::yesterday()->toDateTimeString();
          $results = DB::select(
                    "SELECT
                    Address, area,pType,user_id,created_at, COUNT(*)
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

          $count = count($results);
           return response()->json([
             'count' => $count,
             'date' =>$today,
             'duplicates' => $results,


           ]);
        }

    public function getPlaceByType(Request $request)
    {
      $place = Place::where('subType', $request->subType)->get(['id','Address','area','longitude','latitude','pType','subType']);
      $count = count($place);
      return response()->json([
        'Total' => $count,
        'Places' => $place,
      ]);
    }

    public function getAllSubtype()
    {
      $subtype = PlaceSubType::all();
      return $subtype->toJson();
    }
    public function dropEdit(Request $request,$id)
    {
      $place = Place::findOrFail($id);
      $place->longitude = $request->longitude;
      $place->latitude = $request->latitude;
      $place->save();

      return response()->json(['Message '=>' Updated']);
    }

}
