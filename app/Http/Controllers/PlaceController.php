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

class PlaceController extends Controller
{

  public function TestImageUp(Request $request){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
    $placeId = $request->pid;
    //source:
    //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
    $reciveFile =$request->file('file');
    //$imagedata = file_get_contents($file);
    //$base64 = base64_encode($imagedata);
    //return $base64;
    $client_id = '55c393c2e121b9f';    
    
    $file = file_get_contents($reciveFile);
    $title= $request->title;
    $relatedTo=$request->relatedTo;
    $url = 'https://api.imgur.com/3/image';
    $headers = array("Authorization: Client-ID $client_id");
    $imgarray  = array('image' => base64_encode($file),'title'=> $title);

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
    $theImageTitle=$json_a['data']['title'];
    $theImageRemove=$json_a['data']['deletehash'];
    $theImageLink=$json_a['data']['link'];
    curl_close ($curl);


    //save image info in images table;

    $saveImage=new Image;
    $saveImage->user_id=$userId;
    $saveImage->pid=$placeId;
    $saveImage->imageGetHash=$theImageHash;
    $saveImage->imageTitle=$theImageTitle;
    $saveImage->imageRemoveHash=$theImageRemove;
    $saveImage->imageLink=$theImageLink;
    $saveImage->relatedTo=$relatedTo;
    $saveImage->save();

    //return $json_a;
    return new JsonResponse([
        'message'=>'image added successfully!',
        'result'=>$json_a
        
      ]);
  }
  
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

        $input->uCode = $ucode;
        $input->isRewarded = 0;      
        $input->save();
        
        //$name = $request->name;
        //$email = $request->email;
        //$Messsage = $request->message;

      // Create a constant to store your Slack URL
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

        //everything went weel, user gets add place points, return code and the point he recived
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
        $message = array('payload' => json_encode(array('text' => "Someone Added a Place with Code:".$request->uCode. "'")));
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
    protected function Slacker($code){
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $message = array('payload' => json_encode(array('text' => "Someone searched for: ".$code. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
      $res=curl_exec($c);
      curl_close($c);

      return [];
    }
    //search address using code
    public function KhujTheSearch($code)
    {
      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);
      $this->Slacker($code);
      return $place->toJson();
    }

    public function KhujTheSearchSlackTest($code)
    {
      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);

      $message1="searched for: ".$code;
      $message = urlencode($message1); // Contains things like 'This is the message to the channel:\n\nHere is the second line with some *bold text* hopefully!'

     // $channel = '#the-channel-to-post-to';
      $data = 'payload=' . json_encode(array(
              'text'     => $message,
      ));

      $url = 'https://hooks.slack.com/services/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';

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
      curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
      $result = curl_exec($ch);
      if ($result === false) {
          echo 'Curl error: ' . curl_error($ch);
      }
      curl_close($ch);
      //return $res;
     // return $place->toJson();
      return new JsonResponse([
        "message"=> $result,
        "search"=>$place
        ]);
    }
    
    // Search places by name
    public function search($name)
    {
      $result = Place::where('Address','like','%'.$name.'%')->get();
      return $result->toJson();
    }

    // Search places by name
    public function searchNameAndCodeApp($name)
    {
     // $result = Place::where('Address','like','%'.$name.'%')->orWhere('uCode','=',$name)->get();
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      $getuserData=User::where('id','=',$userId)->select('name')->first();
      $name1="'".$getuserData->name."'";

      $result = Place::where('uCode', '=', $name)
            ->orWhere(function($query) use ($name) 
            {
                $query->where('Address','like','%'.$name.'%')
                      ->where('flag', '=', 1);
            })
            ->get();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      //webhook adnan: https://hooks.slack.com/services/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
      // https://hooks.slack.com/services/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
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');


    // Make your message
      $message = array('payload' => json_encode(array('text' => "".$name1." searched for: '".$name. "' from App")));
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

        // Search places by name
    public function searchNameAndCodeWeb(Request $request,$name)
    {
     // $result = Place::where('Address','like','%'.$name.'%')->orWhere('uCode','=',$name)->get();
      $result = Place::where('uCode', '=', $name)
            ->orWhere(function($query) use ($name) 
            {
                $query->where('Address','like','%'.$name.'%')
                      ->where('flag', '=', 1);
            })
            ->get();
          $ip=$request->ip();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
      //webhook adnan: https://hooks.slack.com/services/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
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');

    // Make your message
      $message = array('payload' => json_encode(array('text' => " " .$ip." Someone searched for: '".$name. "' from Website")));
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

    public function get_client_ip() {
      $ipaddress = '';
      //$_SERVER['HTTP_USER_AGENT'];
      
      // if (isset($_SERVER['HTTP_USER_AGENT']))
      // $ipaddress = $_SERVER['HTTP_USER_AGENT'];
        
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
      return gethostbyaddr($ipaddress);
    }
    
    public function KhujTheSearchPid($id)
    {
      $place = Place::find($id)->business_details;
      return $place->toJson();
    }

    //search with device ID
    public function KhujTheSearchApp($id)
    {
      $place = Place::where('device_ID','=',$id)->where('user_id', null)->get();
    //  $lon = $place->longitude;
    //  $lat = $place->latitude;
    //  $Address = $place->Address;
      return $place->toJson();
      /*response()->json([
        'lon' => $lon,
        'lat' => $lat,
        'address' => $Address
      ]);*/
    }

    public function getListViewItem($code)
    {
      $place = Place::where('uCode','=',$code)->first();
      return $place->toJson();
    }

    // fetch all data
    public function shobai()
    {
      $places = Place::all();
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
    public function getPlaceSubType($type)
    {
      $subtype = placeSubType::where('type','=',$type)->get();
  //    $subtype = $subtype->subtype;
//      return response()->json($subtype);
   
     return $subtype->toJson();
    }

    public function ashpash($ucode)
    {
      $places = Place::where('uCode','=',$ucode)->first();
      $lat = $places->latitude;
      $lon = $places->longitude;
      $result = DB::table('places')
                ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
        //  ->select(DB::raw('uCode, ( 6371 * acos(cos( radians(23) ) * cos( radians( '.$lat.' ) ) * cos( radians( '.$lon.' ) - radians(90) ) + sin( radians(23) ) * sin( radians( '.$lat.' ) ) ) ) AS distance'))
          ->where('flag','=',1)
          ->having('distance','<',0.5)
          ->orderBy('distance')
          ->limit(5)
          ->get();

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
           ->orderBy('distance')
           ->limit(10)
           ->get();

      return $result->toJson();

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
      //  $places->delete();
      return response()->json('Done');
    }
    public function count()
    {
      $place = DB::table('places')->where('flag',1)->count();

      return response()->json($place);
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

      // Create a constant to store your Slack URL
        define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      // Make your message
        $message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
      // Use curl to send your message
        $c = curl_init(SLACK_WEBHOOK);
        curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        curl_exec($c);
        curl_close($c);

        return response()->json('Thank you, We will get back to you soon.');
    }

}
