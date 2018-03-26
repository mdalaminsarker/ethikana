<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Excel;
use DB;
use Auth;
use Validator;
use App\User;
use App\Place;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use App\Image;
use App\Services;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\Filesystem;
use League\Flysystem\Adapter\Local;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Client;


//use Maatwebsite\Excel\Facades\Excel;
class testController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        //
        // $response="Abcg";
        // $fp = fopen('res.json', 'w');
        // fwrite($fp, json_encode($response));
        // fclose($fp);
        // return "Ok";
        // $posts = array(
        //     'dateTime'=> date('Y-m-d H:i:s'),
        //     'title' => 'A',
        //     'url' => 'www\n',
        //     );
        // $json_data = json_encode($posts);
        // file_put_contents('myfile.json', $json_data);
        // $inp = file_get_contents('myfile.json');
        // $tempArray = json_decode($inp);
        // array_push($tempArray, $posts);
        // $jsonData = json_encode($tempArray);
        // file_put_contents('myfile.json', $jsonData);
        // $user = "bross";
        // $first = "Bob";
        // $last = "Ross";
        // $file = "res.json";
        // $json = json_decode(file_get_contents($file), true);
        // $json[$user] = array("first" => $first, "last" => $last);
        // file_put_contents($file, json_encode($json));
        if ($request->is('v1/*')) {
            #IP
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


            # code...
            //$file = Storage::get('search_log.json', true);
            //$file = file_get_contents('search_log.json', true);
            $file=Storage::disk('json')->get('search_log.json');
            $data = json_decode($file,true);
            unset($file);
            //you need to add new data as next index of data.
            $data[] =array(
                'dateTime'=> date('Y-m-d H:i:s'),
                'terms' => 'A',
                'url' => $request->url(),
                'from_IP' =>$clientDevice
                );
            $result=json_encode($data,JSON_PRETTY_PRINT);
            //file_put_contents('search_log.json', $result);
            //Storage::disk('local')->put('search_log.json', $result);
            Storage::disk('json')->put('search_log.json', $result);
            unset($result);

           //Storage::disk('json')->put('file.json', $content);
           // $content = Storage::disk('json')->get('file.json');
            /*
            $data = json_encode(file_get_contents("search_log.json"));
            File::put('nonesense.txt', $contents);
            $fbData = Storage::get('nonesense.txt');
            $fbData = json_decode($fbData);
            */

            return "ok";
        }else{
            return "not ok";
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
    public function random_code()
    {
      $charactersChar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersCharLength = strlen($charactersChar);
      $randomStringChar = '';
      for ($i = 0; $i < 4; $i++) {
          $randomStringChar .= $charactersChar[rand(0, $charactersCharLength - 1)];
      }
      //number part
      $charactersNum = '0123456789';
      $charactersNumLength = strlen($charactersNum);
      $randomStringNum = '';
      for ($i = 0; $i < 4; $i++) {
          $randomStringNum .= $charactersNum[rand(0, $charactersNumLength - 1)];
      }

      $ucode =  ''.$randomStringChar.''.$randomStringNum.'';
      return $ucode;
    }
    public function excel(Request $request)
    {
        //
        // $p=Excel::create('Laravel Excel', function($excel)
        // {
        //     $excel->sheet('Excel sheet', function($sheet) {
        //         $sheet->setOrientation('landscape');
        //     });
        // })->export('xls');

        // return "ok";

        if($request->file('imported-file'))
        {
            $path = $request->file('imported-file')->getRealPath();
            $data = Excel::load($path, function($reader){})->get();

            if(!empty($data) && $data->count())
            {
                foreach ($data->toArray() as $row)
                {
                  if(!empty($row))
                  {
                    $address=$row['name'].','.$row['location'];
                    $ucode=$this->random_code();
                    $dataArray[] =
                    [
                      'user_id'=>1,
                      'longitude' => $row['longitude'],
                      'latitude' => $row['lattitude'],
                      'Address' =>$address,
                      'city' =>"Dhaka",
                      'pType'=>"Hospital",
                      'uCode' => $ucode,
                      'flag' => 1
                      //'created_at' => $row['created_at']
                    ];
                  }
              }
              if(!empty($dataArray))
              {
                 if(Place::insert($dataArray)){
                    $success=true;
                 }else{
                    $success=false;
                 }
                 //$g=$data->count();
               }
             }
       }
        return new JsonResponse([
                'success'=>$success,
            ]);
    }
    // public function mtb(Request $request){
    //   $user = JWTAuth::parseToken()->authenticate();
    //   $userId = $user->id;
    //   if($request->file('imported-file'))
    //   {
    //       $path = $request->file('imported-file')->getRealPath();
    //       $file = file_get_contents($path, true);
    //       $data = json_decode($file,true);

    //       // $atm=array();
    //       // foreach($data as $item) { //foreach element in $arr

    //       //   $atm[]=$item;
    //       // }

    //       // if(!empty($data) && $data->count())
    //       // {
    //           foreach ($data as $row)
    //           {
    //             if(!empty($row))
    //             {
    //               $address=$row['name'].','.$row['Address'];
    //               //$cityPiceces=array();
    //               //$cityPiceces[]=explode(",", $r1)
    //               //end($r2)
    //               $ucode=$this->random_code();
    //               //$city=array();
    //              // $area=end($row);
    //               //$city[] = $row['city'];
    //               $dataArray[] =
    //               [
    //                 'user_id'=>$userId, //1=local//459=DO
    //                 'longitude' => $row['longitude'],
    //                 'latitude' => $row['latitude'],
    //                 'Address' =>$address,
    //                 'city' => $row['city'],
    //                 'area' => $row['area'],
    //                 'pType'=> "GOVT",
    //                 //'subType' => "Service Points",
    //                 'uCode' => $ucode,
    //                 'flag' => 1
    //                 //'created_at' => $row['created_at']
    //               ];
    //             }
    //         }
    //         if(!empty($dataArray))
    //         {
    //            if(Place::insert($dataArray)){
    //               $success=true;
    //            }else{
    //               $success=false;
    //            }
    //           // $g=$data->count();
    //         }

    //     }

    //     return new JsonResponse([
    //         'success'=>$success,
    //       ]);
    // }

      public function mtb(Request $request){
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      if($request->file('imported-file'))
      {
          $path = $request->file('imported-file')->getRealPath();
          $file = file_get_contents($path, true);
          $data = json_decode($file,true);

              foreach ($data as $row)
              {
                if(!empty($row))
                {
                  $dataArray[] =
                  [
                    'service_category_name'=>$row['service_category_name'],
                    'service_tag' => $row['service_tag'],
                    'isShowable'=>1
                  ];
                }
              }
            if(!empty($dataArray))
            {
               if(Services::insert($dataArray)){
                  $success=true;
               }else{
                  $success=false;
               }
              // $g=$data->count();
            }

        }

        return new JsonResponse([
            'success'=>$success,
          ]);
    }

    public function HandyMama(Request $request)
    {
      $message = ' '.$request->user()->name.' Requested '.$request->order_data.'';
      $channel = 'handymamaleads';
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

      return response()->json($request->user()->name);
    }

    public function BikeRental(Request $request)
    {
      $message = ' '.$request->user()->name.' Requested '.$request->order.' Number: '.$request->user()->phone.'';
      $channel = 'bikerental';
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
      $this->testsms($request->user()->name,$request->user()->phone);
      return response()->json(['message'=> 'Order Receieved']);


    }

    public function rentalDocs()
    {
      $required = "1.NID (Smart Card) Original Copy\n2.Photocopy of Driving License\n3.Photocopy of guarantor's NID\n4.Address in Barikoi\n5.Proof of Address.";

      $terms = "Payment has to be made upfront";

      return response()->json([
        'Require Docs' => $required,
        'terms' => $terms,
      ]);
    }

    public function testsms($name,$number)
    {
      $to = $number;
      $token = "7211aa139c9eaaa7184cead6c1bc7bee";
      $message = "Dear ".$name.", We have recieved your request. We will call on your desired time. Thank you";

      $url = "http://sms.greenweb.com.bd/api.php";


      $data= array(
      'to'=>"$to",
      'message'=>"$message",
      'token'=>"$token"
      ); // Add parameters in key value
      $ch = curl_init(); // Initialize cURL
      curl_setopt($ch, CURLOPT_URL,$url);
      curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      $smsresult = curl_exec($ch);

      return response()->json($smsresult);
    }
    public function distance()
    {
      $lon1 = '90.422846';
      $lon2 = '90.417061';
      $lat = '23.780954';
      $lat2 = '23.780370';
      $client = new Client();
      $result = $client->request('GET', 'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins='.$lat.','.$lon1.'&destinations='.$lat2.','.$lon2.'&key=AIzaSyCMFVbYCGFzRmWfKuKlkDSzwT4azYrNdmM');
      $result = $result->getBody();

      return $result;
    }
    public function Getdistance($SourceLon,$SourceLat,$DestinationLon,$DestinationLot)
    {
      $lon1 = $SourceLon;
      $lon2 = $DestinationLon;
      $lat = $SourceLat;
      $lat2 = $DestinationLot;
      $client = new Client();
      $result = $client->request('GET', 'https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins='.$lat.','.$lon1.'&destinations='.$lat2.','.$lon2.'&key=AIzaSyCMFVbYCGFzRmWfKuKlkDSzwT4azYrNdmM');
      $result = $result->getBody();

      return $result;
    }

    public function aci()
    {

      return response()->json([
        'order_number ' => 'abcd1234',
        'outlet' => 'Mirpur',
        'delivery_date' => '06-03-2018',
        'delivery_slot' => '9-12',
        'delivery_status' => 'Confirmed',
        'delivery_executive' => 'xyz',
        'delivered_time' => '11:39:00',
        'delivered_date' => '06-03-2018',
        'call_centre_agent' => 'lubna',
        'delivery_executive_remarks' => 'lubna',
        'call_centre_agent_remarks' => 'lubna',
        'DM_remarks' => 'Delivery_morse',
        'payment_method' => 'Cash',
        'trip_type' => 'regular',
        'availability_status' => 'available',
        'call_centre_agentc' => 'lubna',
        'call_centre_agentd' => 'lubna',
        'call_centre_agente' => 'lubna',
        'attachment'=> 'order.PDF',
        'createdby'=> 'Customer Service',
        'createdate'=> '06-03-2018',



      ]);
    }
    public function replace(Request $request)
    {
      DB::table('places')->update(['area' => DB::raw("REPLACE(area, '".$request->x."', '".$request->y."')")]);

      return response()->json('ok');
    }


}
