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
}
