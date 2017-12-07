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
use Bugsnag\BugsnagLaravel\Facades\Bugsnag;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;

class PoolVehiclesController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //vehicles owned by a user
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $myVehicles=PoolVehicle::where('user_id','=',$userId)->get();
        
        return new JsonResponse([
            "result"=>$myVehicles
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
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        
        $input = new PoolVehicle;
        $input->user_id=$userId;
        $input->vehicle_type=$request->vehicle_type;
        $input->vehicle_regnum=$request->vehicle_regnum;
        $input->isApproved=0;//default 0,admin will change after verification
        //1, approved

        $input->isAllowedToServe=0;//0 initially, admin will change after verification. 1, allowed, 2.
        if($input->save()){
            if ($request->has('images'))
            {
              $client_id = '55c393c2e121b9f';
              $url = 'https://api.imgur.com/3/image';
              $headers = array("Authorization: Client-ID $client_id");
              $recivedFiles = $request->get('images');
              $uploadcount = count($recivedFiles);
              if($uploadcount>1){
                  $message1="Can not Upload more then 1 files";
              }
              else{
                  foreach($recivedFiles as $file)
                  {
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
                      $saveImage=new PoolPhoto;
                      $saveImage->user_id=$userId;
 
                      $saveImage->imageGetHash=$theImageHash;
                      //$saveImage->imageTitle=$theImageTitle;
                      $saveImage->imageRemoveHash=$theImageRemove;
                      $saveImage->imageLink=$theImageLink;
                      $saveImage->relatedTo='vehiclePhoto';
                      $saveImage->save();
                      $uploadcount--;
                  }
                  $message1="Image Saved Successfully";
                }
            }else{
                $message1="No Image Attachment Found.";
            }
            return new JsonResponse([
                'success' => true,
                'message' => 'Vehcile Information is Saved.',
                'image_uplod_messages'=>$message1
            ],201);
        }
        else{
            return new JsonResponse([
                'success' => false,
                'message' => 'Something went wrong while saving information.',
            ],200);
        }
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
