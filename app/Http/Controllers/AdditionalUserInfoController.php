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
use Carbon\Carbon;

class AdditionalUserInfoController extends Controller
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
    public function store(Request $request)
    {
        //
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

        $input = new AdditionalUserInfo;
        $input->user_id=$userId;
        $input->user_gender=$request->user_gender;
        $input->user_occupation=$request->user_occupation;
        $input->user_nid=$request->user_nid;
        $input->user_dob=Carbon::parse($request->user_dob);
        if($input->save()){
            //any photo id
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
                      $saveImage->relatedTo='photoID';
                      $saveImage->save();
                      $uploadcount--;
                  }
                  $message1="Image Saved Successfully";
                }
            }
            return new JsonResponse([
                'success' => true,
                'message' => 'Additional user Information is Saved.',
                'photo' =>$message1,
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
