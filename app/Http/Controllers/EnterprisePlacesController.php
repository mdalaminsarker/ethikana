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
use App\Reward;
use App\Image;
use Illuminate\Support\Str;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Hash;

class EnterprisePlacesController extends Controller
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
    //add random coded places
    public function storeRandom(Request $request)
    {
        //
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      //char part
      $GetUserType=User::where('id','=',$userId)->select('userType')->first();
      $userType=$GetUserType->userType;  
      if($userType==3)
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

          $lat = $request->latitude;
          $lon = $request->longitude;
          // //check if it is private and less then 10 meter
          // if($request->flag==0){
          // $result = DB::table('places')
          //      ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //     //->where('pType', '=','Food')
          //      ->where('flag','=',0)
          //      ->where('user_id','=',$userId) // same user can not add
          //      ->having('distance','<',0.005) //another private place in 5 meter
          //      ->get();
          //  $message='Can not Add Another Private Place in 5 meter';
          // }

          //if no places from this user exists,
          // if(count($result) === 0)
          // {
            $input = new Place;
            $input->longitude = $lon;
            $input->latitude = $lat;
            $input->Address = $request->Address;
            $input->city = $request->city;
            $input->area = $request->area;
            $input->postCode = $request->postCode;
            $input->pType = $request->pType;
            $input->subType = $request->subType;  
            //enterprise addresses always private=0
            $input->flag = 0;
            if($request->has('device_ID')) {
                $input->device_ID = $request->device_ID;
            }
            $input->user_id =$userId;
            if ($request->has('email')){
              $input->email = $request->email;
            }
            $input->uCode = $ucode;
            $input->isRewarded = 0;
            $input->contact_person_name = $request->contact_person_name;
            $input->contact_person_phone = $request->contact_person_phone;
            $input->save();
            //if image is there, in post request
            $message1='no image file attached.';
            $imgflag=0;
            //handle image
            //user will get 5 points if uploads images
            //$img_point=0; //inititate points for image upload
            
            if ($request->has('images'))
            {
                $placeId=$input->id; //get latest the places id
                $relatedTo=$request->relatedTo;
                $client_id = '55c393c2e121b9f';
                $url = 'https://api.imgur.com/3/image';
                $headers = array("Authorization: Client-ID $client_id");
                //source:
                //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
                $recivedFiles = $request->get('images');
                //count how many uploaded
                $uploadcount = count($recivedFiles);
                //return $uploadcount;
                if($uploadcount>4){
                    $message1="Can not Upload more then 4 files";
                    $imgflag=0; //not uploaded
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
                      $saveImage=new Image;
                      $saveImage->user_id=$userId;
                      $saveImage->pid=$placeId;
                      $saveImage->imageGetHash=$theImageHash;
                      //$saveImage->imageTitle=$theImageTitle;
                      $saveImage->imageRemoveHash=$theImageRemove;
                      $saveImage->imageLink=$theImageLink;
                      $saveImage->relatedTo=$relatedTo;
                      $saveImage->save();
                      $uploadcount--;
                }
                $imgflag=1;
                $message1="Image Saved Successfully";
                //$img_point=5;
              }//else end
            } //if reuest has image
           //Slack Webhook : notify
            define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
           // Make your message
            $getuserData=User::where('id','=',$userId)->select('name')->first();
            $name=$getuserData->name;
            $message = array('payload' => json_encode(array('text' => " ".$name." Added a Place with Code:".$ucode."")));
            //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
          // Use curl to send your message
            $c = curl_init(SLACK_WEBHOOK);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($c, CURLOPT_POST, true);
            curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            $res = curl_exec($c);
            curl_close($c);
            //Give that guy 5 points.
            //User::where('id','=',$userId)->increment('total_points',5+$img_point);
            //$getTheNewTotal=User::where('id','=',$userId)->select('total_points')->first();
            //DB::table('analytics')->increment('code_count');
            //return response()->json($ucode);
            //everything went weel, user gets add place points, return code and the point he recived
            return response()->json([
              'uCode' => $ucode,
              'img_flag' => $imgflag,
              'image_upload_message'=>$message1,
              'status'=>200
              ],200);
         // }
          // else
          // {
          //   //can't add places in 20/50 mter, return a message
          //   return response()->json([
          //     'message' => $message,
          //     'status' => 204
          //     ],204);
          // }      
        }
        else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                'status' => 403
                ],403);
        }
    }

    //add custom coded places
    public function storeCustom(Request $request)
    {
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      //char part
      $GetUserType=User::where('id','=',$userId)->select('userType')->first();
      $userType=$GetUserType->userType;  
      if($userType==3)
      {
         // $ucode =  ''.$randomStringChar.''.$randomStringNum.'';

          $lat = $request->latitude;
          $lon = $request->longitude;
          //check if it is private and less then 10 meter
          // if($request->flag==0){
          // $result = DB::table('places')
          //      ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //     //->where('pType', '=','Food')
          //      ->where('flag','=',0)
          //      ->where('user_id','=',$userId) // same user can not add
          //      ->having('distance','<',0.005) //another private place in 5 meter
          //      ->get();
          //  $message='Can not Add Another Private Place in 5 meter';
          // }

          //if no places from this user exists,
          // if(count($result) === 0)
          // {
            $input = new Place;
            $input->longitude = $lon;
            $input->latitude = $lat;
            $input->Address = $request->Address;
            $input->city = $request->city;
            $input->area = $request->area;
            $input->postCode = $request->postCode;
            $input->pType = $request->pType;
            $input->subType = $request->subType;  
            //enterprise addresses always private=0
            $input->flag = 0;
            if($request->has('device_ID')) {
                $input->device_ID = $request->device_ID;
            }
            $input->user_id =$userId;
            if ($request->has('email')){
              $input->email = $request->email;
            }
            $input->uCode = $request->uCode;  
            $input->isRewarded = 0;
            $input->contact_person_name = $request->contact_person_name;
            $input->contact_person_phone = $request->contact_person_phone;    
            $input->save();
            //if image is there, in post request
            $message1='no image file attached.';
            $imgflag=0;
            //handle image
            //user will get 5 points if uploads images
            //$img_point=0; //inititate points for image upload
            
            if ($request->has('images'))
            {
                $placeId=$input->id; //get latest the places id
                $relatedTo=$request->relatedTo;
                $client_id = '55c393c2e121b9f';
                $url = 'https://api.imgur.com/3/image';
                $headers = array("Authorization: Client-ID $client_id");
                //source:
                //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
                $recivedFiles = $request->get('images');
                //count how many uploaded
                $uploadcount = count($recivedFiles);
                //return $uploadcount;
                if($uploadcount>4){
                    $message1="Can not Upload more then 4 files";
                    $imgflag=0; //not uploaded
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
                      $saveImage=new Image;
                      $saveImage->user_id=$userId;
                      $saveImage->pid=$placeId;
                      $saveImage->imageGetHash=$theImageHash;
                      //$saveImage->imageTitle=$theImageTitle;
                      $saveImage->imageRemoveHash=$theImageRemove;
                      $saveImage->imageLink=$theImageLink;
                      $saveImage->relatedTo=$relatedTo;
                      $saveImage->save();
                      $uploadcount--;
                }
                $imgflag=1;
                $message1="Image Saved Successfully";
                //$img_point=5;
              }//else end
            } //if reuest has image
           //Slack Webhook : notify
            define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
           // Make your message
            $getuserData=User::where('id','=',$userId)->select('name')->first();
            $name=$getuserData->name;
            $message = array('payload' => json_encode(array('text' => " ".$name." Added a Place with Code:".$request->uCode."")));
            //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
          // Use curl to send your message
            $c = curl_init(SLACK_WEBHOOK);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($c, CURLOPT_POST, true);
            curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            $res = curl_exec($c);
            curl_close($c);

            return response()->json([
              'uCode' => $request->uCode,
              'img_flag' => $imgflag,
              'image_upload_message'=>$message1,
              'status'=>200
              ],200);
        //  }
         // else
          // {
          //   return response()->json([
          //     'message' => $message,
          //     'status' => 204
          //     ],204);
          // }      
        }
        else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                'status' => 403
                ],403);
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
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        if($userType==3){
            $getThePlace=Place::with('images')->with('business_details')->where('id','=',$id)->get();
            return new JsonResponse([
                'success' => true,
                'message' => 'Place Details Provided',
                'place_info'=>$getThePlace,
                'status' => 200
                ],200); 
        }else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                'status' => 403
                ],403); 
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
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        if($userType==3)
        {
            $places = Place::where('id','=',$id)->first();
            if ($request->has('longitude')) {
                $places->longitude = $request->longitude;
            }
            if ($request->has('latitude')) {
                $places->latitude = $request->latitude;
            }
            $places->Address = $request->Address;
            $places->city = $request->city;
            $places->area = $request->area;
            $places->user_id = $userId; 
            $places->postCode = $request->postCode;
            $places->flag = 0;
            if ($request->has('contact_person_name')) {
                $places->contact_person_name = $request->contact_person_name;
            }
            if ($request->has('contact_person_phone')) {
                $places->contact_person_phone = $request->contact_person_phone;
            }
            if ($request->has('relatedTo')) {
                $places->relatedTo = $request->relatedTo;
            }
            $places->save();

                  //Slack Webhook : notify
            define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
          // Make your message
            $getuserData=User::where('id','=',$userId)->select('name')->first();
            $name=$getuserData->name;
            $getPlaceData=Places::where('id','=',$id)->select('uCode')->first();
            $placeCode=$getPlaceData->uCode;
            $message = array('payload' => json_encode(array('text' => "Place Code:".$placeCode."Updated by:".$name."")));
            //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
          // Use curl to send your message
            $c = curl_init(SLACK_WEBHOOK);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($c, CURLOPT_POST, true);
            curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            $res = curl_exec($c);
            curl_close($c);


        //  $splaces = SavedPlace::where('pid','=',$id)->update(['Address'=> $request->Address]);
        
            return new JsonResponse([
                'success' => true,
                'message' => 'Place Updated Successfully',
                'status' => 200
                ],200);
        }
        else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                'status' => 403
                ],403);
        }
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy(Request $request,$id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $GetUserType=User::where('id','=',$userId)->select('userType')->first();
        $userType=$GetUserType->userType;  
        if($userType==3){
            $toBeRemoved=$id;
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
            for($i = 0; $i < 4; $i++) {
                $randomStringNum .= $charactersNum[rand(0, $charactersNumLength - 1)];
            }
            $randomStringChar2=''.$randomStringChar.''.$randomStringNum.'';
            //we are not going to delete it from DB but void the reference user_id/device_id
            Place::where('uCode','=',$toBeRemoved)->where('user_id','=',$userId)->update(['device_ID' => null,'uCode' => $randomStringChar2,'user_id' => null,'flag' => 0,'isDeleted'=>1]);
            //remove image
            // $imageGetHash = urlencode($removeHash);
            // //$str= "?Name=".$name_val."&Password=".$password_val."&Message=".$message_val;
            // $str= "/".$imageGetHash;
            // $client_id = '55c393c2e121b9f'; 
            // $url = 'https://api.imgur.com/3/image'.$str;
            // $headers = array("Authorization: Client-ID $client_id");

            // $curl = curl_init();
            // curl_setopt_array($curl, array(
            //    CURLOPT_URL=> $url,
            //    CURLOPT_TIMEOUT => 30,
            //    CURLOPT_RETURNTRANSFER => 1,
            //    CURLOPT_CUSTOMREQUEST => "DELETE",
            //    CURLOPT_HTTPHEADER => $headers
            // ));
            // $json_returned = curl_exec($curl); // blank response
            // $json_a=json_decode($json_returned ,true);
            // Image::where('imageRemoveHash','=',$removeHash)->delete();
            // curl_close ($curl);

            return new JsonResponse([
                'success' => true,
                'message' => 'Place Deleted Successfully',
                'status' => 200
                ],200);
        }
        else{
            return new JsonResponse([
                'success' => false,
                'message' => 'User not authorised to Access this Resource',
                'status' => 403
                ],403);
        }
    }
}
