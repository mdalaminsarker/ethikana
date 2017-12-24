<?php

namespace App\Http\Controllers;

use DB;
use Illuminate\Http\Request;
use App\Place;
use App\User;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use App\Image;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;

class ImageController extends Controller
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
    public function store(Request $request){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $placeCode = $request->pid;
        $place=Place::where('uCode','=',$placeCode)->first();
        $placeId=$place->id;
        $relatedTo=$request->relatedTo;
        if(Place::where('uCode','=',$placeCode)->where('user_id','=',$userId)->exists()){
            $client_id = '55c393c2e121b9f';
            $url = 'https://api.imgur.com/3/image';
            $headers = array("Authorization: Client-ID $client_id");
            //source:
            //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
            //$recivedFiles = $request->file('images');
            $recivedFiles = $request->get('images');
            //$file_count = count($reciveFile);
            //start count how many uploaded
            $uploadcount = count($recivedFiles);
            //return $uploadcount;
            if($uploadcount>4){
                $message="Can not Upload more then 4 files";
            }
            else{
            foreach($recivedFiles as $file)
            {
                //$img = file_get_contents($file);
                //$imgarray  = array('image' => base64_encode($file),'title'=> $title);
                //$imgarray  = array('image' => base64_encode($img));
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
               // $imgur_upload="success";
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
                $success=true;
                $message='Image Uploaded Successfully';
            }
            User::where('id','=',$userId)->increment('total_points',5);
            //return $json_a;
            return new JsonResponse([
                'success'=> true,
                'message'=>$message,
                'image_url'=>$theImageLink,
                'status' => http_response_code()
              ]);
    }else{
        return new JsonResponse([
            'success'=> false,
            //'image_url'=>$theImageLink,
            'message'=>'Owner of the Image could not be verified',
            'status' => http_response_code()
          ]);
    }

  }


    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($pid)
    {

        $allImgForAPlace=Image::where("pid",'=',$pid)->first();
        DB::table('analytics')->increment('search_count');
        return new JsonResponse([
            // 'message'=>'image added successfully!',
            'result'=>$allImgForAPlace
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
    public function destroyImage(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        //
        // $imageGetHash     = urlencode($removeHash);
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
        //curl_close ($curl);
        //return $json_a;

        if(Place::where('uCode','=',$request->pid)->where('user_id','=',$userId)->exists()){
           $id = Place::where('uCode','=',$request->pid)->first();
           $pid = $id->id;
           Image::where('pid','=',$pid)->delete();
           User::where('id','=',$userId)->decrement('total_points',5);
            return new JsonResponse([
                'success'=>true,
                'message'=>'Image Deleted',
                'points_deleted'=>5
                //'result'=>$json_a
              ],200);
        }else{
            return new JsonResponse([
                'success'=> false,
                'message'=>'Delete Unsuccessful',
            ],403);
        }
    }
    public function destroyImages($place_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

        if(Image::where('pid','=',$place_id)->where('user_id','=',$userId)->exists()){
            Image::where('pid','=',$place_id)->update(['user_id' => null,'isDeleted' => 1]);
           // User::where('id','=',$userId)->decrement('total_points',5);
            return new JsonResponse([
                'success'=>true,
                'message'=>'image deleted.',
                //'points_deleted'=>5
            ],200);
        }else{
            return new JsonResponse([
                'success'=> flase,
                'message'=>'image could not be deleted.',
            ],403);
        }
        // $imageGetHash     = urlencode($removeHash);
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
        //curl_close ($curl);
        //return $json_a;

    }
}
