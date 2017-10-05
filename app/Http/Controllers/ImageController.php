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
use App\PoolPhoto;
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
        $placeId = $request->pid;
        $relatedTo=$request->relatedTo;

        $client_id = '55c393c2e121b9f';
        $url = 'https://api.imgur.com/3/image';
        $headers = array("Authorization: Client-ID $client_id");
        //source:
        //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
        //$recivedFiles = $request->file('images');
        $recivedFiles = $request->get('images');
        //$file_count = count($reciveFile);
      // start count how many uploaded
        $uploadcount = count($recivedFiles);
        //return $uploadcount;
        if($uploadcount>4){
            $message="Can not Upload more then 4 files";
        }
        else{
        foreach($recivedFiles as $file)
        {
           // $img = file_get_contents($file);
            //$imgarray  = array('image' => base64_encode($file),'title'=> $title);
           // $imgarray  = array('image' => base64_encode($img));

            $imgarray  = array('image' => $file); //images as base64 string
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
            //$saveImage->isShowable=1;
            $saveImage->relatedTo=$relatedTo;
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
  //Pool: Any Photo ID
   public function storePhotoID(Request $request)
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
                $saveImage=new PoolPhoto;
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
    public function show($pid)
    {
        //
        // $imageGetHash     = urlencode($HashedID);
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
        //    CURLOPT_HTTPHEADER => $headers
        // ));
        // $json_returned = curl_exec($curl); // blank response
        // $json_a=json_decode($json_returned ,true);
        // curl_close ($curl);
        //return $json_a;
        DB::table('analytics')->increment('search_count',1);
        $allImgForAPlace=Image::where("pid",'=',$pid)->get();
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
    public function destroyImage($removeHash)
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
        if(Image::where('pid','=',$place_id)->where('user_id','=',$userId)->exists()){
            Image::where('imageRemoveHash','=',$removeHash)->update(['user_id' => null,'isDeleted' => 1]);;
            return new JsonResponse([
                'message'=>'image deleted.',
                //'result'=>$json_a
              ]);
        }else{
            return new JsonResponse([
                'success'=> flase,
                'message'=>'image could not be deleted.',
            ],403);
        }
    }
    public function destroyImages($place_id)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;

        if(Image::where('pid','=',$place_id)->where('user_id','=',$userId)->exists()){
            Image::where('pid','=',$place_id)->update(['user_id' => null,'isDeleted' => 1]);
            return new JsonResponse([
                'success'=>true,
                'message'=>'image deleted.',
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
