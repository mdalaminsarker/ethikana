<?php

namespace App\Http\Controllers;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Place;
use App\User;
use App\Token;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use Illuminate\Http\JsonResponse;
use DB;

use Auth;

use Illuminate\Support\Facades\Hash;


class BusinessApiController extends Controller
{
    public function RegisterBusinessUser(Request $request){

       $this->validate($request, [
           'name' => 'required',
           'email' => 'required|email|max:255',
           'password' => 'required|min:6',
           'userType'=>'required',
       ]);

       $user = new User;
       $user->name = $request->name;
       $user->email = $request->email;
       $user->password = app('hash')->make($request->password);
      // $hashed_random_password = Hash::make(str_random(8));
       //$user->password =$hashed_random_password;
       $user->userType=$request->userType; //1=admin,2=users,3=business
       $user->save();


     //  return response()->json('Welcome');
       return new JsonResponse([
            'message' => 'Welcome'
        ]);
	}
    /*
	public function generateApiKey($length = 10) {

      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      $charactersLength = strlen($characters);
      $apiKey = '';
      for ($i = 0; $i < $length; $i++) {
        $apiKey .= $characters[rand(0, $charactersLength - 1)];
      }
      return ''.$user_id.':'.$apiKey.'';;
    }
	*//*
	public function generateApiKey(Request $request, $length = 10) {

      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      $charactersLength = strlen($characters);
      $apiKey = '';
      for ($i = 0; $i < $length; $i++) {
        $apiKey .= $characters[rand(0, $charactersLength - 1)];
      }
      return ''.$user_id.':'.$apiKey.'';
    }
    */

    public function generateApiKey(Request $request,$length=10) {

  
       // $places->longitude = $request->longitude;
      	$bEmail=$request->email;
        $isUser = User::where('email','=',$bEmail)->where('userType',3)->first();
        if(is_null($isUser)){
        	return new JsonResponse([
            	'message' => 'Could not find any User with this email'
        	]);
        }
        else{

          $bUid=$isUser->id; //Get The User ID

        	//if there is any previous active for this userId , revoke them
        	$prvsKeys=Token::where('user_id','=',$bUid)->where('isActive',1)->update(['isActive' => 0]);
        	
        	//start generating Key: 
          $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      		$charactersLength = strlen($characters);
     		  $apiKey = '';
	      	for ($i = 0; $i < $length; $i++) {
	        	$apiKey .= $characters[rand(0, $charactersLength - 1)];
          }
	     	  $toEncode= $bUid.':'.$apiKey;
	     	//$toEncode=$apiKey;
      		//return $toEncode= $bUid.':'.$apiKey;
      	//	return $toEncode;
        //	return base64_encode($toEncode);
        /*	return new JsonResponse([
            	'withOutBase64' => $toEncode,
            	'base64'=>base64_encode($toEncode),
    
        	]);*/

        	$newApiKey=new Token;
        	$newApiKey->user_id=$bUid;
        	$newApiKey->key=base64_encode($toEncode); //in future we won't keep any key in our DB 
        	$newApiKey->randomSecret=$apiKey;
        	$newApiKey->isActive=1;

        	$newApiKey->save();// Save The New KEY for this User ID
        	
        	return new JsonResponse([
            	'message' => 'Key Generated!',
            	'data' => [
            		'user_id'=> $bUid,
                	'key'=>base64_encode($toEncode),
                	//'key'=>$toEncode,
            	]
        	]);
        	
        }
      
    }
  //PBDYI2LC4O
  public function addPlaceByBusinessUser(Request $request,$apikey)
	{
	   /* $credentials = base64_decode(
	        Str::substr($request->header('Authorization'),6)
	    );*/
	   //return $credentials;
     $key = base64_decode($apikey);
	   $bIdAndKey = explode(':', $key);
	   $bUser=$bIdAndKey[0];
	   $bKey=$bIdAndKey[1];
     if(Token::where('user_id','=',$bUser)->where('randomSecret','=',$bKey)->where('isActive',1)->exists()){
      //return "Valid";
      
      //Random Code_character part
      $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $charactersLength = strlen($characters);
      $randomStringChar = '';
      for ($i = 0; $i < 4; $i++) {
        $randomStringChar  .= $characters[rand(0, $charactersLength - 1)];
      }
      //Random Code_digit part
      $characters = '0123456789';
      $charactersLength = strlen($characters);
      $randomStringDig = '';
      for ($i = 0; $i < 4; $i++) {
        $randomStringDig .= $characters[rand(0, $charactersLength - 1)];
      }
      $ucode =  ''.$randomStringChar.''.$randomStringDig.'';
      
//Start Storing/Adding Process
      $input = new Place;
      
      $input->longitude = $request->longitude;
      $input->latitude = $request->latitude;
      $input->Address = $request->Address;
      $input->city = $request->city;
      $input->area = $request->area;
      $input->postCode = $request->postCode;
      $input->pType = $request->pType;
      $input->subType = $request->subType;  
      $input->user_id =$bUser;
      //longitude,latitude,Address,city,area,postCode,pType,subType,flag,device_ID,user_id,email
/*      if($request->has('flag')) 
      {
        $input->flag = $request->flag;
        if ($request->flag==1) {
          DB::table('analytics')->increment('public_count');
        }else{
          DB::table('analytics')->increment('private_count');
        }
      }*/
      $request->flag=1;

      if ($request->has('device_ID')) {
        $input->device_ID = $request->device_ID;
      }

      if ($request->has('email')) {
        $input->email = $request->email;
      }
      
      $input->uCode = $ucode;      
      $input->save();
      
      DB::table('analytics')->increment('code_count');
      DB::table('analytics')->increment('business_code_count');
      return response()->json($ucode);
     }
     else{
      return new JsonResponse([
              'message' => 'Invalid or No Regsitered Key',
          ]);
     }
     //  return $key;
   /*  return new JsonResponse([
      'User_ID' => $bUser,
      'KEY' =>$bKey,
    ]);*/
	}

  public function searchPlaceByBusinessUser($apikey, $code){
     $key = base64_decode($apikey);
     $bIdAndKey = explode(':', $key);
     $bUser=$bIdAndKey[0];
     $bKey=$bIdAndKey[1];

     if (Token::where('user_id','=',$bUser)->where('randomSecret','=',$bKey)->where('isActive',1)->exists()) {
       # code...
      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('business_search_count',1);
      return $place->toJson();
     }
     else{
            return new JsonResponse([
              'message' => 'Invalid or No Regsitered Key',
          ]);
     }
  }

  public function PlacesAddedByBusinessUser($apikey){
     $key = base64_decode($apikey);
     $bIdAndKey = explode(':', $key);
     $bUser=$bIdAndKey[0];
     $bKey=$bIdAndKey[1];

     if (Token::where('user_id','=',$bUser)->where('randomSecret','=',$bKey)->where('isActive',1)->exists()) {
       # code...
      $place = Place::where('user_id','=',$bUser)->orderBy('id','desc')->get();
      //DB::table('analytics')->increment('business_search_count',1);
      return $place->toJson();
     }
     else{
            return new JsonResponse([
              'message' => 'Invalid or No Regsitered Key',
          ]);
     }
  }

  public function UpdatePlaceByBusinessUser($apikey,$id){
     $key = base64_decode($apikey);
     $bIdAndKey = explode(':', $key);
     $bUser=$bIdAndKey[0];
     $bKey=$bIdAndKey[1];

     if (Token::where('user_id','=',$bUser)->where('randomSecret','=',$bKey)->where('isActive',1)->exists()) {
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
        $places->user_id = $bUser; 
        $places->postCode = $request->postCode;
        $places->flag = 1;
        $places->save();
    //  $splaces = SavedPlace::where('pid','=',$id)->update(['Address'=> $request->Address]);
    
        return response()->json('updated');
     }
     else{
            return new JsonResponse([
              'message' => 'Invalid or No Regsitered Key',
          ]);
     }
  }

  public function getCurrentActiveKey(){
    
  }

}

