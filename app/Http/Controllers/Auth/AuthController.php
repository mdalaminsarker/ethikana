<?php

namespace App\Http\Controllers\Auth;
use Illuminate\Support\Facades\Hash;
use DB;
use Auth;
use Validator;
use App\User;
use App\Place;
use App\SavedPlace;
use App\Referral;
use App\analytics;
use App\Image;
use Bugsnag\BugsnagLaravel\Facades\Bugsnag;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;
use Illuminate\Support\Facades\Mail;


class AuthController extends Controller
{
  /**
  * Handle a login request to the application.
  *
  * @param \Illuminate\Http\Request $request
  *
  * @return \Illuminate\Http\Response
  */
//webhook adnan: https://hooks.slack.com/services/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
//webhook barikoi: https://hooks.slack.com/services/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

  public function Register(Request $request){
    //Bugsnag::notifyError('ErrorType', 'Test Error');
    $messages = [
      'name.required' => 'We need to know your name!',
      'email.required' => 'We need to know your email!',
      'email.unique'  => 'We think :attribute is already in use!',
      'email.email' => 'Please provide a valid email address',
      'password.required' => 'You need a password!',
      'password.min' => 'Please provide a minimum :min characters password',
      'phone.required' => 'We need to know your phone!',
      'phone.digits_between'=>'We are expecting 11 to 15 digits phone numeber',
      'phone.unique'  => 'We think :attribute is already in use!',
  //'size'    => 'The :attribute must be exactly :size.',
  //'between' => 'The :attribute must be between :min - :max.',
  //'in'      => 'The :attribute must be one of the following types: :values',
    ];

    $rules = [
      'name' => 'required',
      'email' => 'unique:users|required|email|max:255',
      'password' => 'required|min:6',
      'userType'=>'required',
      'phone' => 'required|unique:users|numeric|digits_between:10,15',
    ];
    $validator = Validator::make($request->all(), $rules,$messages);
    //$this->validate($request,$rules);
    if ($validator->fails()) {
            // return redirect('post/create')
            //             ->withErrors($validator)
            //             ->withInput();
      $messages = $validator->errors();
      Bugsnag::notifyError('ErrorType', 'Regiration Error');
      //$message   = $messages->all();
      //return $validator->messages();

    return new JsonResponse([
        'messages' => $validator->messages(),
        'status'=>400
      ],400);
      //return $validator->failed();
    }
    else{
      //Generate Referral Code
      $length = 6;
      $characters = '123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      $refCode = '';    
      for ($p = 0; $p < $length; $p++) {
          $refCode .= $characters[mt_rand(0, strlen($characters))];
      }
      //end of Ref_code gen.

      $user = new User;
      $user->name = $request->name;
      $user->email = $request->email;
      $user->password = app('hash')->make($request->password);
      $user->userType=$request->userType;

      if ($request->has('device_ID')) {
        $user->device_ID = $request->device_ID;
      }
      if ($request->has('phone')) {
        $user->phone=$request->phone;
      }
      $user->ref_code=$refCode;

      $user->save();
     //Slack Webhook : notify
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      //$getuserData=User::where('id','=',$userId)->select('name')->first();
      //$name=$getuserData->name;
      $message = array('payload' => json_encode(array('text' => "New User Registered,Name:".$request->name." , Email:".$request->email." ,Phone:".$request->phone."")));
      //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);

      //return response()->json('Welcome');
      return new JsonResponse([
          'messages'=> 'Welcome',
          'status' => 200
        ],200);
    }
    /*return new JsonResponse([
      'message' => $refCode 
    ]);*/
  }

  //Login Check
  public function postLogin(Request $request)
  {
    // try {
    //   $this->validatePostLoginRequest($request);
    // } catch (HttpResponseException $e) {
    //   return $this->onBadRequest();
    // }
    try {
    // Some potentially crashy code
      $this->validatePostLoginRequest($request);
    } catch (Exception $ex) {
        Bugsnag::notifyException($ex);
    }

    try {
      // Attempt to verify the credentials and create a token for the user
      if (!$token = JWTAuth::attempt(
        $this->getCredentials($request)
      )) {
        return $this->onUnauthorized();
      }
    } catch (Exception $ex) {
        Bugsnag::notifyException($ex);
    }

    // try {
    //   // Attempt to verify the credentials and create a token for the user
    //   if (!$token = JWTAuth::attempt(
    //     $this->getCredentials($request)
    //   )) {
    //     return $this->onUnauthorized();
    //   }
    // } catch (JWTException $e) {
    //   // Something went wrong whilst attempting to encode the token
    //   return $this->onJwtGenerationError();
    // }

    // All good so return the token
    return $this->onAuthorized($token);
  }

  public function postLoginAdmin(Request $request)
  {
    try {
      $this->validateAdminPostLoginRequest($request);
    } catch (HttpResponseException $e) {
      return $this->onBadRequest();
    }

    try {
      // Attempt to verify the credentials and create a token for the user
      if (!$token = JWTAuth::attempt(
        $this->getAdminCredentials($request)
      )) {
        return $this->onUnauthorized();
      }
    } catch (JWTException $e) {
      // Something went wrong whilst attempting to encode the token
      return $this->onJwtGenerationError();
    }

    // All good so return the token
    return $this->onAuthorized($token);
  }

  /**
  * Validate authentication request.
  *
  * @param  Request $request
  * @return void
  * @throws HttpResponseException
  */
  protected function validatePostLoginRequest(Request $request)
  {
    $this->validate($request, [
      'email' => 'required|email|max:255',
      'password' => 'required',
    ]);
  }

  protected function validateAdminPostLoginRequest(Request $request)
  {
    $this->validate($request, [
      'email' => 'required|email|max:255',
      'password' => 'required',
      'userType'=> 'required|in:1',
    ]);
  }

  /**
  * What response should be returned on bad request.
  *
  * @return JsonResponse
  */
  protected function onBadRequest()
  {
    return new JsonResponse([
      'message' => 'invalid_credentials'
    ], Response::HTTP_BAD_REQUEST);
  }

  /**
  * What response should be returned on invalid credentials.
  *
  * @return JsonResponse
  */
  protected function onUnauthorized()
  {
    return new JsonResponse([
      'message' => 'invalid_credentials'
    ], Response::HTTP_UNAUTHORIZED);
  }

  /**
  * What response should be returned on error while generate JWT.
  *
  * @return JsonResponse
  */
  protected function onJwtGenerationError()
  {
    return new JsonResponse([
      'message' => 'could_not_create_token'
    ], Response::HTTP_INTERNAL_SERVER_ERROR);
  }

  /**
  * What response should be returned on authorized.
  *
  * @return JsonResponse
  */
  protected function onAuthorized($token)
  {
    return new JsonResponse([
      'message' => 'token_generated',
      'data' => [
        'token' => $token,
      ]
    ],Response::HTTP_OK);
  }

  /**
  * Get the needed authorization credentials from the request.
  *
  * @param \Illuminate\Http\Request $request
  *
  * @return array
  */
  protected function getCredentials(Request $request)
  {
    return $request->only('email', 'password');
  }

  protected function getAdminCredentials(Request $request)
  {
    return $request->only(['email', 'password','userType']);
  }

  /**
  * Invalidate a token.
  *
  * @return \Illuminate\Http\Response
  */
  public function deleteInvalidate()
  {
    $token = JWTAuth::parseToken();

    $token->invalidate();

    return new JsonResponse(['message' => 'token_invalidated']);
  }

  /**
  * Refresh a token.
  *
  * @return \Illuminate\Http\Response
  */
  public function patchRefresh()
  {
    $token = JWTAuth::parseToken();

    $newToken = $token->refresh();

    return new JsonResponse([
      'message' => 'token_refreshed',
      'data' => [
        'token' => $newToken
      ]
    ]);
  }

  /**
  * Get authenticated user.
  *
  * @return \Illuminate\Http\Response
  */
  public function getUser()
  {
    return new JsonResponse([
      'message' => 'authenticated_user',
      'data' => JWTAuth::parseToken()->authenticate()
    ]);
  }
//search 
    public function AppKhujTheSearch($code)
    {
      if($token = JWTAuth::getToken()){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $getuserData=User::where('id','=',$userId)->select('name')->first();
        $name="'".$getuserData->name."'";
        //return $token;
      }
      else{
        $name='Someone';
        //return $name;
      }
      
      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);
      //$searched4Code=$code;
     // $this->Slacker($code);
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
  //Admin Routes;
  public function getUserList(){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
    $GetUserType=User::where('id','=',$userId)->select('userType')->first();
    $userType=$GetUserType->userType;  
    //return $userType;

    if($userType==1){
      $listUsers=User::get();
      $countUsers=count($listUsers);
      return new JsonResponse([
        'message' => 'User List Provided',
        'data' => [
          'user_count' => $countUsers,
          'list_users' => $listUsers,
        ]
      ]);
    }else{
      return new JsonResponse([
        'message' => 'User Not Permitted To See This Resources;',
      ]);
    }
  }


  //End Admin

  public function getPlacesByUserDeviceId($deviceId){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
   //update all places with this 'deviceId' ,where user_id is null -> update the user id to $userId;  
    $placesWithDvid=Place::where('device_ID','=',$deviceId)->where('user_id', null)->update(['user_id' => $userId]);
    //get the places with user id only
    $place = Place::where('user_id','=',$userId)->get();

    return $place->toJson();
    //return $deviceId;
  }

  public function getPlacesByUserId()
  {
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
 
    //get the places with user id only
    $place = Place::with('images')->where('user_id','=',$userId)->get();

    return $place->toJson();
    //return $deviceId;
  }

  public function resetPassword(Request $request){
    if ($request->has('email')) {
      # code...
      $findThisEmail=$request->email;
      if (User::where('email','=',$findThisEmail)->exists()) {
      $characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
      $charactersLength = strlen($characters);
      $randomStringChar = '';
      for ($i = 0; $i < 6; $i++) {
        $randomStringChar  .= $characters[rand(0, $charactersLength - 1)];
      }
      //we will be  sending the Rand. password as is to User mail
      //but, saving the hash version in DB
      $tempPass=app('hash')->make($randomStringChar);
      $updateTempPass=User::where('email','=',$request->email)->update(['password'=>$tempPass]);
//Simple String
   /*   Mail::raw('Some one requested a New Password for your BariKoi Account. Your Temporary Password(without quote):"'.$tempPass.'".Please update your password after logging in.', function($message) use($request){
        $message->from('barikoicode@gmail.com', 'BariKoi');
        $message->to($request->email)->subject('BariKoi Password Reset');
      });  */
      //Pass A View
      Mail::send('Email.resetpass', ['tempPass' => $randomStringChar], function($message) use($request)
      {
          $message->to($request->email)->subject('Password Reset!');
      });
      //Slack Webhook : notify
      define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
    // Make your message
      $getuserData=User::where('email','=',$findThisEmail)->select('name')->first();
      $name=$getuserData->name;
      $email=$findThisEmail;
      $message = array('payload' => json_encode(array('text' => "Password Reset,Requested by:".$name." , (".$email.")")));
      //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
    // Use curl to send your message
      $c = curl_init(SLACK_WEBHOOK);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_POST, true);
      curl_setopt($c, CURLOPT_POSTFIELDS, $message);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
      $res = curl_exec($c);
      curl_close($c);
      //return 'logged email via mailtrap.io...';
      return new JsonResponse([
        
          'message'=> 'We have sent a temporary password to: '.$request->email
          //'message'=> 'We have sent a temporary password to: '. $randomStringChar
        ]);
      }else{
        return new JsonResponse([
          'message' => 'Could not find any User with this Email!',
          ]);
      }      
    }
  }
  public function UpdatePass12(Request $request){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
    // get mail, to inform the user about password change

    $current_password =$request->oldPass;
    $password = app('hash')->make($request->newPass);

    //see if atleast one user exists with this id
    $user_count = DB::table('users')->where('id','=',$userId)->count();

    $getMail=User::where('id','=',$userId)->select('email')->first();
    $data = array( 'to' => $getMail['email']);

    if (Hash::check($current_password, $user->password) && $user_count == 1){
        User::where('id','=',$userId)->update(['password'=>$password]);
        Mail::send('Email.passupdate',$data, function($message) use ($data){
          $message->to($data['to'])->subject('Password Changed!');
        });
        //$this->deleteInvalidate();
        return new JsonResponse([
        'message' => 'Password changed successfully.',
        ]);
  
    }else{
      return new JsonResponse([
        'message'=>'Your current password dose not match our record.',
        ]);
    }
  }
  
  public function UpdatePass(Request $request){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
    $current_password =$request->oldPass;
    $password = app('hash')->make($request->newPass);
    // get mail, to inform the user about password change
    $getMail=User::where('id','=',$userId)->select('email')->first();
    $data = array( 'to' => $getMail['email']);
    $user_count = DB::table('users')->where('id','=',$userId)->count();

    if (Hash::check($current_password, $user->password) && $user_count == 1) {
        User::where('id','=',$userId)->update(['password'=>$password]);
        //$this->deleteInvalidate();
       /* Mail::send('Email.passchanged',$data, function($message) use ($data)
        {
          $message->to($data['to'])->subject('Password Changed!');
        });
        */
        return new JsonResponse([
        'message'=>'Password changed successfully.',
        ]);
    }
    else{
      return new JsonResponse([
        'message'=>'Your current password do not match our record.',
        ]);
    }
  }
  /*
public function changePasswordByUser(Request $request){
    $user = JWTAuth::parseToken()->authenticate();
    $userId = $user->id;
    // get mail, to inform the user about password change
    $getMail=User::where('id','=',$userId)->select('email')->first();
   // $oldPass=$request->oldPass;
    $newPass=$request->newPass;
    $newPassHashed=app('hash')->make($newPass);
    //Hash::check($data['old_password'], $user->password)
   // $temp_pass=User::where('id','=',$userId)->select('password')->first();
    //$hashedOldPass=app('hash')->make($request->oldPass);

    //Hash class not working, work on it later
    if(\Hash::check($oldPass,$temp_pass)){
      //do the password change
      $doThePassChange=User::where('id','=',$userId)->update(['password'=>$newPassHashed]);
      Mail::send('Email.passchanged', [], function($message) use ($getMail)
      {
          $message->to($getMail)->subject('Password Changed!');
      });
    return new JsonResponse([
      'message' => 'Password Changed',
      ]);
    }
    if(User::where('id','=',$userId)->update(['password'=>$newPassHashed])){
      Mail::send('Email.passchanged', [], function($message) use ($getMail)
      {
          $message->to($getMail)->subject('Password Changed!');
      });
    return new JsonResponse([
      'message' => 'Password Changed',
      ]);
    }
    else{
    return new JsonResponse([
      'message' => 'Could not change password.',
      ]);
    }
  }
  */

    //Add New Place
          /*
      $lat = $request->latitude;
      $lon = $request->longitude;
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->having('distance','<',0.02) //20 meter
           ->where('flag','=',1)
           ->get();
      */    
    public function authAddNewPlace(Request $request){

      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      //char part
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
      //check if it is private and less then 10 meter
      if($request->flag==0){
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('user_id','=',$userId) // same user can not add
           ->having('distance','<',0.005) //another private place in 5 meter
           ->get();
       $message='Can not Add Another Private Place in 10 meter';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){
        
        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.005) //no one 5 meter for public
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
      	if($request->has('device_ID')) {
          	$input->device_ID = $request->device_ID;
      	}

        //ADN:when authenticated , user_id from client will be passed on this var. 
        $input->user_id =$userId;

        if ($request->has('email')){
          $input->email = $request->email;
        }
        if ($request->has('route_description')){
          $input->route_description = $request->route_description;
        }
        //$img1=empty($request->input('images'));
        // if ($request->hasFile('images')) {
        //     dd('write code here');
        // }
        $input->uCode = $ucode;
        $input->isRewarded = 1;    
        $input->save();
        //$placeId=$input->id;
        //if image is there, in post request
        $message1='no image file attached.';
        $imgflag=0;
        
        //handle image
        //user will get 5 points if uploads images
        $img_point=0; //inititate points for image upload
        
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
	        //$file_count = count($reciveFile);
	      // start count how many uploaded
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
            $img_point=5;
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
        // 
        User::where('id','=',$userId)->increment('total_points',5+$img_point);
        $getTheNewTotal=User::where('id','=',$userId)->select('total_points')->first();

        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);

        //everything went weel, user gets add place points, return code and the point he recived
        return response()->json([
          'uCode' => $ucode,
          'img_flag' => $imgflag,
          'new_total_points'=>$getTheNewTotal->total_points,
          'points'=>5+$img_point,
          'image_uplod_messages'=>$message1
         // 'place'=>$placeId
          ]);
      }
      else{
        //can't add places in 20/50 mter, return a message
        return response()->json([
          'message' => $message
          ]);
      }
    }

    //*******ADD PLACE with CUSTOM CODE************************
    //Add new place with custom code
    public function authAddCustomPlace(Request $request)
    {
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      $lat = $request->latitude;
      $lon = $request->longitude;
      //check if it is private and less then 20 meter
      if($request->flag==0){
      
      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',0)
           ->where('user_id','=',$userId)
           ->having('distance','<',0.001) //10 meter for private
           ->get();
       $message='Can not Add Another Private Place in 1 meter';
      }
      //check if it is public and less then 50 meter
      if($request->flag==1){
        
        $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          //->where('pType', '=','Food')
           ->where('flag','=',1)
           ->having('distance','<',0.001) //5 meter for public
           ->get();
        $message='A Public Place is Available in 1 meter';
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
        $input->user_id =$userId;

        if ($request->has('email')){
          $input->email = $request->email;
        }
        if ($request->has('route_description')){
          $input->route_description = $request->route_description;
        }
        
        $input->uCode = $request->uCode;   
        $input->isRewarded = 1;   
        $input->save();
		
		//$placeId=$input->id;
        //if image is there, in post request
        $message1='no image file attached.';
        $imgflag=0;//is uploded? initialize
        
        //handle image
        //user will get 5 points if uploads images
        $img_point=0; //inititate points for image upload
        
        if ($request->hasFile('images'))
        {

	        $placeId=$input->id; //get latest the places id
	        $relatedTo=$request->relatedTo;
	        $client_id = '55c393c2e121b9f';
	        $url = 'https://api.imgur.com/3/image';
	        $headers = array("Authorization: Client-ID $client_id");
	        //source:
	        //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
	        $recivedFiles = $request->file('images');
	        //$file_count = count($reciveFile);
	      // start count how many uploaded
	        $uploadcount = count($recivedFiles);
	        //return $uploadcount;
	        if($uploadcount>4){
	            $message1="Can not Upload more then 4 files";
	            $imgflag=0;//not uploaded
	        }
	        else{
	          foreach($recivedFiles as $file)
	          {
	              $img = file_get_contents($file);
	              //$imgarray  = array('image' => base64_encode($file),'title'=> $title);
	              $imgarray  = array('image' => base64_encode($img));
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
            $img_point=5;
          }//else end
        } //if reuest has image
        
        User::where('id','=',$userId)->increment('total_points',5+$img_point);
        $getTheNewTotal=User::where('id','=',$userId)->select('total_points')->first();

       //Slack Webhook : notify
        define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      // Make your message
        $getuserData=User::where('id','=',$userId)->select('name')->first();
        $name=$getuserData->name;
        $message = array('payload' => json_encode(array('text' => " ".$name." Added a Place with Code:".$request->uCode. "")));
        //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
      	// Use curl to send your message
        $c = curl_init(SLACK_WEBHOOK);
        curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
        $res = curl_exec($c);
        curl_close($c);
		//Webhook ends
        DB::table('analytics')->increment('code_count');
        //return response()->json($ucode);
        return response()->json([
          'uCode' => $request->uCode,
          'points'=>5+$img_point,
          'new_total_points'=>$getTheNewTotal->total_points,
		  'img_flag' => $imgflag,
          'image_uplod_messages'=>$message1,
          ]);
      } //count===0
      else{
        return response()->json([
          'message' => $message
          ]);
      }

    }

    //Update My Place
    public function halnagadMyPlace(Request $request,$id){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
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
        $places->flag = $request->flag;
        if ($request->has('pType')) {
            $places->pType = $request->pType;
        }
        if ($request->has('subType')) {
            $places->subType = $request->subType;
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
    
        return response()->json('updated');
    }



    //Delete place from MyPlaces/"Places" table
    public function mucheFeliMyPlace(Request $request,$bariCode){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $toBeRemoved=$bariCode;
       // $getPid=Place::where('uCode','=',$toBeRemoved)->first();    
      //  $pid=$getPid->id;
       // $toDeleteSavedPlacesTable =SavedPlace::where('pid','=',$pid)->where('user_id','=',$userId)->delete();

        $isThisPlaceRewarded=Place::where('uCode','=',$toBeRemoved)->where('user_id','=',$userId)->where('isRewarded','=',1)->first();
        if(count($isThisPlaceRewarded)!=0){
        //   $charactersChar1 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        //   $charactersCharLength1 = strlen($charactersChar1);
        //   $randomStringChar1 = '';
        //   for ($i = 0; $i < 5; $i++) {
        //       $randomStringChar1 .= $charactersChar1[rand(0, $charactersCharLength1 - 1)];
        //   }

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
          $randomStringChar1=''.$randomStringChar.''.$randomStringNum.'';
          //we are not going to delete it from DB but void the reference user_id/device_id
          Place::where('uCode','=',$toBeRemoved)->where('user_id','=',$userId)->update(['device_ID' => null,'uCode' => $randomStringChar1,'user_id' => null,'flag' => 0,'isDeleted'=>1]);
          //deduct points
          User::where('id','=',$userId)->decrement('total_points',5);
          return response()->json('Place Deleted! You Lost 5 Points!!');
        }else{
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
          $randomStringChar2=''.$randomStringChar.''.$randomStringNum.'';
          //we are not going to delete it from DB but void the reference user_id/device_id
          Place::where('uCode','=',$toBeRemoved)->where('user_id','=',$userId)->update(['device_ID' => null,'uCode' => $randomStringChar2,'user_id' => null,'flag' => 0,'isDeleted'=>1]);
          return response()->json('Place Deleted!');
        }
    }

    // get all saved places for a userId
    public function getSavedPlacesByUserId()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $savedPlaces=DB::table('places')
                  ->join('saved_places', function ($join)
                    {$join->on('places.id', '=', 'saved_places.pid');})
                  ->where('saved_places.user_id','=',$userId)
                  ->get();
         return $savedPlaces->toJson();
    }
    //Add Favorite Place
    public function authAddFavoritePlace(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $saved = new SavedPlace;
        $saved->user_id = $userId; //user who is adding a place to his/her favorite
        $code = $request->barikoicode; // place is
        $getPid=Place::where('uCode','=',$code)->first();    
        $pid=$getPid->id;
        $saved->pid=$pid;
        //return $pid;
        $saved->save();
        DB::table('analytics')->increment('saved_count');
        return response()->json('saved');
    }
    // Delete a place from favorite
    public function authDeleteFavoritePlace(Request $request,$bariCode)
    {
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $toBeDeleted=$bariCode;
        $findThePid=Place::where('uCode','=',$toBeDeleted)->first();
        $toDelete = SavedPlace::where('pid','=',$findThePid->id)->where('user_id','=',$userId)->delete();
        return response()->json('Done');
        //return $toDelete;
    }
    //generate ref code for users dosen't have the code already
    public function authRefCodeGen(){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        //Generate Referral Code
       
        $userInfo=User::where('id','=',$userId)->select('ref_code','isReferred')->first();
        $isRef_code=$userInfo->ref_code;
      //  return $isRef_code;
        if ($isRef_code==NULL) {
          $length = 6;
          //exclude 0 & O;
          $characters = '123456789ABCDEFGHIJKLMNPQRSTUVWXYZ';
          $refCode = '';    
          for ($p = 0; $p < $length; $p++) {
              $refCode .= $characters[mt_rand(0, strlen($characters))];
          }
          User::where('id','=',$userId)->where('ref_code','=',null)->update(['ref_code'=>$refCode]);
            return new JsonResponse([
              'message'=>'Your Referral Code:'.$refCode
              ]);
            # code...
        }
        else{
          return new JsonResponse([
            'message'=>'Your Referral Code:'.$isRef_code
            ]);
        }
    }

    //Redeem Referral Code
    public function authRedeemRefCode(Request $request){
        $user = JWTAuth::parseToken()->authenticate();
        $userId = $user->id;
        $refCode=$request->ref_code;
        $rewardPoints=25;
        if(User::where('ref_code','=',$refCode)->exists()){
          if(User::where('id','=',$userId)->where('ref_code','=',$refCode)->exists()){
            $message="Own Referral Code Can not be Redeemed";
            $rewardPoints=0;
            //return response()->json('Own Referral Code Can not be Redeemed');
            return new JsonResponse([
                'message'=> $message,
                'points' => $rewardPoints
              ]);
          }else{
            //return response()->json('Lets Check,More!');
            $refStat=User::where('id','=',$userId)->select('isReferred')->first();
            //$refStatus=$refStat->pluck('isReferred');
            $refStatus=$refStat->isReferred;
            print $refStatus;
            //return $refStatus;
            // if($refStatus==1){
            //   return new JsonResponse([
            //     'message'=>'Can Not Redeem more than One Invite Referral Code'
            //     ]);
            // }else{
            //   $referral=new Referral;
            //   //need to know the Ref_Code owner
            //   $referrer=User::where('ref_code','=',$refCode)->select('id')->first();
            //   $referrerId=$referrer->id;

            //   $referral->ref_code_referrer=$referrerId;
            //   $referral->ref_code_redeemer=$userId;
            //   $referral->save();
            //   //give the Redemmer 50 points;
            //   User::where('id','=',$userId)->increment('total_points',$rewardPoints);
            //   //give the Eeferrer 50 points as well;
            //   User::where('id','=',$referrerId)->increment('total_points',$rewardPoints);
            //   //Update the isRferred flag for the Redemmer in User Table
            //   User::where('id','=',$userId)->update(['isReferred'=>1]);
              
            //   $Redeemer=User::where('id','=',$userId)->select('name')->first();
            //   $InviterMail=User::where('id','=',$referrerId)->select('name','email')->first();
            //   $data = array( 'to' => $InviterMail['email'],'redeemer' => $Redeemer['name'],'points' => $rewardPoints);
                           
            //                //Slack Webhook : notify
            //   define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
            // // Make your message
            //   //$getuserData=User::where('id','=',$userId)->select('name')->first();
            //   //$name=$getuserData->name;
            //   $message = array('payload' => json_encode(array('text' => "'".$Redeemer->name."'(user id:".$userId.")-Redeemed ".$InviterMail->name."'s Invite Code (user id:".$referrerId.").")));
            //   //$message = array('payload' => json_encode(array('text' => "New Message from".$name.",".$email.", Message: ".$Messsage. "")));
            // // Use curl to send your message
            //   $c = curl_init(SLACK_WEBHOOK);
            //   curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
            //   curl_setopt($c, CURLOPT_POST, true);
            //   curl_setopt($c, CURLOPT_POSTFIELDS, $message);
            //   curl_setopt($c, CURLOPT_RETURNTRANSFER, TRUE);
            //   $res = curl_exec($c);
            //   curl_close($c);

            //   //Mail
            //   Mail::send('Email.redeemed',$data, function($message) use ($data){
            //     $message->to($data['to'])->subject('Wow! You have earned Barikoi Invite Points.');

            //   });
            //   return new JsonResponse([
            //     'message'=>'Awesome! You have recieved '.$rewardPoints.' points',
            //     'points'=>$rewardPoints
            //     ]);
            // }
          }
        }else{
          return response()->json('Invalid Referral Code');
        }
    }

    public function analytics()
    {
      $user = JWTAuth::parseToken()->authenticate();
      $userId = $user->id;
      $getUserType=User::where('id','=',$userId)->select('userType')->first();
      $thisUserType=$getUserType->userType;
      if($thisUserType==1){
        $numbers=analytics::all();
        return $numbers->toJson();
      }else{
        return response()->json('This User is not Allowed To Access This Resource');
      }
    }

}