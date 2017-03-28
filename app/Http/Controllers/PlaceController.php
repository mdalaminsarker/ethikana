<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Place;
use App\User;
use App\PlaceType;
use App\PlaceSubType;
use App\analytics;
use App\SavedPlace;
use Illuminate\Http\JsonResponse;
use DB;

class PlaceController extends Controller
{
    //

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
      $input = new Place;
      $input->longitude = $request->longitude;
      $input->latitude = $request->latitude;
      $input->Address = $request->Address;
      $input->city = $request->city;
      $input->area = $request->area;
      $input->postCode = $request->postCode;
      $input->pType = $request->pType;
      $input->subType = $request->subType;

      if ($request->has('flag')) {
          $input->flag = $request->flag;
          // check the value of the flag and decide if its public or private
          if ($request->flag==1) {
            DB::table('analytics')->increment('public_count');
          }else {
            DB::table('analytics')->increment('private_count');
          }
      }
      if ($request->has('device_ID')) {
        $input->device_ID = $request->device_ID;
      }
      if ($request->has('email')) {
        $input->email = $request->email;
      }
      $input->uCode = $ucode;
      $input->save();
      DB::table('analytics')->increment('code_count');

      return response()->json($ucode);
    }
    //Store Custom Place
    public function StoreCustomPlace(Request $request)
    {
      $input = new Place;
      $input->longitude = $request->longitude;
      $input->latitude = $request->latitude;
      $input->Address = $request->Address;
      $input->city = $request->city;
      $input->area = $request->area;
      $input->postCode = $request->postCode;
      $input->pType = $request->pType;
      $input->subType = $request->subType;
      if ($request->has('flag')) {
        // check the value of the flag and decide if its public or private
          $input->flag = $request->flag;
          if ($request->flag===1) {
            DB::table('analytics')->increment('public_count');
          }else {
            DB::table('analytics')->increment('private_count');
          }

      }
      if ($request->has('device_ID')) {
        $input->device_ID = $request->device_ID;
      }
      if ($request->has('email')) {
        $input->email = $request->email;
      }
      $input->uCode = $request->uCode;
      $input->save();

      DB::table('analytics')->increment('code_count');

      return response()->json('Done');
    }
    //search address using code
    public function KhujTheSearch($code)
    {
      // Create a constant to store your Slack URL
        /*define('SLACK_WEBHOOK', 'https://hooks.slack.com/services/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');
      // Make your message
        $message = array('payload' => json_encode(array('text' => "Someone searched an address")));
      // Use curl to send your message
        $c = curl_init(SLACK_WEBHOOK);
        curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($c, CURLOPT_POST, true);
        curl_setopt($c, CURLOPT_POSTFIELDS, $message);
        curl_exec($c);
        curl_close($c);*/

      $place = Place::where('uCode','=',$code)->first();
      DB::table('analytics')->increment('search_count',1);
      return $place->toJson();
  /*  $lon = $place->longitude;
      $lat = $place->latitude;
      $Address = $place->Address;


*/
    }

    //search with device ID
    public function KhujTheSearchApp($id)
    {

      $place = Place::where('device_ID','=',$id)->get();
    /*  $lon = $place->longitude;
        $lat = $place->latitude;
        $Address = $place->Address;
    */
      return $place->toJson();
      /*response()->json([
        'lon' => $lon,
        'lat' => $lat,
        'address' => $Address
      ]);*/
    }
    // fetch all data

    public function shobai()
    {
      $places = Place::all();
      return $places->toJson();
    }
    //delete
    public function mucheFeli($code)
    {
      $places = Place::where('uCode','=',$code)->first();
      $places->delete();



      return response()->json('Done');
    }

    //update
    public function halnagad(Request $request,$code){
      $places = Place::where('uCode','=',$code)->first();
      if ($request->has('longitude')) {
        $places->longitude = $request->longitude;
      }
      if ($request->has('latitude')) {
        $places->latitude = $request->latitude;
      }
      $places->Address = $request->Address;
      $places->city = $request->city;
      $places->area = $request->area;
      $places->postCode = $request->postCode;
      $places->flag = $request->flag;
      $places->save();
      //Update the saved places database
      $splaces = SavedPlace::where('uCode','=',$code)->update(['Address'=> $request->Address]);




      return response()->json('updated');
    }

    // Add place type
    public function placeType(Request $request)
    {
      $type = new PlaceType;
      $type->type = $request->type;
      $type->save();

      return response()->json('Done');
    }
// Add place subtype
    public function placeSubType(Request $request)
    {
      $type = new PlaceSubType;
      $type->type = $request->type;
      $type->subtype = $request->subtype;
      $type->save();
      return response()->json('Done');
    }
    // Get place type
    public function getPlaceType()
    {
      $type = PlaceType::all();

      return $type->toJson();
    }
    //Get place subtype by type
    public function getPlaceSubType($type)
    {
      $subtype = placeSubType::where('type','=',$type)->get();
      $subtype = $subtype->subtype;
      return response()->json($subtype);
    }
    // Search places by name
    public function search($name)
    {
      $result = Place::where('Address','like','%'.$name.'%')->get();

      return $result->toJson();
    }
    // Get nearby places of a code
    public function ashpash($ucode)
    {
      $places = Place::where('uCode','=',$ucode)->first();
      $lat = $places->latitude;
      $lon = $places->longitude;
      // public place 1 private 0
      //$results = DB::select(DB::raw('SELECT id, ( 3959 * acos( cos( radians('. $lat .') ) * cos( radians( lat ) ) * cos( radians( lng ) - radians(' . $lon . ') ) + sin( radians(' . $lat .') ) * sin( radians(lat) ) ) ) AS distance FROM articles HAVING distance < ' . $distance . ' ORDER BY distance') );

     $result = DB::table('places')
          ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
          ->where('flag','=',1)//public place is 1
          //->where('type', '=',$type)
          ->having('distance','<',25)
          ->orderBy('distance')
          ->limit(5)
          ->get();


      return $result->toJson();
    }
    // get nearby places from current location
    public function amarashpash(Request $request)
    {
      $lat = $request->latitude;
      $lon = $request->longitude;

      $result = DB::table('places')
           ->select(DB::raw('*, ((ACOS(SIN('.$lat.' * PI() / 180) * SIN(latitude * PI() / 180) + COS('.$lat.' * PI() / 180) * COS(latitude * PI() / 180) * COS(('.$lon.' - longitude) * PI() / 180)) * 180 / PI()) * 60 * 1.1515 * 1.609344) as distance'))
           ->where('flag','=',1)//public place is 1 in the database
           //->where('type', '=',$type)
           ->having('distance','<',25)
           ->orderBy('distance')
           ->limit(5)
           ->get();

      return $result->toJson();

    }
    // get all analytics information
    public function analytics()
    {
      $numbers=analytics::all();
      return $numbers->toJson();
    }
    // Save places
    public function savedPlaces(Request $request)
    {
      $saved = new SavedPlace;
      $saved->uCode= $request->uCode;
      $saved->device_ID= $request->device_ID;
      $saved->email= $request->email;
      $saved->Address= $request->Address;
      $saved->save();
      DB::table('analytics')->increment('saved_count');

      return response()->json('saved');

    }
    public function getSavedPlace($deviceID)
    {
      $place= DB::table('places')
            //->join('saved_places', 'places.uCode', '=', 'saved_places.uCode')
            ->select('places.*')
            ->where('device_ID','=',$deviceID)
            ->get();


      return $place->toJson();

    }
    public function DeleteSavedPlace(Request $request, $code)
    {

      $places = DB::table('saved_places')->where('uCode','=',$code)->where('device_ID','=', $request->device_ID)->delete();


      return response()->json('Done');
    }

    public function count()
    {
      $place = Place::all()->count()-get();

      return $place->toJson();
    }
    public function updateCustomCode(Request $request, $uCode)
    {
      $splaces = Place::where('uCode','=',$uCode)->update(['uCode'=> $request->uCode]);
      return response()->json('updated');
    }


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
