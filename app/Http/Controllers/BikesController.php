<?php namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Carbon\Carbon;
use App\Bike;

class BikesController extends Controller {

    //const MODEL = "App\Bike";

  //  use RESTActions;

    public function add(Request $request)
    {
      if ($request->user()->userType === 1) {
        $today = Carbon::today();
        $nextMonth = Carbon::today()->addMonth();
        $bikepic = $this->uploadImage($request->bike_image_link);
        $papers = $this->uploadImage($request->paper_image_link);
        $request->user()->bikes()->create([
         'model_name' => $request->model_name,
         'model_year' => $request->model_year,
         'engine_capacity' => $request->engine_capacity,
         'registration_number' => $request->registration_number,
        // 'user_id'=> $request->user()->id,
         'engine_number'=>$request->engine_number,
         'chassis_number'=> $request->chassis_number,
         'bike_image_link'=> $bikepic,
         'paper_image_link'=> $papers,
         'last_serviced'=> $today,
         'next_service'=> $nextMonth,
         'hourly_rent' => $request->hourly_rent,
         'daily_rent' => $request->daily_rent,
       ]);

        return response()->json(['Message' => 'Added Successfully']);
      }else {
        return response()->json(['Message' => 'Unauthorised']);
      }

  }
    public function all()
    {
      $today = Carbon::today();
      $all = Bike::all();
      return $all->toJson();

    }
    public function get($id)
    {
      $bike = Bike::findOrFail($id);
      return response()->json($bike);
    }
    public function put(Request $request,$id)
    {
      $bike = Bike::findOrFail($id);
      if ($request->has('model_name')) {
        $bike->model_name = $bike->model_name;
      }
      if ($request->has('model_year')) {
        $bike->model_year = $request->model_year;
      }
      if ($request->has('engine_capacity')) {
        $bike->engine_capacity = $request->engine_capacity;
      }
      if ($request->has('engine_number')) {
        $bike->engine_number = $request->engine_number;
      }
      if ($request->has('chassis_number')) {
        $bike->chassis_number = $request->chassis_number;
      }
      if ($request->has('registration_number')) {
        $bike->registration_number = $request->registration_number;
      }
      if ($request->has('hourly_rent')) {
        $bike->hourly_rent = $request->hourly_rent;
      }
      if ($request->has('daily_rent')) {
         $bike->daily_rent = $request->daily_rent;
      }
      if ($request->has('last_serviced')) {
          $bike->last_serviced = $request->last_serviced;
      }
      if ($request->has('next_service')) {
        $bike->next_service = $request->next_service;
      }
      if ($request->has('bike_image_link')) {
        $bike->bike_image_link  = $this->uploadImage($request->bike_image_link);
      }
      if ($request->has('paper_image_link')) {
        $bike->paper_image_link  = $this->uploadImage($request->paper_image_link);
      }
      $bike->save();

      return response()->json(['Message' => 'Updated']);

    }
    public function remove($id)
    {
      $bike = Bike::findOrFail($id);
      $bike->delete();
      return response()->json(['Message' => 'deleted']);
    }

    public function BikeAvailability($id)
    {
      $bike = Bike::findOrFail($id);
      $bike->availability = 0;
      return response()->json(['Message' => 'Made Available']);
    }


    public function uploadImage($file)
    {
      $client_id = '55c393c2e121b9f';
      $url = 'https://api.imgur.com/3/image';
      $headers = array("Authorization: Client-ID $client_id");
      //source:
      //http://stackoverflow.com/questions/17269448/using-imgur-api-v3-to-upload-images-anonymously-using-php?rq=1
      $recivedFiles = $file;


            //$img = file_get_contents($file);
            //$imgarray  = array('image' => base64_encode($file),'title'=> $title);
            $imgarray  = array('image' => $recivedFiles);
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
          //  $theImageHash=$json_a['data']['id'];
           // $theImageTitle=$json_a['data']['title'];
          //$theImageRemove=$json_a['data']['deletehash'];
            $theImageLink=$json_a['data']['link'];
            curl_close ($curl);

            return $theImageLink;
    }
}
