<?php namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use App\Rent;
use App\Bike;
use DB;
use Carbon\Carbon;
class RentsController extends Controller {

    public function Index(Request $request)
    {
      $bike = Bike::findOrFail($request->bike_id);
      if ($bike->availability === 0) {
        $rent =  Rent::create($request->all()+['user_id'=>$request->user()->id]);
        DB::table('Bike')->where('id',$request->bike_id)->update(['availability'=>'1']);
        return response()->json(['Message' => 'Requested']);
      }else {
        return response()->json(['Message' => 'Sorry the bike is not available at this moment']);
      }

    }

    public function rentAll()
    {
      //$rent = Rent::all();
      $rent = DB::table('Rent')
      ->join('Bike','Rent.bike_id','=','Bike.id')
      ->join('users','Rent.user_id','=','users.id')
      ->select('users.name','users.phone','Rent.*','Bike.model_name','Bike.bike_image_link','Bike.registration_number')->get();

      return $rent->toJson();
    }
    // Show renter thier orders
    public function ShowRentRequestByUserId(Request $request)
    {
      $rent = DB::table('Rent')
      ->join('Bike','Rent.bike_id','=','Bike.id')
      ->select('Rent.*','Bike.*')
      ->where('Rent.user_id',$request->user()->id)
      ->OrderBy('Rent.created_at','asc')
      ->get();

      return $rent->toJson();
    }

    public function changeRentStatus(Request $request,$id)
    {
      $status = $request->status;
      if($status === 1)
      {
        DB::table('Rent')->where('id',$id)->update(['rent_status'=>'1', 'start_time' => Carbon::now()]);// ongoing
        return response()->json(['Message' => 'Started']);
      }
      elseif ($status === 2) {
        DB::table('Rent')->where('id',$id)->update(['rent_status'=>'2']);// completed
        $rent= DB::findOrFail($id);
        $bikeID = $rent->bike_id;
        DB::table('Bike')->where('id',$bikeID)->update(['availability'=>'1']);

        return response()->json(['Message' => 'Completed! Thank you']);
      }
      elseif ($status === 3) {
        DB::table('Rent')->where('id',$id)->update(['rent_status'=>'3']);// cancelled
        $rent= DB::findOrFail($id);
        $bikeID = $rent->bike_id;
        DB::table('Bike')->where('id',$bikeID)->update(['availability'=>'1']);

        return response()->json(['Message' => 'Thank you for using Barikoi Rental']);
      }
      else{
        DB::table('Rent')->where('id',$id)->update(['rent_status'=>'4']);// refused
        $rent= DB::findOrFail($id);
        $bikeID = $rent->bike_id;
        DB::table('Bike')->where('id',$bikeID)->update(['availability'=>'1']);

        return response()->json(['Message' => 'Refused']);
      }


    }


    public function rentDashboard()
    {
      $bikes = Bike::all();
      $bikes = count($bikes);
      $availableBikes = Bike::where('availability',0)->count();
      $totalRentRequest = Rent::all();
      $totalRentRequest = count($totalRentRequest);
      $totalServedRents = Rent::where('rent_status',2)->count();
      $totalRefusedRents = Rent::where('rent_status',4)->count();


      return response()->json([
        'Total Bikes' => $bikes,
        'Available Bikes' => $availableBikes,
        'Total Rent Requests' => $totalRentRequest,
        'Total Served'  => $totalServedRents,
        'Total Refused' => $totalRefusedRents,

      ]);
    }




}
