<?php namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\RideTechsRequestRides;
class RideTechsController extends Controller {

    public function RequestRide(Request $request)
    {
      $create = RideTechsRequestRides::create($request->all()+['name'=> $request->user()->name,'contact_number'=>$request->user()->phone,'user_id'=> $request->user()->id]);

      return response()->json(['message' => 'Ride Request Complete. Someone from ride will call you soon. Thank you!']);
    }

    public function ShowRequestedRides()
    {
      $show = RideTechsRequestRides::all();

      return $show->toJson();
    }

    public function ShowRequestedRidesByUser($id)
    {
      $show = RideTechsRequestRides::where('user_id',$id)->get();

      return $show->toJson();
    }
    
    public function DeleteRideRequest($id)
    {
      $show = RideTechsRequestRides::findOrFail($id);
      $show->delete();
      return response()->json(['message' => 'Ride Request Deleted.']);

    }

}
